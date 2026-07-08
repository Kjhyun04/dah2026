"""test_operator_auto — Phase 1 (sandbox demo): operator auto-confirm of the OPER execution path.

Covers the three wiring points of Phase 1 (RECOVERY_DEMO_PLAN Phase 1 / B1):
  gate.py            — gate_for(..., operator_auto=True) widens a REGISTERED OPER decision to
                       auto=True (tier2 "AUTO_BY_OPERATOR"), preserving flight/registry_tier for
                       transparency; an UNREGISTERED ghost is NEVER widened (fail-closed absolute).
  edges.py           — route_after_decide routes an otherwise-escalated OPER response to act under
                       the env-sourced operator_auto bool (deterministic; 불변식① intact).
  act node           — the OPER tool EXECUTES (enforcement recorded) with the ledger Intent stamped
                       operator_auto_confirmed=True + authority="sandbox-auto"; operator_auto=0 keeps
                       the legacy operator-gate defer (regression: escalate/미집행).

Runs offline (Backend.allow_live=False -> DRY; no testbed state change). pytest or script.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import gate as G                       # noqa: E402
from mdg.core.edges import END, route_after_decide   # noqa: E402
from mdg.core.nodes.act import act                   # noqa: E402
from mdg.core.nodes.effect_confirm import effect_confirm  # noqa: E402
from mdg.core.state import Intent, initial_state      # noqa: E402
from mdg.core.worldstate import WorldState            # noqa: E402
from mdg.safe_exec.backend import Backend             # noqa: E402
from mdg.safe_exec.observer import make_effect_observer  # noqa: E402

CFG = "mdg-cfg-2026-07-07"


class _SpyLedger:
    def __init__(self):
        self.intents = []

    def record_intent(self, intent):
        self.intents.append(intent)
        return {"ledger": [intent]}


def _world(**kw) -> WorldState:
    kw.setdefault("role_verified", {"target": True})
    return WorldState(config_version=CFG, **kw)


def _pause_intent() -> Intent:
    # enforce_at="target" resolves role_verified["target"]=True so legality passes (docker_pause
    # requires role_verified.target). revert_cmd present -> reversible enforcement, revertible on boot.
    return Intent(rule="backdoor_pause", tool_id="docker_pause", enforce_at="target",
                  config_version=CFG, revert_cmd="revert:backdoor_pause")


def _state(chosen: Intent, *, risk="MED", reversible=True) -> dict:
    st = dict(initial_state(CFG))
    st["worldstate"] = _world()
    st["chosen_action"] = chosen
    st["chosen_action_risk"] = risk
    st["chosen_action_reversible"] = reversible
    return st


# --------------------------------------------------------------------------- #
# gate.py — operator_auto widens registered OPER -> auto (transparency preserved)
# --------------------------------------------------------------------------- #
def test_gate_operator_auto_widens_registered_oper():
    # default (operator_auto=0) — legacy OPER classification (REGRESSION guard)
    d0 = G.gate_for("docker_pause", "MED", True)
    assert d0.operator_required and d0.tier2 == "OPER"

    # operator_auto=1 -> auto, but registry_tier stays OPER for ledger/routing transparency
    d1 = G.gate_for("docker_pause", "MED", True, operator_auto=True)
    assert d1.auto is True and not d1.operator_required
    assert d1.tier2 == "AUTO_BY_OPERATOR" and d1.registry_tier == "OPER"
    assert G.is_auto("docker_pause", "MED", True, operator_auto=True)

    # flight (send_signed_mode): widened too, flight field PRESERVED (transparency)
    df = G.gate_for("send_signed_mode", "HIGH", False, operator_auto=True)
    assert df.auto is True and df.flight is True and df.registry_tier == "OPER"

    # a native AUTO tool is UNAFFECTED (still plain AUTO, not AUTO_BY_OPERATOR)
    da = G.gate_for("nsenter_input_drop", "MED", True, operator_auto=True)
    assert da.auto is True and da.tier2 == "AUTO"

    # fail-closed ABSOLUTE: an unregistered/ghost id is NEVER widened by operator_auto
    assert G.gate_for("ghost_tool", "LOW", True, operator_auto=True).operator_required


# --------------------------------------------------------------------------- #
# edges.py — route_after_decide honors operator_auto deterministically (불변식①)
# --------------------------------------------------------------------------- #
def test_route_after_decide_operator_auto():
    chosen = _pause_intent()
    # HIGH risk: default escalate; operator_auto -> act
    hi = {"chosen_action": chosen, "chosen_action_risk": "HIGH", "chosen_action_reversible": False}
    assert route_after_decide(hi) == "escalate"
    assert route_after_decide({**hi, "operator_auto": True}) == "act"

    # non-reversible MED: default escalate; operator_auto -> act
    nr = {"chosen_action": chosen, "chosen_action_risk": "MED", "chosen_action_reversible": False}
    assert route_after_decide(nr) == "escalate"
    assert route_after_decide({**nr, "operator_auto": True}) == "act"

    # MED + reversible always act (independent of operator_auto); None -> END
    ok = {"chosen_action": chosen, "chosen_action_risk": "MED", "chosen_action_reversible": True}
    assert route_after_decide(ok) == "act"
    assert route_after_decide({**ok, "operator_auto": True}) == "act"
    assert route_after_decide({"chosen_action": None}) == END


# --------------------------------------------------------------------------- #
# act node — OPER executes under operator_auto=1 (enforcement recorded)
# --------------------------------------------------------------------------- #
def test_act_operator_auto_enforces_and_records():
    led = _SpyLedger()
    out = act(_state(_pause_intent()), backend=Backend(allow_live=False), ledger=led,
              operator_auto=True)

    # routed to the ENFORCEMENT path (not operator-gate defer): dry_streak reset, world applied
    assert out.get("dry_streak") == 0
    assert out.get("operator_auto_confirmed") is True
    assert "worldstate" in out
    assert out["worldstate"].applied.get("backdoor_pause") is not None

    # ledger Intent carries the transparency audit fields, and is NOT an operator-gate defer
    assert len(led.intents) == 1
    it = led.intents[0]
    assert it.operator_auto_confirmed is True and it.authority == "sandbox-auto"
    assert it.operator_gate is False


def test_act_operator_auto_off_defers_to_operator():
    # REGRESSION: operator_auto=0 keeps the legacy OPER operator-gate defer (side-effect 0)
    led = _SpyLedger()
    out = act(_state(_pause_intent()), backend=Backend(allow_live=False), ledger=led,
              operator_auto=False)

    # operator-gate defer: intent recorded with operator_gate=True, NO enforcement/world change
    assert "worldstate" not in out
    assert out.get("operator_auto_confirmed") is None
    assert len(led.intents) == 1
    it = led.intents[0]
    assert it.operator_gate is True
    assert it.operator_auto_confirmed is False and it.authority == ""


# --------------------------------------------------------------------------- #
# Phase 4 end-to-end: act ACTUATES the docker_pause -> effect_confirm confirms (S1)
# --------------------------------------------------------------------------- #
class _StatefulDocker:
    """Duck-typed docker backend whose inspect_paused REFLECTS a real pause() call — the coupling
    that a scripted _FakeDocker cannot express (fixes the gap where pause was never actuated)."""
    def __init__(self):
        self.paused = {}

    def pause(self, container):
        self.paused[container] = True
        return {"paused": container}

    def inspect_paused(self, container):
        return self.paused.get(container, False)


# backdoor_pause resolves enforce_at via RECOVERY_PRIORS -> "web_backend"; the observer probes that
# SAME container, so the intent enforce_at and world verification must use it too (live coherence).
def _pause_intent_web() -> Intent:
    return Intent(rule="backdoor_pause", tool_id="docker_pause", enforce_at="web_backend",
                  config_version=CFG, revert_cmd="revert:backdoor_pause")


def _state_web(chosen: Intent) -> dict:
    st = dict(initial_state(CFG))
    st["worldstate"] = WorldState(config_version=CFG, role_verified={"web_backend": True})
    st["chosen_action"] = chosen
    st["chosen_action_risk"] = "MED"
    st["chosen_action_reversible"] = True
    return st


def test_act_pause_actuates_then_effect_confirm_confirms():
    """S1 회복 lifecycle: operator_auto docker_pause is ACTUATED in act (act_host.pause), then the
    read-only effect observer sees .State.Paused=True and effect_confirm flips confirmed True."""
    docker = _StatefulDocker()
    out = act(_state_web(_pause_intent_web()), backend=Backend(allow_live=False),
              ledger=_SpyLedger(), operator_auto=True, docker=docker)
    # act actually paused the enforce_at container (was the missing actuation)
    assert docker.paused.get("web_backend") is True
    world = out["worldstate"]
    assert world.applied["backdoor_pause"].confirmed is False       # not yet observed

    # next tick effect_confirm with the read-only observer -> transitions to confirmed
    obs = make_effect_observer(docker=docker)
    ec = effect_confirm({"worldstate": world}, observe=obs)
    assert ec["worldstate"].applied["backdoor_pause"].confirmed is True


def test_act_pause_inert_without_docker_stays_unconfirmed():
    """Regression/honesty guard: with NO docker backend the pause degrades to operator-go DRY (no
    actuation), so inspect_paused can never be True and confirmed stays False (never a false confirm)."""
    out = act(_state_web(_pause_intent_web()), backend=Backend(allow_live=False),
              ledger=_SpyLedger(), operator_auto=True, docker=None)
    world = out["worldstate"]
    assert world.applied["backdoor_pause"].confirmed is False
    ec = effect_confirm({"worldstate": world}, observe=make_effect_observer(docker=None))
    assert ec["worldstate"].applied["backdoor_pause"].confirmed is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[PASS] {name}")
