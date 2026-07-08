"""test_provenance_relaxed — Phase 2 (RECOVERY_DEMO_PLAN §Phase2, B3/PS-7).

Under operator_auto (sandbox demo) the injected-high-severity provenance/debounce gate is
RELAXED to record-then-pass:
  * rank_recovery stamps chosen_action.provenance_relaxed=True (ledger/trace transparency);
  * the physical-action debounce is SHRUNK to config demo_mode.debounce_ticks for the INERT-DRY
    recovery paths (docker_pause / flight — no live argv builder) so a re-selected recovery
    re-binds within the NEXT tick. The LIVE netns-insertion path (nsenter_input_drop) is EXCLUDED
    and keeps its full physical_action_min hold: its actuator uses a non-idempotent iptables -I
    and, with observe=None, already_applied never fires, so debounce is its sole re-actuation
    throttle — shrinking it would accumulate duplicate DROP rules (leak-0 / reversibility risk).
Production (operator_auto off) is UNCHANGED: provenance_relaxed=False and the full
debounce.physical_action_min_ticks hold applies (strict PS-7). 불변식① (deterministic: env bool +
config, no LLM) and ② (no new subprocess path) are intact.

Runnable standalone as ``python mdg/tests/test_provenance_relaxed.py``.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import defaults as D  # noqa: E402
from mdg.config import loader  # noqa: E402
from mdg.core import bundle as bundle_mod  # noqa: E402
from mdg.core.nodes.rank_recovery import rank_recovery  # noqa: E402
from mdg.core.nodes.select_policy import select_policy  # noqa: E402
from mdg.core.state import Action, Incident, Intent  # noqa: E402
from mdg.core.worldstate import AppliedRule, WorldState  # noqa: E402
from mdg.safe_exec.backend import Backend  # noqa: E402
from mdg.safe_exec.response import ResponseController  # noqa: E402


def _injected_backdoor_action() -> Action:
    # a feasible reversible MED recovery (docker_pause / backdoor_pause) as an injected candidate
    return Action(tool_id="docker_pause", recovery_type="backdoor_pause", risk="MED",
                  reversible=True, params={"recovery_type": "backdoor_pause",
                                           "target": "10.45.0.5", "target_kind": "ip",
                                           "enforce_at": "web_backend"})


# --------------------------------------------------------------------------- #
# config surface — demo_mode present, relaxed, and debounce strictly shorter
# --------------------------------------------------------------------------- #
def test_demo_mode_config_present_and_shorter_than_strict():
    dm = loader.demo_mode()
    assert dm["provenance_relaxed"] is True
    assert isinstance(dm["debounce_ticks"], int)
    # the demo hold MUST be shorter than the strict physical-action debounce (otherwise "relax"
    # would be a no-op)
    assert dm["debounce_ticks"] < D.DEBOUNCE_PHYSICAL_MIN_TICKS


# --------------------------------------------------------------------------- #
# PRODUCTION (operator_auto off) — strict: bind unchanged, NO relaxation marker
# --------------------------------------------------------------------------- #
def test_production_binds_but_does_not_relax_provenance():
    st = {"legal_actions": [_injected_backdoor_action()], "config_version": "t"}
    out = rank_recovery(st)                                # operator_auto absent -> False
    assert out["chosen_action"] is not None               # REGRESSION: still binds
    assert isinstance(out["chosen_action"], Intent)
    assert out["chosen_action"].provenance_relaxed is False  # strict posture NOT waived

    # explicit operator_auto=False is identical (safe default)
    st2 = {"legal_actions": [_injected_backdoor_action()], "config_version": "t",
           "operator_auto": False}
    assert rank_recovery(st2)["chosen_action"].provenance_relaxed is False


# --------------------------------------------------------------------------- #
# DEMO (operator_auto on) — record-then-pass: bind + provenance_relaxed=True (trace/ledger)
# --------------------------------------------------------------------------- #
def test_demo_operator_auto_relaxes_and_records():
    st = {"legal_actions": [_injected_backdoor_action()], "config_version": "t",
          "operator_auto": True}
    out = rank_recovery(st)
    intent = out["chosen_action"]
    assert intent is not None
    assert intent.provenance_relaxed is True              # waiver stamped for ledger/trace
    assert out["chosen_action_risk"] == "MED"
    assert out["chosen_action_reversible"] is True
    # the marker survives model_dump so the recording hook / ledger carries it
    assert out["chosen_action"].model_dump()["provenance_relaxed"] is True


# --------------------------------------------------------------------------- #
# END-TO-END(ish) — an INJECTED single-signal attack binds to chosen_action under demo
# --------------------------------------------------------------------------- #
def test_injected_attack_binds_to_chosen_action_under_demo():
    # BACKDOOR_5762 injected incident -> select_policy candidate -> rank_recovery binds it
    cfg = loader.config_version()
    rv = {}
    for spec in loader.recovery_priors().get("recovery_priors", {}).values():
        ea = str(spec.get("enforce_at") or "")
        if ea:
            rv[ea] = True
    world = WorldState(config_version=cfg, role_verified=rv)
    inc = Incident(id="sig-0-Port_5762_State", kind="BACKDOOR_5762", target="10.45.0.9")
    st = {"incidents": [inc], "worldstate": world, "config_version": cfg,
          "operator_auto": True}
    st.update(select_policy(st))
    assert st["legal_actions"], "injected 5762 incident must yield a legal recovery candidate"
    out = rank_recovery({**st, **{"legal_actions": st["legal_actions"]}})
    assert out["chosen_action"] is not None, "injected attack must bind to chosen_action"
    assert out["chosen_action"].provenance_relaxed is True


# --------------------------------------------------------------------------- #
# DEBOUNCE relaxation — the demo shrink applies to INERT-DRY paths only; the LIVE
# netns-insertion path (nsenter_input_drop) keeps its full physical_action_min hold.
# --------------------------------------------------------------------------- #
def test_demo_debounce_shrink_holds_live_insertion_frees_inert_path():
    # primitive: at tick 1, strict (3) HOLDS, demo (1) does NOT
    world = WorldState().with_applied(
        AppliedRule(rule="probe", applied_tick=0, confirmed=False))
    assert bundle_mod.debounce_blocked(world, "probe", 1, D.DEBOUNCE_PHYSICAL_MIN_TICKS) is True
    assert bundle_mod.debounce_blocked(world, "probe", 1, loader.demo_mode()["debounce_ticks"]) is False

    prod = ResponseController(backend=Backend(allow_live=False), operator_auto=False)
    demo = ResponseController(backend=Backend(allow_live=False), operator_auto=True)

    # LIVE netns-insertion path (nsenter_input_drop): its actuator uses a NON-idempotent iptables
    # -I and, with observe=None, already_applied never fires -> debounce is the SOLE re-actuation
    # throttle. The demo shrink MUST NOT apply here (else duplicate DROP rules accumulate that a
    # single -D revert cannot undo). Strict 3-tick hold holds under BOTH prod and operator_auto.
    live_rule = "backdoor_drop"
    world_live = WorldState().with_applied(
        AppliedRule(rule=live_rule, applied_tick=0, confirmed=False))
    intent_live = Intent(rule=live_rule, tool_id="nsenter_input_drop")
    p_prod = prod.plan(intent_live, world_live, 1, risk="MED", reversible=True)
    assert p_prod.skip is True and "debounced" in p_prod.reason
    p_live = demo.plan(intent_live, world_live, 1, risk="MED", reversible=True)
    assert p_live.skip is True and "debounced" in p_live.reason, \
        "live netns DROP must keep 3-tick damping even under operator_auto (non-idempotent -I)"

    # INERT-DRY path (docker_pause widened by operator_auto -> no argv builder, side-effect 0):
    # here re-actuation is a pure no-op, so the demo shrink safely lets the recovery re-bind next
    # tick. Held strictly in production.
    inert_rule = "backdoor_pause"
    world_inert = WorldState().with_applied(
        AppliedRule(rule=inert_rule, applied_tick=0, confirmed=False))
    intent_inert = Intent(rule=inert_rule, tool_id="docker_pause", enforce_at="target")
    assert prod.plan(intent_inert, world_inert, 1, risk="MED", reversible=True).skip is True
    p_inert = demo.plan(intent_inert, world_inert, 1, risk="MED", reversible=True)
    assert p_inert.skip is False, "inert OPER recovery re-binds within the next tick under demo"


def _run_all() -> int:
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"[FAIL] {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"[ERROR] {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
