"""test_operator_select — ① OPERATOR-SELECT path (Item A).

Locks the operator-select override: the operator explicitly picks a legal candidate
(env MDG_OPERATOR_PICK -> state['operator_pick']) and rank_recovery promotes THAT action to
chosen_action, bypassing the autonomous ranking that permanently demotes send_signed_mode below
the reversible blockades (backdoor_pause). A blank/non-matching pick leaves the autonomous ranking
intact (fail-safe). The selected send_signed_mode is COMMAND-BOUND (KEY-FREE command_digest) and,
on the HIGH/flight escalate route, authorized via OperatorGate.issue with a durable secret-free
receipt. Fully deterministic (env string only, 불변식①) and offline.

  S2 legal set (signing CONFIRMED_ON + web_backend & gcs_proxy verified):
      single-signal -> {backdoor_pause, signed_guided}. Autonomous ranking picks backdoor_pause
      (priors). operator_pick=signed_guided (or send_signed_mode) promotes send_signed_mode instead.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core.nodes.escalate import escalate  # noqa: E402
from mdg.core.nodes.rank_recovery import rank_recovery  # noqa: E402
from mdg.core.nodes.select_policy import select_policy  # noqa: E402
from mdg.core.state import Incident  # noqa: E402
from mdg.core.worldstate import SigningObs, WorldState  # noqa: E402
from mdg.live_autorun import parse_operator_pick  # noqa: E402
from mdg.safe_exec.signer_shim import OperatorGate, command_digest  # noqa: E402

CFG = "mdg-cfg-2026-07-07"


def _single_signal() -> Incident:
    return Incident(id="sig-0-Unauthorized_Command", kind="single-signal",
                    members=["Unauthorized_Command"])


def _world() -> WorldState:
    # both chokepoints verified + signing ON -> backdoor_pause AND signed_guided are legal.
    return WorldState(config_version=CFG, signing=SigningObs.CONFIRMED_ON,
                      role_verified={"web_backend": True, "gcs_proxy": True})


def _drive(operator_pick: str | None = None) -> tuple[list, dict]:
    st = {"incidents": [_single_signal()], "worldstate": _world(), "config_version": CFG}
    st["legal_actions"] = select_policy(st)["legal_actions"]
    if operator_pick is not None:
        st["operator_pick"] = operator_pick
    return st["legal_actions"], rank_recovery(st)


# --------------------------------------------------------------------------- #
# env parser (parse_operator_auto pattern; a VALUE, not a bool gate)
# --------------------------------------------------------------------------- #
def test_parse_operator_pick_reads_env_value():
    assert parse_operator_pick({"MDG_OPERATOR_PICK": "signed_guided"}) == "signed_guided"
    assert parse_operator_pick({"MDG_OPERATOR_PICK": "  send_signed_mode  "}) == "send_signed_mode"
    assert parse_operator_pick({}) == ""
    assert parse_operator_pick({"MDG_OPERATOR_PICK": ""}) == ""
    assert parse_operator_pick({"MDG_OPERATOR_PICK": "   "}) == ""


# --------------------------------------------------------------------------- #
# default / fail-safe — autonomous ranking stands (backdoor_pause)
# --------------------------------------------------------------------------- #
def test_no_pick_keeps_autonomous_ranking():
    legal, out = _drive(operator_pick=None)
    assert {a.recovery_type for a in legal} == {"backdoor_pause", "signed_guided"}
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.rule == "backdoor_pause"     # autonomous top-1
    assert chosen.tool_id == "docker_pause"
    assert chosen.authority == ""                                     # not operator-selected


def test_blank_pick_keeps_autonomous_ranking():
    _, out = _drive(operator_pick="   ")
    assert out["chosen_action"].rule == "backdoor_pause"


def test_nonmatching_pick_ignored_falls_back_to_ranking():
    # a ghost/typo that matches no legal recovery_type or tool_id -> autonomous ranking (fail-safe)
    _, out = _drive(operator_pick="ghost_recovery")
    chosen = out["chosen_action"]
    assert chosen.rule == "backdoor_pause"
    assert chosen.authority == ""


# --------------------------------------------------------------------------- #
# operator-select — send_signed_mode is PROMOTED (the whole point of Item A)
# --------------------------------------------------------------------------- #
def test_pick_by_recovery_type_promotes_send_signed_mode():
    legal, out = _drive(operator_pick="signed_guided")
    assert "signed_guided" in {a.recovery_type for a in legal}         # present in legal set
    chosen = out["chosen_action"]
    assert chosen is not None
    assert chosen.tool_id == "send_signed_mode"                        # promoted over backdoor_pause
    assert chosen.rule == "signed_guided"
    assert chosen.authority == "operator-select"                       # provenance marked
    assert out["chosen_action_risk"] == "HIGH"                         # flight -> OPER/HIGH
    assert out["chosen_action_reversible"] is False
    # COMMAND-BOUND (PS-9): the KEY-FREE digest binds the approval to THIS command.
    assert chosen.command_digest and chosen.command_digest == command_digest(chosen)


def test_pick_by_tool_id_also_matches():
    # match works by tool_id spelling too (send_signed_mode), not only recovery_type.
    _, out = _drive(operator_pick="send_signed_mode")
    chosen = out["chosen_action"]
    assert chosen.tool_id == "send_signed_mode" and chosen.rule == "signed_guided"
    assert chosen.authority == "operator-select"


def test_pick_backdoor_pause_still_selectable():
    # operator can also explicitly pick the reversible blockade — it is already the autonomous top,
    # but the authority marking must flip to operator-select when EXPLICITLY chosen.
    _, out = _drive(operator_pick="backdoor_pause")
    chosen = out["chosen_action"]
    assert chosen.rule == "backdoor_pause"
    assert chosen.authority == "operator-select"


# --------------------------------------------------------------------------- #
# OperatorGate authentication of the operator-selected send_signed_mode (escalate route)
# --------------------------------------------------------------------------- #
class _SpyIntentLedger:
    def __init__(self):
        self.intents = []

    def record_intent(self, intent):
        self.intents.append(intent)
        return {"ledger": [intent]}


class _SpyOperatorLedger:
    def __init__(self):
        self.receipts = []

    def recover_on_boot(self):
        return set()

    def record(self, **kw):
        self.receipts.append(kw)


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def now(self):
        return self.t


def test_escalate_issues_command_bound_operator_request_for_operator_select():
    # operator-selected send_signed_mode routes to escalate (HIGH/irreversible, operator_auto off);
    # OperatorGate.issue mints a command-bound OperatorRequest + a durable secret-free ISSUED receipt,
    # and the operator-gate ledger Intent carries the operator-select provenance.
    _, out = _drive(operator_pick="signed_guided")
    chosen = out["chosen_action"]

    op_led = _SpyOperatorLedger()
    gate = OperatorGate(key=b"unit-test-key", clock=_Clock(1000.0), ledger=op_led)
    intent_led = _SpyIntentLedger()

    upd = escalate({"chosen_action": chosen, "config_version": CFG},
                   ledger=intent_led, clock=_Clock(1000.0), gate=gate, ttl_s=120.0)

    # operator-gate Intent recorded (side-effect 0 actuation), command-bound + provenance
    assert len(intent_led.intents) == 1
    it = intent_led.intents[0]
    assert it.operator_gate is True
    assert it.authority == "operator-select"
    assert it.command_digest == command_digest(chosen) and it.command_digest
    assert it.nonce and it.expiry == 1000.0 + 120.0
    assert "ledger" in upd

    # OperatorGate.issue wrote a durable secret-free ISSUED receipt bound to the SAME command
    assert len(op_led.receipts) == 1
    r = op_led.receipts[0]
    assert r["verdict"] == "ISSUED"
    assert r["command_digest"] == it.command_digest
    assert r["nonce"] == it.nonce


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
