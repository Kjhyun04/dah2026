"""test_operator_select — 1. OPERATOR-SELECT 경로 (Item A).

operator-select 오버라이드를 고정: 운영자가 합법 후보를 명시적으로 선택하면
(env MDG_OPERATOR_PICK -> state['operator_pick']) rank_recovery 가 그 액션을 chosen_action 으로
승격하여, send_signed_mode 를 가역 차단(backdoor_pause) 아래로 영구 강등하는 자율 랭킹을 우회한다.
공백/미일치 선택은 자율 랭킹을 그대로 둔다(fail-safe). 선택된 send_signed_mode 는 COMMAND-BOUND
(KEY-FREE command_digest)이며, HIGH/flight escalate 경로에서는 durable secret-free 영수증과 함께
OperatorGate.issue 로 인증된다. 완전 결정론적(env 문자열만, 불변식1.)이며 오프라인이다.

  S2 합법 집합 (signing CONFIRMED_ON + web_backend & gcs_proxy verified):
      single-signal -> {backdoor_pause, signed_guided}. 자율 랭킹은 backdoor_pause 를 선택
      (priors). operator_pick=signed_guided (또는 send_signed_mode)는 대신 send_signed_mode 를 승격한다.
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
    # 두 chokepoint 검증됨 + signing ON -> backdoor_pause 와 signed_guided 모두 합법.
    return WorldState(config_version=CFG, signing=SigningObs.CONFIRMED_ON,
                      role_verified={"web_backend": True, "gcs_proxy": True})


def _drive(operator_pick: str | None = None) -> tuple[list, dict]:
    st = {"incidents": [_single_signal()], "worldstate": _world(), "config_version": CFG}
    st["legal_actions"] = select_policy(st)["legal_actions"]
    if operator_pick is not None:
        st["operator_pick"] = operator_pick
    return st["legal_actions"], rank_recovery(st)


# --------------------------------------------------------------------------- #
# env 파서 (parse_operator_auto 패턴; bool 게이트가 아니라 VALUE)
# --------------------------------------------------------------------------- #
def test_parse_operator_pick_reads_env_value():
    assert parse_operator_pick({"MDG_OPERATOR_PICK": "signed_guided"}) == "signed_guided"
    assert parse_operator_pick({"MDG_OPERATOR_PICK": "  send_signed_mode  "}) == "send_signed_mode"
    assert parse_operator_pick({}) == ""
    assert parse_operator_pick({"MDG_OPERATOR_PICK": ""}) == ""
    assert parse_operator_pick({"MDG_OPERATOR_PICK": "   "}) == ""


# --------------------------------------------------------------------------- #
# 기본 / fail-safe — 자율 랭킹 유지 (backdoor_pause)
# --------------------------------------------------------------------------- #
def test_no_pick_keeps_autonomous_ranking():
    legal, out = _drive(operator_pick=None)
    assert {a.recovery_type for a in legal} == {"backdoor_pause", "signed_guided"}
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.rule == "backdoor_pause"     # 자율 랭킹 top-1
    assert chosen.tool_id == "docker_pause"
    assert chosen.authority == ""                                     # operator-select 아님


def test_blank_pick_keeps_autonomous_ranking():
    _, out = _drive(operator_pick="   ")
    assert out["chosen_action"].rule == "backdoor_pause"


def test_nonmatching_pick_ignored_falls_back_to_ranking():
    # 어떤 합법 recovery_type/tool_id 와도 매칭되지 않는 유령/오타 -> 자율 랭킹 (fail-safe)
    _, out = _drive(operator_pick="ghost_recovery")
    chosen = out["chosen_action"]
    assert chosen.rule == "backdoor_pause"
    assert chosen.authority == ""


# --------------------------------------------------------------------------- #
# operator-select — send_signed_mode 가 승격됨 (Item A 의 핵심)
# --------------------------------------------------------------------------- #
def test_pick_by_recovery_type_promotes_send_signed_mode():
    legal, out = _drive(operator_pick="signed_guided")
    assert "signed_guided" in {a.recovery_type for a in legal}         # 합법 집합에 존재
    chosen = out["chosen_action"]
    assert chosen is not None
    assert chosen.tool_id == "send_signed_mode"                        # backdoor_pause 위로 승격
    assert chosen.rule == "signed_guided"
    assert chosen.authority == "operator-select"                       # provenance 표시됨
    assert out["chosen_action_risk"] == "HIGH"                         # flight -> OPER/HIGH
    assert out["chosen_action_reversible"] is False
    # COMMAND-BOUND (PS-9): KEY-FREE digest 가 승인을 이 명령에 바인딩한다.
    assert chosen.command_digest and chosen.command_digest == command_digest(chosen)


def test_pick_by_tool_id_also_matches():
    # 매칭은 recovery_type 뿐 아니라 tool_id 표기(send_signed_mode)로도 동작한다.
    _, out = _drive(operator_pick="send_signed_mode")
    chosen = out["chosen_action"]
    assert chosen.tool_id == "send_signed_mode" and chosen.rule == "signed_guided"
    assert chosen.authority == "operator-select"


def test_pick_backdoor_pause_still_selectable():
    # 운영자는 가역 차단도 명시적으로 선택할 수 있다 — 이미 자율 랭킹 최상위이지만,
    # 명시적으로 선택되면 authority 표시가 operator-select 로 바뀌어야 한다.
    _, out = _drive(operator_pick="backdoor_pause")
    chosen = out["chosen_action"]
    assert chosen.rule == "backdoor_pause"
    assert chosen.authority == "operator-select"


# --------------------------------------------------------------------------- #
# operator-select 된 send_signed_mode 의 OperatorGate 인증 (escalate 경로)
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
    # operator-select 된 send_signed_mode 는 escalate 로 라우팅됨 (HIGH/비가역, operator_auto off);
    # OperatorGate.issue 는 command-bound OperatorRequest + durable secret-free ISSUED 영수증을 발행하고,
    # operator-gate ledger Intent 는 operator-select provenance 를 실어 나른다.
    _, out = _drive(operator_pick="signed_guided")
    chosen = out["chosen_action"]

    op_led = _SpyOperatorLedger()
    gate = OperatorGate(key=b"unit-test-key", clock=_Clock(1000.0), ledger=op_led)
    intent_led = _SpyIntentLedger()

    upd = escalate({"chosen_action": chosen, "config_version": CFG},
                   ledger=intent_led, clock=_Clock(1000.0), gate=gate, ttl_s=120.0)

    # operator-gate Intent 기록됨 (부수효과 0 actuation), command-bound + provenance
    assert len(intent_led.intents) == 1
    it = intent_led.intents[0]
    assert it.operator_gate is True
    assert it.authority == "operator-select"
    assert it.command_digest == command_digest(chosen) and it.command_digest
    assert it.nonce and it.expiry == 1000.0 + 120.0
    assert "ledger" in upd

    # OperatorGate.issue 는 동일 명령에 바인딩된 durable secret-free ISSUED 영수증을 기록했다
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
