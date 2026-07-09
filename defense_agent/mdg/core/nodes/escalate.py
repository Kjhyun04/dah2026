"""escalate (PA-8) — 오퍼레이터 게이트(HIGH-위험 / 비행) 액션의 종단 노드.

record_intent 로 오퍼레이터 게이트 Intent 를 부작용 0 으로 기록한다(실제 서명 명령은
operator-go RESERVED, 부록B). Intent 는 COMMAND-BOUND(PS-9): command_digest 가 이를
정확히 이 결정에 바인딩하여 포획된 승인이 다른 명령을 인가할 수 없게 한다. 주입된
``gate``(signer_shim.OperatorGate)는 추가로 일회용 nonce + TTL 만료를 각인한다.
오퍼레이터 게이트 HMAC 키는 OperatorGate 내부에 머문다(MDGState 에는 절대 없음 — PS-3).
ledger/posture 에 기록하고 -> END. HITL 은 LangGraph interrupt() 가 아니라 대역 외
오퍼레이터 처리를 사용한다(1 invoke = 1 tick / 리플레이 결정론 유지).
"""
from __future__ import annotations

from ...safe_exec.signer_shim import command_digest
from ..state import Intent, MDGState


def escalate(state: MDGState, ledger=None, clock=None, gate=None,
             ttl_s: float = 120.0) -> dict:
    chosen = state.get("chosen_action")
    ts = clock.now() if clock is not None else 0.0

    if chosen is None:
        return {}

    # PS-9 명령 바인딩(KEY-FREE digest; 비밀값 없음). 다른 명령에 대한 포획된 승인은
    # digest 가 달라 검증에 실패한다(verify_operator_binding).
    digest = command_digest(chosen)
    nonce, expiry = "", 0.0
    if gate is not None:
        nonce = f"esc-{chosen.decision_id or chosen.rule}-{int(ts)}"
        req = gate.issue(chosen, nonce=nonce, ttl_s=ttl_s, now=ts, digest=digest)
        nonce, expiry = req.nonce, req.expiry

    # 오퍼레이터 게이트 Intent: 부작용 0(기록만; 실제 발행 = operator-go)
    intent = Intent(
        rule=chosen.rule, tool_id=chosen.tool_id,
        revert_cmd=chosen.revert_cmd, ts=ts,
        decision_id=chosen.decision_id,
        config_version=state.get("config_version", ""),
        operator_gate=True,
        command_digest=digest, nonce=nonce, expiry=expiry,
        # 1. operator-select 출처를 오퍼레이터 게이트 ledger Intent 에 실어 OperatorGate
        # 인가가 누가 (HIGH/비행) 명령을 선택했는지 기록하게 한다. 자율 경로는 "".
        authority=getattr(chosen, "authority", ""),
    )
    if ledger is not None:
        ledger_update = ledger.record_intent(intent)
    else:
        ledger_update = {"ledger": [intent]}
    return ledger_update
