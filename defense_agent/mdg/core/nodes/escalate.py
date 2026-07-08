"""escalate (PA-8) — terminal node for operator-gated (HIGH-risk / flight) actions.

Records an operator-gate Intent via record_intent with side-effect 0 (the real signed command
is operator-go RESERVED, 부록B). The Intent is COMMAND-BOUND (PS-9): a command_digest binds it to
this exact decision so a captured approval cannot authorize a different command; an injected
``gate`` (signer_shim.OperatorGate) additionally stamps a single-use nonce + TTL expiry. The
operator-gate HMAC key stays inside the OperatorGate (never MDGState — PS-3). Writes to the
ledger/posture and -> END. HITL uses out-of-band operator processing, NOT LangGraph interrupt()
(keeps 1 invoke = 1 tick / replay determinism).
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

    # PS-9 command binding (KEY-FREE digest; no secret). A captured approval for a different
    # command has a different digest and will not verify (verify_operator_binding).
    digest = command_digest(chosen)
    nonce, expiry = "", 0.0
    if gate is not None:
        nonce = f"esc-{chosen.decision_id or chosen.rule}-{int(ts)}"
        req = gate.issue(chosen, nonce=nonce, ttl_s=ttl_s, now=ts, digest=digest)
        nonce, expiry = req.nonce, req.expiry

    # operator-gate Intent: side-effect 0 (record only; real issuance = operator-go)
    intent = Intent(
        rule=chosen.rule, tool_id=chosen.tool_id,
        revert_cmd=chosen.revert_cmd, ts=ts,
        decision_id=chosen.decision_id,
        config_version=state.get("config_version", ""),
        operator_gate=True,
        command_digest=digest, nonce=nonce, expiry=expiry,
    )
    if ledger is not None:
        ledger_update = ledger.record_intent(intent)
    else:
        ledger_update = {"ledger": [intent]}
    return ledger_update
