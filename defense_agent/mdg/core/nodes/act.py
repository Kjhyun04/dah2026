"""act (PA-6) — legality pre-check -> 2-tier gate/bundle -> record_intent(guard 밖) -> tool_wrap.

Order (exact):
  1. legality pre-check (OUTSIDE tool_wrap/guard): re-verify against CURRENT worldstate +
     pinned config_version (X7). Illegal -> side-effect-0 early return.
  2. Response Controller plan (pure, no side effect): bundle idempotency/N-tick debounce
     (core.bundle) + 2-tier gate (core.gate).
       - SKIP (idempotent/debounced) -> no intent, no exec (dry_streak++ toward quiescence, NOT
         reset — a skip is no actuation, so it must not masquerade as progress and defeat k_dry).
       - OPER tier (flight / docker pause) -> record an operator-gate Intent (command_digest
         bound, PS-9), side-effect 0, NO exec (tier-2 defers to operator; "비행=operator").
  3. record_intent (OUTSIDE guard, ALWAYS before exec): write Intent to durable JSONL + ledger
     channel so recover_on_boot can revert leaks (G3).
  4. tool_wrap = Backend.run(ExecRequest) [safe-exec] + post world_update. legality/record_intent
     are NOT inside tool_wrap.

The node NEVER calls subprocess directly — only Backend.run via the Response Controller (불변식②).
Live actuation is operator-go RESERVED (Backend.allow_live=False -> DRY-RUN). dry_streak -> 0 on act.
"""
from __future__ import annotations

from ...safe_exec.backend import Backend
from ...safe_exec.response import ResponseController
from ...safe_exec.signer_shim import command_digest
from ...tools.defresult import CRSError, def_tool_wrap
from ..legality import assert_legal
from ..state import Action, MDGState
from ..worldstate import AppliedRule, WorldState


def act(state: MDGState, backend: Backend | None = None, ledger=None, clock=None,
        controller: ResponseController | None = None, smf_table=None,
        operator_auto: bool = False, docker=None) -> dict:
    chosen = state.get("chosen_action")
    if chosen is None:
        return {}                                          # nothing to do

    risk = state.get("chosen_action_risk", "LOW")
    reversible = state.get("chosen_action_reversible", True)
    action = Action(
        tool_id=chosen.tool_id,
        # Carry the ENFORCEMENT-container + source selectors so the legality pre-hook can resolve
        # the registry's role_verified alias to the REAL container key (step 10 dynamic binding).
        # Without them the reconstructed Action would carry no concrete selector and the fail-closed
        # role_verified check would veto every autonomous action. Data-only (no live resolution).
        params={"recovery_type": chosen.rule, "enforce_at": chosen.enforce_at,
                "target": chosen.target, "target_kind": chosen.target_kind},
        risk=risk, reversible=reversible,
        recovery_type=chosen.rule,
    )

    # 1) legality pre-check OUTSIDE tool_wrap (side-effect 0 on illegal)
    try:
        assert_legal(action, state)
    except CRSError:
        return {}                                          # illegal -> side-effect 0 early return

    ts = clock.now() if clock is not None else 0.0
    world: WorldState = state.get("worldstate") or WorldState()
    tick_i = int(state.get("tick_i", 0))

    be = backend or Backend(allow_live=False)               # operator-go 유보 default
    # P4: thread the LIVE SmfSessionTable into the controller so the stale-binding guard's (b)
    # cross-check (imsi_for_ip re-attribution) is active on the production act path — not just the
    # boot-snapshot (a). Absent (deps has no smf_table) -> best-effort (a)-only (fail-safe).
    # Phase 1: thread the sandbox operator_auto flag into the controller so the 2-tier gate widens a
    # registered OPER decision (docker_pause) to auto — the OPER recovery then EXECUTES here instead
    # of deferring to a human. DETERMINISTIC (env bool), transparency kept via ledger fields below.
    # Phase 4: thread the duck-typed docker backend so an operator_auto-widened docker_pause
    # ACTUATES (act_host.pause) instead of recording an inert decision — the S1 회복 completion
    # then becomes observable via inspect_paused. Absent (docker=None) -> operator-go DRY (fail-safe).
    ctrl = controller or ResponseController(
        backend=be, docker=docker, smf_table=smf_table, operator_auto=bool(operator_auto))

    # 2) plan: bundle idempotency/debounce + 2-tier gate (pure — no side effect yet)
    plan = ctrl.plan(chosen, world, tick_i, risk=risk, reversible=reversible)

    if plan.skip:
        # idempotent / debounced -> NO NEW actuation this tick. Count it toward quiescence
        # (dry_streak++), do NOT reset to 0. Resetting pinned dry_streak at 0 in a steady state
        # (a confirmed rule re-selected every tick is skipped every tick), so the driver's k_dry
        # quiescence break (PA-1) could never fire and runs burned to max_iters (~60 no-op ticks +
        # LLM calls). A pure skip performed no actuation, so it is NOT progress: increment, distinct
        # from the actuated path below which legitimately resets (a real side effect = progress).
        return {"dry_streak": int(state.get("dry_streak", 0)) + 1}

    if plan.operator_required:
        # tier-2 OPER (flight / docker pause): defer to operator, side-effect 0. Record a
        # command-bound operator-gate Intent (PS-9 digest binding; HMAC key stays in the
        # OperatorGate, never State). NO exec, NO backend call.
        # Q-D-3 NOTE: an audit flagged "reverse_container_for_ip dead in act (OPER pause container
        # not resolved)". There is NO such call to remove here — act.py never references
        # reverse_container_for_ip (it is live only in targets/resolve.py + test_p2_recon). The
        # OPER pause path INTENTIONALLY does not resolve the pause-target container: docker_pause
        # is operator-go, so act stops at recording the operator-gate Intent and the human resolves
        # the container out-of-band. Resolution is thus correctly absent, not dead code. DOCUMENT-
        # DEFER: wiring container resolution into this branch is an operator-tooling concern.
        op_intent = chosen.model_copy(update={
            "ts": ts, "operator_gate": True, "command_digest": command_digest(chosen),
        })
        op_update = ledger.record_intent(op_intent) if ledger is not None else {"ledger": [op_intent]}
        op_update["dry_streak"] = 0
        return op_update

    # 3) record_intent OUTSIDE guard, BEFORE exec (G3). Phase 1: when this AUTO plan is an OPER tool
    # widened by operator_auto, stamp the ledger Intent so an auditor can distinguish a sandbox
    # operator-auto-confirmed enforcement from a native AUTO one (transparency; registry_tier stays
    # OPER upstream). authority names WHO authorized it — the sandbox, not a human operator.
    op_auto_confirmed = bool(getattr(plan, "operator_auto_confirmed", False))
    # ① operator-select PRESERVATION: when the operator EXPLICITLY picked this candidate,
    # rank_recovery stamped chosen.authority="operator-select". Do NOT let the operator_auto widen
    # clobber that human provenance to "sandbox-auto" — the durable ledger must show WHO authorized
    # (Item A goal #3). This is the PRIMARY S2 path: operator picks send_signed_mode with
    # operator_auto ON -> gate widens flight to AUTO_BY_OPERATOR -> plan.operator_auto_confirmed=True.
    # We keep operator_auto_confirmed=True (sandbox auto-actuated) AND authority="operator-select"
    # (human selected) so the audit shows BOTH. Absent an inbound operator-select, native AUTO keeps
    # authority="sandbox-auto" (op_auto_confirmed) / "" as before (fail-safe, no regression).
    inbound_authority = getattr(chosen, "authority", "")
    authority = inbound_authority if inbound_authority == "operator-select" else (
        "sandbox-auto" if op_auto_confirmed else "")
    intent = chosen.model_copy(update={
        "ts": ts, "revert_cmd": plan.revert_cmd or chosen.revert_cmd,
        "operator_auto_confirmed": op_auto_confirmed,
        "authority": authority,
    })
    ledger_update = ledger.record_intent(intent) if ledger is not None else {"ledger": [intent]}

    # 4) tool_wrap = safe-exec body (Backend.run) + post world_update (only these two wrapped)
    def _body(_action: Action):
        return ctrl.run_plan(plan)                          # Backend.run(exec_request) — DRY unless live

    def _world_update(exec_result):
        rule = AppliedRule(
            rule=action.recovery_type, revert_cmd=intent.revert_cmd, ts=ts, applied_tick=tick_i,
            decision_id=intent.decision_id, config_version=intent.config_version,
            confirmed=False, provenance="verified",
        )
        return world.with_applied(rule)

    wrapped = def_tool_wrap(_body, pre_hooks=[], post_hooks=[_world_update])
    result = wrapped(action)                                # DefOk[WorldState] | DefErr

    out: dict = {"dry_streak": 0}
    out.update(ledger_update)
    if op_auto_confirmed:
        out["operator_auto_confirmed"] = True              # state marking (edge can't mutate state)
    if getattr(result, "ok", False):
        out["worldstate"] = result.value                   # merged world with applied rule
    return out
