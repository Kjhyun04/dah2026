"""act (PA-6) — 적법성 사전검사 -> 2-tier gate/bundle -> record_intent(guard 밖) -> tool_wrap.

순서(정확히):
  1. 적법성 사전검사 (tool_wrap/guard 밖): 현재 worldstate +
     고정된 config_version(X7)에 대해 재검증. 위법 -> side-effect-0 조기 반환.
  2. Response Controller plan (순수, side effect 없음): bundle 멱등성/N-tick 디바운스
     (core.bundle) + 2-tier gate (core.gate).
       - SKIP (멱등/디바운스됨) -> intent 없음, exec 없음 (dry_streak++로 정적화 진행, 리셋
         아님 — skip은 작동이 아니므로 진행으로 위장해 k_dry를 무력화해서는 안 됨).
       - OPER tier (비행 / docker pause) -> operator-gate Intent 기록 (command_digest
         바인딩, PS-9), side-effect 0, exec 없음 (tier-2는 operator에 위임; "비행=operator").
  3. record_intent (guard 밖, 항상 exec 전): Intent를 영속 JSONL + ledger
     채널에 기록해 recover_on_boot이 누출을 되돌릴 수 있게 함 (G3).
  4. tool_wrap = Backend.run(ExecRequest) [safe-exec] + post world_update. legality/record_intent
     은 tool_wrap 안에 있지 않다.

이 노드는 subprocess를 직접 호출하지 않는다 — 오직 Response Controller를 통한 Backend.run만 (불변식2.).
라이브 작동은 operator-go RESERVED (Backend.allow_live=False -> DRY-RUN). act 시 dry_streak -> 0.
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
        return {}                                          # 할 일 없음

    risk = state.get("chosen_action_risk", "LOW")
    reversible = state.get("chosen_action_reversible", True)
    action = Action(
        tool_id=chosen.tool_id,
        # ENFORCEMENT 컨테이너 + source 셀렉터를 실어 legality pre-hook이 레지스트리의
        # role_verified 별칭을 REAL 컨테이너 키로 해석할 수 있게 함 (step 10 동적 바인딩).
        # 없으면 재구성된 Action이 구체 셀렉터를 못 실어 fail-closed
        # role_verified 검사가 모든 자율 동작을 거부한다. 데이터 전용 (라이브 해석 없음).
        params={"recovery_type": chosen.rule, "enforce_at": chosen.enforce_at,
                "target": chosen.target, "target_kind": chosen.target_kind},
        risk=risk, reversible=reversible,
        recovery_type=chosen.rule,
    )

    # 1) tool_wrap 밖 적법성 사전검사 (위법 시 side-effect 0)
    try:
        assert_legal(action, state)
    except CRSError:
        return {}                                          # 위법 -> side-effect 0 조기 반환

    ts = clock.now() if clock is not None else 0.0
    world: WorldState = state.get("worldstate") or WorldState()
    tick_i = int(state.get("tick_i", 0))

    be = backend or Backend(allow_live=False)               # operator-go 유보 기본값
    # P4: LIVE SmfSessionTable을 controller에 연결해 stale-binding guard의 (b)
    # 교차검사(imsi_for_ip 재귀속)를 프로덕션 act 경로에서 활성화 — boot-snapshot(a)
    # 만이 아님. 없으면 (deps에 smf_table 없음) -> best-effort (a)-only (fail-safe).
    # Phase 1: sandbox operator_auto 플래그를 controller에 연결해 2-tier gate가
    # 등록된 OPER 결정(docker_pause)을 auto로 확장 — OPER 회복이 사람에 위임하지 않고
    # 여기서 EXECUTE된다. 결정론적(env bool), 투명성은 아래 ledger 필드로 유지.
    # Phase 4: duck-typed docker backend를 연결해 operator_auto로 확장된 docker_pause가
    # 비활성 결정 기록 대신 ACTUATE(act_host.pause)하도록 — S1 회복 완료가
    # 그다음 inspect_paused로 관측 가능해진다. 없으면 (docker=None) -> operator-go DRY (fail-safe).
    ctrl = controller or ResponseController(
        backend=be, docker=docker, smf_table=smf_table, operator_auto=bool(operator_auto))

    # 2) plan: bundle 멱등성/디바운스 + 2-tier gate (순수 — 아직 side effect 없음)
    plan = ctrl.plan(chosen, world, tick_i, risk=risk, reversible=reversible)

    if plan.skip:
        # 멱등 / 디바운스됨 -> 이번 tick에 NEW 작동 없음. 정적화로 계산
        # (dry_streak++), 0으로 리셋 금지. 정상상태에서 고정된 dry_streak을 0으로 리셋하면
        # (매 tick 재선택되는 확정 규칙이 매 tick skip됨), 드라이버의 k_dry
        # 정적화 break(PA-1)이 결코 발화 못 하고 max_iters까지 소진(~60 no-op tick +
        # LLM 호출). 순수 skip은 작동을 안 했으므로 진행이 아님: 증가시키되, 아래
        # 정당하게 리셋하는 작동 경로와 구분(실제 side effect = 진행).
        return {"dry_streak": int(state.get("dry_streak", 0)) + 1}

    if plan.operator_required:
        # tier-2 OPER (비행 / docker pause): operator에 위임, side-effect 0. command에
        # 바인딩된 operator-gate Intent 기록 (PS-9 digest 바인딩; HMAC 키는
        # OperatorGate에 상주, State에는 절대 없음). exec 없음, backend 호출 없음.
        # Q-D-3 NOTE: 감사에서 "reverse_container_for_ip가 act에서 dead (OPER pause 컨테이너
        # 미해석)"라고 표시됨. 여기서 제거할 그런 호출은 없음 — act.py는
        # reverse_container_for_ip를 참조하지 않는다 (targets/resolve.py + test_p2_recon에서만 라이브).
        # OPER pause 경로는 의도적으로 pause 대상 컨테이너를 해석하지 않음: docker_pause는
        # operator-go이므로 act은 operator-gate Intent 기록에서 멈추고 사람이
        # 컨테이너를 out-of-band로 해석한다. 따라서 해석 부재는 정당하며 dead code 아님. DOCUMENT-
        # DEFER: 이 분기에 컨테이너 해석을 배선하는 것은 operator-tooling 사안이다.
        op_intent = chosen.model_copy(update={
            "ts": ts, "operator_gate": True, "command_digest": command_digest(chosen),
        })
        op_update = ledger.record_intent(op_intent) if ledger is not None else {"ledger": [op_intent]}
        op_update["dry_streak"] = 0
        return op_update

    # 3) guard 밖, exec 전 record_intent (G3). Phase 1: 이 AUTO plan이 operator_auto로
    # 확장된 OPER 도구일 때, ledger Intent에 스탬프해 감사자가 sandbox
    # operator-auto-confirmed 집행을 네이티브 AUTO와 구분할 수 있게 함 (투명성; registry_tier는
    # 상류에서 OPER 유지). authority는 누가 권한을 부여했는지 명시 — 사람 operator가 아닌 sandbox.
    op_auto_confirmed = bool(getattr(plan, "operator_auto_confirmed", False))
    # 1. operator-select 보존: operator가 이 후보를 명시적으로 골랐을 때,
    # rank_recovery가 chosen.authority="operator-select"를 스탬프함. operator_auto 확장이
    # 그 사람 provenance를 "sandbox-auto"로 덮어쓰게 두지 마라 — 영속 ledger는 누가 권한을 부여했는지
    # 보여야 함 (Item A goal #3). 이것이 PRIMARY S2 경로: operator가 send_signed_mode를
    # operator_auto ON으로 선택 -> gate가 flight를 AUTO_BY_OPERATOR로 확장 -> plan.operator_auto_confirmed=True.
    # operator_auto_confirmed=True (sandbox 자동작동) AND authority="operator-select"
    # (사람 선택)를 유지해 감사가 둘 다 보이게 함. 인바운드 operator-select가 없으면 네이티브 AUTO는
    # authority="sandbox-auto" (op_auto_confirmed) / "" 를 이전처럼 유지 (fail-safe, 회귀 없음).
    inbound_authority = getattr(chosen, "authority", "")
    authority = inbound_authority if inbound_authority == "operator-select" else (
        "sandbox-auto" if op_auto_confirmed else "")
    intent = chosen.model_copy(update={
        "ts": ts, "revert_cmd": plan.revert_cmd or chosen.revert_cmd,
        "operator_auto_confirmed": op_auto_confirmed,
        "authority": authority,
    })
    ledger_update = ledger.record_intent(intent) if ledger is not None else {"ledger": [intent]}

    # 4) tool_wrap = safe-exec 본체 (Backend.run) + post world_update (이 둘만 래핑)
    def _body(_action: Action):
        return ctrl.run_plan(plan)                          # Backend.run(exec_request) — 라이브 아니면 DRY

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
        out["operator_auto_confirmed"] = True              # state 마킹 (edge는 state를 변경 못 함)
    if getattr(result, "ok", False):
        out["worldstate"] = result.value                   # applied rule이 병합된 world
    return out
