"""rank_recovery (PA-4/PS-7) — 결정론 액션 선택.

legal 액션을 recovery prior 점수로 정렬하고, 최상위를 chosen_action 에 바인딩하며,
번들 수준 chosen_action_risk = max(원자 risk), chosen_action_reversible
= all(op.reversible) 를 decide-edge 가 읽는 State 필드로 승격한다. 후보 없음 ->
chosen_action = None. Debounce(dry_streak) + 출처 게이트가 주입된
high-severity 가 자동 대응을 촉발하지 못하게 막는다(PS-7).

Phase 2 (B3, 샌드박스 데모) — 출처/debounce 완화: operator_auto 하에서 엄격한
"신뢰 소스 요구" 보류가 RECORD-THEN-PASS 로 완화된다. rank_recovery 는 선택된
Intent 에 provenance_relaxed=True 를 각인하여 ledger/trace 가 면제를 투명하게 기록하게 하고,
물리 액션 debounce 는 하류(response.py)에서 config demo_mode.debounce_ticks 로 축소되어
주입된 high-severity recovery 가 다음 tick 안에 재바인딩된다. PRODUCTION(operator_auto off)
은 변경 없음: provenance_relaxed 는 False 로 유지되고 전체 debounce 보류가 적용된다(엄격 PS-7).
"""
from __future__ import annotations

from ...config import loader
from ...safe_exec.signer_shim import command_digest
from ..scoring import recovery_score
from ..state import Action, Intent, MDGState

_RISK_ORDER = {"LOW": 0, "MED": 1, "HIGH": 2}


def _bundle_risk(actions: list[Action]) -> str:
    if not actions:
        return "LOW"
    return max(actions, key=lambda a: _RISK_ORDER[a.risk]).risk       # 최대 risk


def _bundle_reversible(actions: list[Action]) -> bool:
    return all(a.reversible for a in actions)                          # 전부 reversible


def rank_recovery(state: MDGState) -> dict:
    legal: list[Action] = state.get("legal_actions", [])
    if not legal:
        return {"chosen_action": None, "chosen_action_risk": "LOW",
                "chosen_action_reversible": True}

    # 1. OPERATOR-SELECT (env->STATE, 결정론, 불변식1.): 오퍼레이터가 후보를 명시적으로 고르면
    # (MDG_OPERATOR_PICK -> state['operator_pick'], operator_auto 처럼 live_autorun 이 시드),
    # 매칭되는 legal Action 을 chosen_action 으로 승격하여, reversible-blockade 도구를
    # send_signed_mode 아래로 영구히 강등하는 자율 랭킹을 우회한다. 매칭은
    # recovery_type 또는 tool_id 로 한다(어느 표기든 허용). 공백/비매칭 pick 은 무시된다
    # (자율 랭킹 유지 — fail-safe). LLM 없음: 닫힌 legal 집합에 대한 순수 문자열 동등 비교.
    # pick 이 실현가능성 하한 아래여도 승격은 존중된다: 이것은
    # 사람의 인가이므로 자율 실현가능성 휴리스틱으로 재게이트되어서는 안 된다.
    pick = str(state.get("operator_pick") or "").strip()
    operator_selected = None
    if pick:
        for a in legal:
            if a.recovery_type == pick or a.tool_id == pick:
                operator_selected = a
                break

    rp = loader.recovery_priors()
    priors = rp.get("recovery_priors", {})
    # 실현가능성 게이트는 recovery_score 가 아니라 success_probability 를 비교한다(M6/E-2). config
    # 롤오버 중 복원력을 위해 레거시 키를 폴백으로 허용한다.
    feasible_min = float(rp.get("success_prob_feasible_min", rp.get("feasible_min", 0.70)))

    def _succ(a: Action) -> float:
        return float(priors.get(a.recovery_type, {}).get("success_probability", 0.5))

    def score(a: Action) -> float:
        # 복합 랭킹 점수(prototype §5). trust_rec = 복구된 trust 포인트.
        p = priors.get(a.recovery_type, {})
        rec = p.get("expected_trust_recovery", {})
        trust_rec = sum(float(v) for v in rec.values())
        risk_w = {"LOW": 0.1, "MED": 0.3, "HIGH": 0.6}[a.risk]
        return recovery_score(_succ(a), trust_rec, mission_rec=trust_rec, risk=risk_w, cost=0.0)

    # 실현가능성 게이트 = success_probability >= feasible_min (FEASIBILITY §3 priors).
    # 실현가능 후보 간 랭킹 = 복합 recovery_score. (M6/E-2 조정 — DESIGN 노트 참조:
    # 문서의 "recovery_score>=0.7" 과 20-40pt trust-delta priors 는 서로
    # 맞지 않는다; success_probability 가 보정된 실현가능성 신호이다.)
    # PP-1 바인딩 계약(panel-1 step d + risk-note 3): 정렬 안정성에 기댄 단일 점수가 아니라
    # 명시적 결정론 키 튜플로 정렬한다. recovery_score 는
    # ~0.14-0.38 로 압축되어 동점이 흔하다; 입력 순서에 의존하면 리플레이 재현성이 깨진다
    # (불변식1.). 순서 = recovery_score 내림차순, 그다음 낮은 risk, 그다음 reversible 우선, 그다음
    # recovery_type 이름 — legal_actions 순열과 무관한 전순서.
    def _sort_key(a: Action) -> tuple:
        return (-score(a), _RISK_ORDER[a.risk], 0 if a.reversible else 1, a.recovery_type)

    if operator_selected is not None:
        # operator-select 는 자율 랭킹과 실현가능성 게이트를 모두 재정의한다(사람의 권한).
        top = operator_selected
    else:
        feasible = [a for a in legal if _succ(a) >= feasible_min]
        if not feasible:
            return {"chosen_action": None, "chosen_action_risk": "LOW",
                    "chosen_action_reversible": True}
        ranked = sorted(feasible, key=_sort_key)
        top = ranked[0]

    # Phase 2 (B3/PS-7) 출처/debounce 완화 — 결정론(env bool + config, LLM 없음,
    # 불변식1.). operator_auto(샌드박스 데모) 하에서 주입된 high-severity recovery 에 대한
    # 엄격한 신뢰-소스 보류가 RECORD-THEN-PASS 된다: 선택된 Intent 에 provenance_relaxed=True 를
    # 각인하여 ledger/trace 가 면제를 보이게 한다(response.py 가 별도로 debounce 를
    # demo_mode.debounce_ticks 로 축소). Production(operator_auto off) -> False, 엄격 태세 유지.
    operator_auto = bool(state.get("operator_auto"))
    provenance_relaxed = operator_auto and bool(loader.demo_mode().get("provenance_relaxed", False))

    # 원자 번들 = recovery + attack-path block (X4/X6). 여기서는 단일-op 번들.
    bundle = [top]
    # P4-Q1 — 랭킹된 후보의 params 에서 불투명 검증 셀렉터를 선택된
    # Intent 로 실어 나른다. 이것이 빠져 있던 하중 배선이다: rank_recovery 는 이전에
    # top.params 를 버려서 chosen_action 이 target 을 잃고 dispatch 가 추측해야 했다. 셀렉터를
    # 데이터로만 복사한다 — 여기서 라이브 해석은 없음(이 노드는 backend/netns 를 보유하지 않음; 불변식2.).
    # (pid, src_ip) 바인딩은 dispatch 에서 검증된 WorldState 맵에 대한 순수 조회로 일어난다.
    intent = Intent(
        rule=top.recovery_type, tool_id=top.tool_id,
        revert_cmd=f"revert:{top.recovery_type}",
        config_version=state.get("config_version", ""),
        target=str(top.params.get("target", "")),
        target_kind=str(top.params.get("target_kind", "")),
        # P4-2 — 소스 셀렉터와 함께 집행 초크포인트 셀렉터를 실어 dispatch 가
        # 서로 다른 두 검증 엔드포인트를 해석하게 한다. 데이터만(여기서 라이브 해석 없음; 불변식2.).
        enforce_at=str(top.params.get("enforce_at", "")),
        # Phase 2 (B3) — record-then-pass 면제 마커(데모 전용; production 에서는 False).
        provenance_relaxed=provenance_relaxed,
        # 1. operator-select 출처: 누가 이 액션을 선택했는지 표시하여 ledger/trace 가
        # 사람의 인가(자율 랭킹 대비)를 보이게 한다. 자율 경로는 ""(회귀 0).
        authority="operator-select" if operator_selected is not None else "",
    )
    if operator_selected is not None:
        # operator-select 된 Intent 를 COMMAND-BIND(PS-9): KEY-FREE command_digest 를 각인하여
        # 바인딩이 chosen_action 을 타고 OperatorGate 인가(operator_auto-off 경로의
        # escalate.issue)와 operator_auto 하 act 의 집행 Intent 로 전달되게 한다(model_copy 가
        # 보존) — 다른 명령용으로 발행된 포획 승인은 이것을 인가할 수 없다.
        # command_digest 는 식별 필드에 대한 순수 sha256; 서명 키는 열지 않는다
        # (verify_signer_no_keyopen — 업링크 서명은 gcs_c2 에 머문다).
        intent = intent.model_copy(update={"command_digest": command_digest(intent)})
    return {
        "chosen_action": intent,
        "chosen_action_risk": _bundle_risk(bundle),
        "chosen_action_reversible": _bundle_reversible(bundle),
    }
