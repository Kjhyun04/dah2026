"""core.modules.kb — 상태정보(WorldState) + tool 상태 판정(Legality) (11).

조합 창발의 런타임 엔진. 전부 **결정론**(LLM 아님, 11 §5).
  ① WorldState — '지금 아는 사실'의 타입된 저장소 (11 §1).
  ② legality(spec, kb) → {runnable, missing, effect_eval} (11 §2, Legality 하드게이트).
  ③ kb_update(kb, result) — 결과로 KB 갱신 (11 §3-A).
  ④ goal_reached(kb, goal) — 목표 도달 판정 (11 §3-B).

A12(18): KB=pydantic, 내부 set / 경계에서 정렬 list. B1: DB 없음(in-memory).
작성 2026-07-05.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from core.common.results import CollectResult, InjectResult, ReconResult
from core.common.types import (
    Artifact,
    BlockedBy,
    Cond,
    CondWhen,
    Disrupt,
    Fact,
    Risk,
    SetFlag,
    SetMode,
    ToolSpec,
    reach,
    unauth,
)

# ═══════════════════════════════════════════════════════════════════════════
# 1. WorldState — 상태정보 규격 (11 §1)
# ═══════════════════════════════════════════════════════════════════════════


class Signing(str, Enum):
    ON = "on"
    OFF = "off"
    UNKNOWN = "unknown"


class C2(str, Enum):
    UP = "up"
    DISRUPTED = "disrupted"
    UNKNOWN = "unknown"


class Scalars(BaseModel):
    """단일값 enum (11 §1-C). default unknown."""

    signing: Signing = Signing.UNKNOWN
    mode: Optional[int] = None  # None=unknown; 값 ∈ {0,4,5,9}
    c2: C2 = C2.UNKNOWN


class WorldState(BaseModel):
    """에이전트가 '지금 아는 사실'의 타입된 저장소 (11 §1).

    보수원칙(11 §1-D): 사실이 KB에 '없으면 = 미충족'(unknown=거짓 취급).
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    facts: set[Fact] = Field(default_factory=set)          # 참인 boolean 사실
    artifacts: set[Artifact] = Field(default_factory=set)  # 보유 아티팩트
    flags: set[str] = Field(default_factory=set)           # boolean 세계상태 플래그(SetFlag)
    scalars: Scalars = Field(default_factory=Scalars)
    prov: dict[str, str] = Field(default_factory=dict)     # 출처: recon|effect|config|asserted

    @staticmethod
    def initial(
        footholds: Optional[list[Fact]] = None,
        in_flight: bool = False,
        signing: Optional[Signing] = None,
    ) -> "WorldState":
        """초기 상태 (11 §1-D). facts={attached}+footholds, scalars=unknown, artifacts={}.

        goal.defense≠auto 면 signing 시드(19 PART1-1, prov=config).
        """
        from core.common.types import ATTACHED, IN_FLIGHT

        facts: set[Fact] = {ATTACHED}
        prov: dict[str, str] = {str(ATTACHED): "config"}
        if in_flight:
            facts.add(IN_FLIGHT)
            prov[str(IN_FLIGHT)] = "config"
        for f in footholds or []:
            facts.add(f)
            prov[str(f)] = "config"
        sc = Scalars()
        if signing is not None:
            sc.signing = signing
            prov["signing"] = "config"
        return WorldState(facts=facts, artifacts=set(), scalars=sc, prov=prov)

    def snapshot(self) -> dict[str, Any]:
        """경계 직렬화 (A12: 정렬 list). viewer/CampaignResult.kb_final 용."""
        return {
            "facts": sorted(str(f) for f in self.facts),
            "artifacts": sorted(a.value for a in self.artifacts),
            "flags": sorted(self.flags),
            "scalars": {
                "signing": self.scalars.signing.value,
                "mode": self.scalars.mode,
                "c2": self.scalars.c2.value,
            },
            "prov": dict(self.prov),
        }


# ═══════════════════════════════════════════════════════════════════════════
# 2. Legality — tool 상태 판정 (11 §2). 결정론.
# ═══════════════════════════════════════════════════════════════════════════


class EffectEvalKind(str, Enum):
    SET_MODE = "SetMode"
    DISRUPT = "Disrupt"
    SET_FLAG = "SetFlag"
    PRODUCE = "Produce"
    BLOCKED = "Blocked"
    UNCERTAIN = "Uncertain"
    NONE = "None"


class EffectEval(BaseModel):
    """KB 기반 효과 예측 (11 §2, 참고용·하드게이트 아님. 진실은 ACK)."""

    kind: EffectEvalKind
    blocked_by: Optional[BlockedBy] = None


class Missing(BaseModel):
    """미충족 항목 (11 §2 backward-chaining 힌트). fact | artifact | any-of 그룹."""

    kind: Literal["fact", "artifact", "any_of"]
    detail: str  # str(Fact) / Artifact.value / "a | b"


class ToolStatus(BaseModel):
    """legality 반환 (11 §2). runnable=하드게이트, missing=힌트, effect_eval=예측.

    requires_confirm (HITL 게이트 표식, 절대규칙5·DESIGN §8): risk==HIGH 이고 hitl_enabled
      일 때 True. optional 필드(default False)로만 확장 — 기존 필드/판정 불변(P0 무영향).
      실제 승인 프롬프트 실행은 P3 orchestrator 위임. 여기서는 표식만.
    """

    runnable: bool
    missing: list[Missing] = []
    effect_eval: EffectEval
    requires_confirm: bool = False


def _eval_effect(spec: ToolSpec, kb: WorldState) -> EffectEval:
    """s.effect를 W에 평가 (11 §2). 조건부(Cond)는 signing scalar에 판정."""
    eff = spec.effect
    if eff is None:
        # 산출만 하는 recon/collect
        kind = EffectEvalKind.PRODUCE if (spec.produces or spec.produces_facts) else EffectEvalKind.NONE
        return EffectEval(kind=kind)
    if isinstance(eff, SetMode):
        return EffectEval(kind=EffectEvalKind.SET_MODE)
    if isinstance(eff, Disrupt):
        return EffectEval(kind=EffectEvalKind.DISRUPT)
    if isinstance(eff, SetFlag):
        return EffectEval(kind=EffectEvalKind.SET_FLAG)
    if isinstance(eff, Cond):
        if eff.when == CondWhen.NEVER:
            # 대조군(naive): 항상 차단
            return EffectEval(kind=EffectEvalKind.BLOCKED, blocked_by=eff.else_blocked)
        if eff.when == CondWhen.SIGNING_OFF:
            sig = kb.scalars.signing
            if sig == Signing.OFF:
                inner = EffectEvalKind.SET_MODE if isinstance(eff.then, SetMode) else EffectEvalKind.DISRUPT
                return EffectEval(kind=inner)
            if sig == Signing.ON:
                return EffectEval(kind=EffectEvalKind.BLOCKED, blocked_by=eff.else_blocked)
            return EffectEval(kind=EffectEvalKind.UNCERTAIN)  # unknown
    return EffectEval(kind=EffectEvalKind.UNCERTAIN)


def legality(spec: ToolSpec, kb: WorldState, hitl_enabled: bool = True) -> ToolStatus:
    """결정론 Legality 게이트 (11 §2, 06 §4).

    runnable = precond ⊆ facts ∧ (각 require_any 그룹 ≥1 충족) ∧ consumes ⊆ artifacts.
    missing  = 미충족 목록(백워드체이닝). effect_eval = 조건부 효과 예측.

    HITL 게이트(절대규칙5·DESIGN §8): risk==HIGH(예: forceland — 비가역·물리 LAND)이고
      hitl_enabled(**기본 on**) 이면 requires_confirm=True 표식 부여. 실행 직전 승인 필요를
      의미하나 승인 프롬프트 자체는 P3 orchestrator 담당. hitl_enabled=False 로 명시적
      opt-out 가능(플래그 종속). runnable 하드게이트와는 독립(표식만).
    """
    missing: list[Missing] = []

    for f in spec.precond:
        if f not in kb.facts:
            missing.append(Missing(kind="fact", detail=str(f)))

    for group in spec.require_any:
        if not any(f in kb.facts for f in group):
            missing.append(
                Missing(kind="any_of", detail=" | ".join(str(f) for f in group))
            )

    for agroup in spec.require_any_artifact:
        if not any(a in kb.artifacts for a in agroup):
            missing.append(
                Missing(kind="any_of", detail=" | ".join(a.value for a in agroup))
            )

    for a in spec.consumes:
        if a not in kb.artifacts:
            missing.append(Missing(kind="artifact", detail=a.value))

    runnable = len(missing) == 0
    requires_confirm = hitl_enabled and spec.risk == Risk.HIGH
    return ToolStatus(
        runnable=runnable,
        missing=missing,
        effect_eval=_eval_effect(spec, kb),
        requires_confirm=requires_confirm,
    )


# ═══════════════════════════════════════════════════════════════════════════
# 3. kb_update — 결과로 KB 갱신 (11 §3-A). post_hook에서 호출.
# ═══════════════════════════════════════════════════════════════════════════

_ResultT = Union[ReconResult, CollectResult, InjectResult]


def _parse_reach(token: str) -> Optional[Fact]:
    """'role@ip:port' 또는 'role' → reach(role) Fact. 닫힌 어휘만 수용."""
    from core.common.types import ReachTarget

    role = token.split("@", 1)[0].strip()
    try:
        ReachTarget(role)  # 어휘 검증
    except ValueError:
        return None
    return reach(role)


def kb_update(kb: WorldState, result: _ResultT) -> WorldState:
    """결과 종류별로 KB in-place 갱신 (11 §3-A). 모든 갱신은 prov 기록.

    ReconResult  → reach 사실 · signing scalar · unauth.
    CollectResult→ artifacts += produced.
    InjectResult → effect(mode/c2) · blocked_by(signing 확증). (완전분리: ground-truth 없음)
    """
    if isinstance(result, ReconResult):
        for tok in result.reach:
            f = _parse_reach(tok)
            if f is not None:
                kb.facts.add(f)
                kb.prov[str(f)] = "recon"
        for svc in result.unauth:
            f = unauth(svc)
            kb.facts.add(f)
            kb.prov[str(f)] = "recon"
        if result.signing in ("on", "off"):
            kb.scalars.signing = Signing(result.signing)
            kb.prov["signing"] = "recon"
        if result.seid:
            kb.artifacts.add(Artifact.SEID)
            kb.prov[Artifact.SEID.value] = "recon"
        if result.observed_mode is not None:
            kb.scalars.mode = int(result.observed_mode)
            kb.prov["mode"] = "observed"   # 실측 관측(observe_mode) — 자기판정 배제

    elif isinstance(result, CollectResult):
        for key in result.artifacts:
            try:
                art = Artifact(key)
            except ValueError:
                continue  # 닫힌 어휘 밖 무시(정직: 아는 것만 반영)
            kb.artifacts.add(art)
            kb.prov[art.value] = "effect"

    elif isinstance(result, InjectResult):
        # blocked_by=signing → signing=on 확증(정보 획득, 상태변경 없음) (11 §3-A)
        if result.blocked_by == "signing":
            kb.scalars.signing = Signing.ON
            kb.prov["signing"] = "asserted"
        # ★ blocked_by 가드 (19 PART1-3): accepted AND blocked_by is None 일 때만 effect 적용.
        #   차단된 InjectResult(=blocked_by 세팅됨)는 mode/c2/flags 를 절대 바꾸지 않음(불변).
        if result.accepted and result.blocked_by is None:
            eff = result.effect or {}
            if "mode" in eff:
                try:
                    kb.scalars.mode = int(eff["mode"])
                    kb.prov["mode"] = "asserted"
                except (ValueError, TypeError):
                    pass
            if eff.get("c2") == "disrupted":
                kb.scalars.c2 = C2.DISRUPTED
                kb.prov["c2"] = "asserted"
            # SetFlag 효과(subscriber_written 등): mode/c2 외 truthy 키 → 세계상태 플래그
            for k, v in eff.items():
                if k in ("mode", "c2"):
                    continue
                if str(v).lower() in ("true", "1", "yes", "on"):
                    kb.flags.add(k)
                    kb.prov[k] = "asserted"

    return kb


# ═══════════════════════════════════════════════════════════════════════════
# 4. goal_reached — 목표 도달 판정 (11 §3-B). 결정론(감독 LLM 0, 18-A14).
# ═══════════════════════════════════════════════════════════════════════════


class Goal(BaseModel):
    """목표 규격 (15 InputSpec.goal · 11 §3-B).

    type ∈ {mode_set, c2_disrupt, exfil, signing_bypass}.
    target: mode_set/signing_bypass={"mode":4} · exfil={"artifact":"sign_key"}.
    scope: 허용 공격 계층코드 부분집합(예: ['A','B']). 미지정=None=전체(RECON 상시 허용).
      goal_reached 판정엔 미사용 — prompt_context.scoped_tool_ids 의 계층 필터 입력.
      기존 호출(scope 미전달)은 None 으로 그대로 동작(하위호환).
    """

    type: Literal["mode_set", "c2_disrupt", "exfil", "signing_bypass"]
    target: dict[str, Any] = {}
    success: Literal["ack", "ground_truth"] = "ack"
    scope: Optional[list[str]] = None


def _as_int(x: Any) -> Optional[int]:
    """느슨한 int 강제 (양변 정규화). 실패=None. goal.target.mode 가 str '4' 여도 매칭."""
    if isinstance(x, bool):  # bool 은 int 하위형 — 오매칭 방지
        return None
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def goal_reached(kb: WorldState, goal: Goal) -> bool:
    """목표별 도달 조건 (11 §3-B). KB 스칼라/아티팩트 비교. 결정론.

    mode 비교는 **양변 int 강제**(_as_int) — target 이 '4'(str) 여도 mode==4 매칭.
    signing_bypass = mode==target AND signing==on AND prov[mode]==asserted
      (서명 강제 하 우회 성립. prov 가드로 'config 시드가 아니라 실제 주입으로 달성'을
       하드코딩 없이 확인 — 19 PART1-3 정합).
    """
    t = goal.type
    if t == "mode_set":
        m, want = _as_int(kb.scalars.mode), _as_int(goal.target.get("mode"))
        if not (m is not None and want is not None and m == want):
            return False
        if goal.success == "ground_truth":
            return kb.prov.get("mode") == "observed"  # 실측 관측(observe_mode)만 성립
        return True
    if t == "c2_disrupt":
        return kb.scalars.c2 == C2.DISRUPTED
    if t == "exfil":
        want_a = goal.target.get("artifact")
        try:
            return Artifact(want_a) in kb.artifacts
        except ValueError:
            return False
    if t == "signing_bypass":
        m, want = _as_int(kb.scalars.mode), _as_int(goal.target.get("mode"))
        need = "observed" if goal.success == "ground_truth" else "asserted"
        return (
            m is not None
            and want is not None
            and m == want
            and kb.scalars.signing == Signing.ON
            and kb.prov.get("mode") == need  # ground_truth=실측관측 · ack=자기주장(하위호환)
        )
    return False


__all__ = [
    "WorldState",
    "Scalars",
    "Signing",
    "C2",
    "ToolStatus",
    "EffectEval",
    "EffectEvalKind",
    "Missing",
    "legality",
    "kb_update",
    "goal_reached",
    "Goal",
]
