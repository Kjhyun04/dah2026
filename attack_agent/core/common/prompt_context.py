"""core.common.prompt_context — Jinja2 렌더 어댑터 (P3, 과제 §12-2).

WorldState(kb.py) + ToolStatus 목록 + Goal 을 prompts/default.yaml 의 뷰 변수로
**명시 매핑**한다(문서 gap: legality 반환 ToolStatus 엔 layer/produces 없음 -> spec 과 합성):

  agent.goal_text
  agent.kb.{signing, mode, c2, reach_list, artifact_list, prov_notes}
  agent.tool_status[].{id, layer, runnable, missing, effect_eval, produces}

규율:
  - **jinja2.StrictUndefined** 강제 — 템플릿이 없는 필드를 참조하면 조용한 빈칸이 아니라
    **예외**(필드 어긋남 조기 검출). (과제 §12-2)
  - tool_status 는 REGISTRY 22 ∩ goal.scope 필터(scope 미지정=22 전량)로 빌드하며,
    orchestrator 의 _tools 필터와 **동일 닫힌 집합**이어야 함(yaml 상단 규율).
    -> RECON 계층은 **상시 포함**(scope 로 정찰을 봉쇄하지 않음, gap 해소).

레시피 금지: 이 어댑터는 상태를 '표시'만 하며 순서/조합을 처방하지 않는다.
작성 2026-07-05.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import jinja2
import yaml

from core.common.types import Layer, PredKind, ToolId, ToolSpec
from core.modules.kb import EffectEval, Goal, Missing, ToolStatus, WorldState
from core.modules.registry import REGISTRY, get_spec

# ═══════════════════════════════════════════════════════════════════════════
# 0. Jinja2 env — StrictUndefined(어긋난 필드 = 예외)
# ═══════════════════════════════════════════════════════════════════════════

_ENV = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)


def render(template_str: str, agent_ctx: "AgentView") -> str:
    """template_str 를 agent_ctx 로 렌더. 필드 어긋나면 StrictUndefined 예외.

    default.yaml 의 변수는 전부 `agent.*` 이므로 {'agent': ctx} 로 바인딩.
    """
    tmpl = _ENV.from_string(template_str)
    return tmpl.render(agent=agent_ctx)


# ═══════════════════════════════════════════════════════════════════════════
# 1. scope 필터 — REGISTRY 22 ∩ goal.scope (RECON 상시 포함)
# ═══════════════════════════════════════════════════════════════════════════


def scoped_tool_ids(goal: Goal) -> list[ToolId]:
    """노출·실행할 닫힌 tool 집합. scope 미지정(None/빈)=22 전량. RECON 은 항상 포함.

    goal.scope(정식 필드, kb.Goal) = Layer 문자값 목록(예: ['A','B','C','D']).
    None 또는 빈 리스트 -> REGISTRY 22 전량. 지정 시 해당 계층 tool 만 통과시키되
    RECON 계층(정찰=전 계층 공용)은 scope 와 무관하게 상시 포함(gap 해소).
    """
    ids = list(REGISTRY.keys())
    scope = goal.scope
    if not scope:
        return ids
    allowed = {str(s).strip().upper() for s in scope}
    return [
        tid
        for tid in ids
        if REGISTRY[tid].layer == Layer.RECON or REGISTRY[tid].layer.value in allowed
    ]


# ═══════════════════════════════════════════════════════════════════════════
# 2. 뷰 객체 — default.yaml 변수와 1:1 (plain dataclass; 없는 속성은 jinja 예외)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ToolStatusView:
    """agent.tool_status[] 원소. legality(ToolStatus) + spec(layer/produces) 합성."""

    id: str
    layer: str
    runnable: bool
    missing: list[str] = field(default_factory=list)
    effect_eval: str = ""
    produces: list[str] = field(default_factory=list)


@dataclass
class KBView:
    """agent.kb.*. WorldState.snapshot 키를 템플릿 필드명으로 재매핑."""

    signing: str
    mode: Any
    c2: str
    reach_list: list[str]
    artifact_list: list[str]
    prov_notes: str


@dataclass
class AgentView:
    """agent.* 루트. system/user 템플릿이 참조하는 유일 컨텍스트."""

    goal_text: str
    kb: KBView
    tool_status: list[ToolStatusView]


# ═══════════════════════════════════════════════════════════════════════════
# 3. 매핑 헬퍼 (결정론 · 표시 전용)
# ═══════════════════════════════════════════════════════════════════════════


def _goal_text(goal: Goal) -> str:
    """선언적 목표 -> 사람이 읽는 1줄(레시피 아님, 목표 표시)."""
    t = goal.type
    tgt = goal.target or {}
    if t in ("mode_set", "signing_bypass"):
        return f"{t}: mode={tgt.get('mode')}"
    if t == "exfil":
        return f"exfil: artifact={tgt.get('artifact')}"
    if t == "c2_disrupt":
        return "c2_disrupt: c2 := disrupted"
    return f"{t}: {tgt}"


def _fmt_effect_eval(ee: EffectEval) -> str:
    """EffectEval -> 'SetMode' / 'Blocked(signing)' 등 표시 문자열."""
    if ee.blocked_by is not None:
        return f"Blocked({ee.blocked_by.value})"
    return ee.kind.value


def _fmt_missing(missing: list[Missing]) -> list[str]:
    """Missing 목록 -> detail 문자열 목록(백워드체이닝 힌트 표시)."""
    return [m.detail for m in missing]


def _produces_of(spec: ToolSpec) -> list[str]:
    """spec.produces(아티팩트) + produces_facts(사실) 표시 목록."""
    out = [a.value for a in spec.produces]
    out += [str(f) for f in spec.produces_facts]
    return out


def _reach_list(kb: WorldState) -> list[str]:
    """kb.facts 중 reach(...) 사실의 대상 정렬 목록."""
    return sorted(
        f.arg for f in kb.facts if f.pred == PredKind.REACH and f.arg is not None
    )


def _artifact_list(kb: WorldState) -> list[str]:
    return sorted(a.value for a in kb.artifacts)


def _prov_notes(kb: WorldState) -> str:
    """config 시드가 아닌 출처(recon/effect/asserted)만 요약. 없으면 '' (템플릿에서 생략)."""
    notes = [
        f"{k}←{src}" for k, src in sorted(kb.prov.items()) if src != "config"
    ]
    return ", ".join(notes)


def _kb_view(kb: WorldState) -> KBView:
    return KBView(
        signing=kb.scalars.signing.value,
        mode=("미확인" if kb.scalars.mode is None else kb.scalars.mode),
        c2=kb.scalars.c2.value,
        reach_list=_reach_list(kb),
        artifact_list=_artifact_list(kb),
        prov_notes=_prov_notes(kb),
    )


# ═══════════════════════════════════════════════════════════════════════════
# 4. 최상위 빌더
# ═══════════════════════════════════════════════════════════════════════════


def build_tool_status(statuses: dict[str, ToolStatus]) -> list[ToolStatusView]:
    """{tool_id: ToolStatus} -> 뷰 목록. spec(layer/produces)과 합성.

    statuses 키가 곧 닫힌 집합(orchestrator 가 scoped_tool_ids 로 만든 것과 동일해야).
    """
    views: list[ToolStatusView] = []
    for tid, st in statuses.items():
        spec = get_spec(tid)
        views.append(
            ToolStatusView(
                id=tid,
                layer=spec.layer.value,
                runnable=st.runnable,
                missing=_fmt_missing(st.missing),
                effect_eval=_fmt_effect_eval(st.effect_eval),
                produces=_produces_of(spec),
            )
        )
    return views


def build_prompt_context(
    goal: Goal,
    kb: WorldState,
    statuses: dict[str, ToolStatus],
) -> AgentView:
    """default.yaml user 템플릿 변수 공급(agent.*). 결정론 · 표시 전용.

    statuses = {tid: legality(spec, kb)} — orchestrator 가 scoped_tool_ids 로 계산해 전달.
    """
    return AgentView(
        goal_text=_goal_text(goal),
        kb=_kb_view(kb),
        tool_status=build_tool_status(statuses),
    )


# ═══════════════════════════════════════════════════════════════════════════
# 5. 프롬프트 로더 — 단일 default.yaml(최소 Jinja2, per-model merge 미채용)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class AgentPrompt:
    """agents.<Name>.{system, user, adapt_user?, tools}. tools[tid] = {summary, params}."""

    system: str
    user: str
    adapt_user: Optional[str]
    tools: dict[str, dict[str, Any]]


def _default_prompts_path() -> Path:
    # core/common/prompt_context.py -> attack_agent/prompts/default.yaml
    return Path(__file__).resolve().parents[2] / "prompts" / "default.yaml"


def load_agent_prompt(
    agent_name: str = "AttackOrchestrator",
    path: Optional[Path] = None,
) -> AgentPrompt:
    """default.yaml 에서 지정 에이전트의 system/user/adapt_user/tools 를 로드."""
    p = path or _default_prompts_path()
    with open(p, "rb") as f:
        raw = yaml.safe_load(f)
    agents = (raw or {}).get("agents", {})
    if agent_name not in agents:
        raise KeyError(f"agents.{agent_name} not found in {p}")
    a = agents[agent_name]
    return AgentPrompt(
        system=a["system"],
        user=a["user"],
        adapt_user=a.get("adapt_user"),
        tools=a.get("tools", {}) or {},
    )


__all__ = [
    "render",
    "scoped_tool_ids",
    "AgentView",
    "KBView",
    "ToolStatusView",
    "build_prompt_context",
    "build_tool_status",
    "AgentPrompt",
    "load_agent_prompt",
]
