"""Evidence summarizer (non-load-bearing).

This module provides optional LLM-based narration for operator-facing context.
It never changes legality, tool selection, or KB transitions.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional

from core.common import llm
from core.common.results import StepRecord
from core.modules.kb import Goal, ToolStatus, WorldState
from core.modules.tool_wrap import Ok

_WS_RE = re.compile(r"\s+")


class EvidenceAgent:
    """Generate short correlate/narrate notes from current campaign state."""

    def __init__(
        self,
        *,
        model: str,
        temperature: float = 0.2,
        max_chars: int = 260,
        use_llm: bool = True,
    ) -> None:
        self._model = model
        self._temperature = float(temperature)
        self._max_chars = max(80, int(max_chars))
        self._use_llm = bool(use_llm)

    def narrate(
        self,
        *,
        goal: Goal,
        kb: WorldState,
        statuses: Mapping[str, ToolStatus],
        last_step: Optional[StepRecord],
    ) -> str:
        """Return a bounded single-line evidence note (best-effort)."""
        fallback = self._fallback(goal=goal, kb=kb, statuses=statuses, last_step=last_step)
        if not self._use_llm:
            return fallback

        messages = [
            {
                "role": "system",
                "content": (
                    "You summarize campaign evidence in one Korean sentence. "
                    "No instructions, no tool advice, no policy text. "
                    "Output only concise evidence narration."
                ),
            },
            {
                "role": "user",
                "content": self._evidence_context(
                    goal=goal,
                    kb=kb,
                    statuses=statuses,
                    last_step=last_step,
                ),
            },
        ]
        res = llm.completion(
            model=self._model,
            messages=messages,
            tool_choice="none",
            temperature=self._temperature,
        )
        match res:
            case Ok(resp):
                msg = llm.make_assistant_message(resp)
                text = msg.content if msg and msg.content else ""
                clean = self._sanitize(text)
                return clean or fallback
            case _:
                return fallback

    def _fallback(
        self,
        *,
        goal: Goal,
        kb: WorldState,
        statuses: Mapping[str, ToolStatus],
        last_step: Optional[StepRecord],
    ) -> str:
        runnable = sum(1 for st in statuses.values() if st.runnable)
        blocked = sum(1 for st in statuses.values() if st.effect_eval.kind.value == "Blocked")
        mode = "unknown" if kb.scalars.mode is None else str(kb.scalars.mode)
        signing = kb.scalars.signing.value
        if last_step is None:
            text = (
                f"목표 {goal.type} 기준으로 현재 runnable={runnable}, blocked_eval={blocked}, "
                f"mode={mode}, signing={signing} 상태입니다."
            )
        else:
            text = (
                f"{last_step.tool_id} 실행 결과는 {last_step.verdict}"
                f"{f'({last_step.blocked_by})' if last_step.blocked_by else ''}이며, "
                f"현재 mode={mode}, signing={signing}, runnable={runnable}입니다."
            )
        return self._sanitize(text)

    def _evidence_context(
        self,
        *,
        goal: Goal,
        kb: WorldState,
        statuses: Mapping[str, ToolStatus],
        last_step: Optional[StepRecord],
    ) -> str:
        runnable = [tid for tid, st in statuses.items() if st.runnable][:6]
        blocked = [
            f"{tid}:{st.effect_eval.blocked_by.value}"
            for tid, st in statuses.items()
            if st.effect_eval.blocked_by is not None
        ][:6]
        reach = sorted(
            f.arg for f in kb.facts if f.pred.value == "reach" and f.arg is not None
        )[:10]
        artifacts = sorted(a.value for a in kb.artifacts)[:10]
        step_txt = (
            "none"
            if last_step is None
            else f"tool={last_step.tool_id}, verdict={last_step.verdict}, blocked_by={last_step.blocked_by}"
        )
        mode = "unknown" if kb.scalars.mode is None else str(kb.scalars.mode)
        return (
            f"goal={goal.type} target={goal.target}\n"
            f"last_step={step_txt}\n"
            f"kb: signing={kb.scalars.signing.value}, mode={mode}, c2={kb.scalars.c2.value}\n"
            f"reach={reach}\n"
            f"artifacts={artifacts}\n"
            f"runnable={runnable}\n"
            f"blocked_effect_eval={blocked}\n"
            "한 줄 증거요약만 출력."
        )

    def _sanitize(self, text: str) -> str:
        s = _WS_RE.sub(" ", (text or "")).strip()
        if not s:
            return ""
        if len(s) > self._max_chars:
            return s[: self._max_chars - 1].rstrip() + "…"
        return s


__all__ = ["EvidenceAgent"]
