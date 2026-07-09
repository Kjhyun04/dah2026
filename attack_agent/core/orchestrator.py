"""core.orchestrator — P3 공격 계획 오케스트레이터 (비동기 ReAct 스켈레톤).

과제 §12-3. FSM: RECON->SELECT->EXECUTE->INFER->(goal?END:PIVOT).
  매 턴: (1) scoped tool 에 legality -> tool_status 렌더(default.yaml user),
         (2) LLM 이 **닫힌 화이트리스트**에서 tool 1개 선택(replay 또는 live),
         (3) tool_wrap 실행 await (pre_hook=legality 하드게이트, post_hook=kb_update/redact),
         (4) kb_update 반영, (5) goal_reached 판정.

종료는 **드라이버(시스템)의 결정론**(goal_reached ∨ max_steps ∨ 교착 하드캡).
  LLM 은 terminate 하지 않으며 스스로 멈추지 않는다(11 §3·prompt §5·DESIGN FSM).

grep0 불변식(06 P2·17 §3): 이 모듈은 **감독/ground-truth/truth** 산출을 절대
  import·참조하지 않는다. 공격자-가시 result payload(Recon/Collect/Inject)만 다룬다.

비동기(18 A2): 순차 await(병렬 gather 없음) — AgentAction 순서 결정론화.
  LLM 호출(llm.completion)은 동기 래퍼이며 루프에서 직접 호출(단일 스레드).

레시피 금지: 순서/조합 처방을 코드·프롬프트에 넣지 않는다.
  선택은 legality(missing<->produces)에서 창발, 폴백도 상태 기반 결정표.
작성 2026-07-05.
"""

from __future__ import annotations

import contextlib
import json
import sys
from typing import Any, Awaitable, Callable, Optional, Protocol

from core.common import llm
from core.common.prompt_context import (
    AgentPrompt,
    build_prompt_context,
    load_agent_prompt,
    render,
    scoped_tool_ids,
)
from core.common.results import CampaignResult, StepRecord
from core.common.types import (
    LLMToolCall,
    Message,
    ParamSpec,
    ToolCall,
    ToolError,
    ToolId,
    ToolSpec,
    ToolSuccess,
)
from core.modules.kb import (
    EffectEvalKind,
    Goal,
    ToolStatus,
    WorldState,
    goal_reached,
    kb_update,
    legality,
)
from core.modules.registry import get_spec
from core.modules.safeexec import Backend, Vault, make_runner_factory
from core.modules.tool_wrap import CRSError, Err, Ok, Result, tool_wrap

# Windows 콘솔(cp949) 한글 출력 깨짐 방지 (과제 지침).
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass


# 실행기 러너 타입: params(dict) -> Result[payload] (executor.run 을 감싼 결정론 러너).
type Runner = Callable[..., Awaitable[Result[Any]]]
# 러너 팩토리: spec -> runner. 미주입 시 stub(미배선).
type RunnerFactory = Callable[[ToolSpec], Runner]
# replay 훅: (step) -> mock_response dict | None (None=결정론 폴백/ live).
type ReplayHook = Callable[..., Optional[dict[str, Any]]]


class Observer(Protocol):
    """Optional passive observer hook (best-effort, non-load-bearing)."""

    async def sample_notes(self) -> list[str]: ...


class Evidence(Protocol):
    """Optional narrate/correlate hook (non-load-bearing)."""

    def narrate(
        self,
        *,
        goal: Goal,
        kb: WorldState,
        statuses: dict[str, ToolStatus],
        last_step: Optional[StepRecord],
    ) -> str: ...


_ADAPT_VERDICTS = frozenset({"BLOCKED", "ERROR", "TIMEOUT"})


def _unwired_runner(spec: ToolSpec) -> Runner:
    """기본 러너(executor.run 미배선, P3 스코프 밖). 항상 Err — 안전 no-op."""

    async def run(**_params: Any) -> Result[Any]:
        return Err(CRSError(f"executor 미배선: {spec.id}", extra={"tool": spec.id}))

    return run


# ═══════════════════════════════════════════════════════════════════════════
# 파라미터 검증 (닫힘 강제: ParamSpec.type/choices/required)
# ═══════════════════════════════════════════════════════════════════════════


def _validate_params(spec: ToolSpec, params: dict[str, Any]) -> Optional[str]:
    """ParamSpec 위반 시 사유 문자열, 정상 시 None. 허용값 밖 인자 거부(06 닫힘)."""
    for key, pspec in spec.params.items():
        if key not in params:
            if pspec.required and pspec.default is None:
                return f"missing required param '{key}'"
            continue
        val = params[key]
        if not _type_ok(pspec, val):
            return f"param '{key}' type != {pspec.type}"
        if pspec.choices is not None and val not in pspec.choices:
            return f"param '{key}'={val!r} not in choices {pspec.choices}"
    return None


def _type_ok(pspec: ParamSpec, val: Any) -> bool:
    if pspec.type == "int":
        return isinstance(val, int) and not isinstance(val, bool)
    if pspec.type == "bool":
        return isinstance(val, bool)
    return isinstance(val, str)


# ═══════════════════════════════════════════════════════════════════════════
# AttackOrchestrator — 공격 두뇌(LLM 1곳). 종료는 드라이버 결정론.
# ═══════════════════════════════════════════════════════════════════════════


class AttackOrchestrator:
    """닫힌 행동공간 위 ReAct 루프. return_type = CampaignResult(드라이버 조립).

    ToolRequiredAgent 의 '합성 terminate'는 쓰지 않는다 — 종료는 goal_reached/카운터.
    """

    def __init__(
        self,
        *,
        goal: Goal,
        kb: WorldState,
        model: str = "claude-sonnet-4",
        runner_factory: Optional[RunnerFactory] = None,
        backend: Optional[Backend] = None,
        vault: Optional[Vault] = None,
        timeout_s: int = 30,
        replay: Optional[ReplayHook] = None,
        prompt: Optional[AgentPrompt] = None,
        max_steps: int = 30,
        max_pivots: int = 8,
        temperature: float = llm.DEFAULT_TEMP,
        observer: Optional[Observer] = None,
        evidence: Optional[Evidence] = None,
        auto_seed_recon: bool = False,
    ) -> None:
        self.goal = goal
        self.kb = kb
        self.model = model
        self.replay = replay
        self.max_steps = max_steps
        self.max_pivots = max_pivots      # 교착 하드캡(무진전 스텝 상한)
        self.temperature = temperature

        # 닫힌 tool 집합(REGISTRY 22 ∩ goal.scope). tool_status·_tools 동일 필터.
        self._ids: list[ToolId] = scoped_tool_ids(goal)

        # 러너 팩토리(executor.run 주입점) 선택(하위호환 3단계):
        # 1. runner_factory 명시 주입 -> 그대로 사용(replay/커스텀).
        # 2. backend 주입 -> safeexec.make_runner_factory 로 real 실행엔진 배선.
        # 3. 둘 다 없음 -> _unwired_runner(항상 Err, 안전 no-op) 유지.
        if runner_factory is not None:
            rf: RunnerFactory = runner_factory
        elif backend is not None:
            rf = make_runner_factory(
                backend=backend, vault=vault, timeout_s=timeout_s
            )
        else:
            rf = _unwired_runner
        self._rf: RunnerFactory = rf  # recon baseline 시드가 동일 팩토리를 재사용(배선 일관)
        self._observer = observer
        self._last_obs_note: Optional[str] = None
        self._evidence = evidence
        self._evidence_notes: list[str] = []
        self._auto_seed_recon = auto_seed_recon
        self._backend = backend  # teardown 훅용(종료계약 자원회수)
        # _tools = {id: tool_wrap(runner, pre=[legality 게이트], post=[kb_update, redact])}
        self._tools: dict[str, Runner] = {
            tid: tool_wrap(
                rf(get_spec(tid)),
                pre_hooks=[self._make_legality_pre(get_spec(tid))],
                post_hooks=[self._make_kb_post(), self._make_redact_post()],
            )
            for tid in self._ids
        }

        self.prompt: AgentPrompt = prompt or load_agent_prompt("AttackOrchestrator")
        self.msgs: list[Message] = [Message(role="system", content=self.prompt.system)]
        self.steps: list[StepRecord] = []
        self._step = 0

    # ── hook 어댑터 (tool_wrap PreHook/PostHook 시그니처 정합) ─────────────
    def _make_legality_pre(self, spec: ToolSpec):
        """legality 하드게이트 pre_hook. runnable=False -> ToolError(미실행)."""

        async def pre(*_a: Any, **_k: Any) -> Optional[ToolError]:
            st = legality(spec, self.kb)
            if not st.runnable:
                return ToolError(
                    f"legality gate: {spec.id} not runnable",
                    extra={"missing": [m.detail for m in st.missing]},
                )
            return None

        return pre

    def _make_kb_post(self):
        """kb_update post_hook. 성공 payload 로 KB in-place 갱신(가드 내장)."""

        async def post(res: Any, *_a: Any, **_k: Any) -> Any:
            if isinstance(res, ToolSuccess):
                kb_update(self.kb, res.result)
            return res

        return post

    def _make_redact_post(self):
        """redact post_hook(F5 2차). CollectResult.values 마스킹 보장 — 비밀 로깅 금지."""

        async def post(res: Any, *_a: Any, **_k: Any) -> Any:
            if isinstance(res, ToolSuccess):
                payload = res.result
                if getattr(payload, "values", None) and hasattr(payload, "redacted"):
                    payload.redacted = True
            return res

        return post

    # ── tool_status 계산 (동일 닫힌 집합) ────────────────────────────────
    def _statuses(self) -> dict[str, ToolStatus]:
        return {tid: legality(get_spec(tid), self.kb) for tid in self._ids}

    # ── live LLM 용 최소 tool 스키마(OpenAI function) ─────────────────────
    def _tools_api(self) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = []
        for tid in self._ids:
            spec = get_spec(tid)
            props: dict[str, Any] = {}
            required: list[str] = []
            for key, pspec in spec.params.items():
                jtype = {"int": "integer", "str": "string", "bool": "boolean"}[pspec.type]
                sch: dict[str, Any] = {"type": jtype}
                if pspec.choices is not None:
                    sch["enum"] = pspec.choices
                if pspec.desc:
                    sch["description"] = pspec.desc
                props[key] = sch
                if pspec.required and pspec.default is None:
                    required.append(key)
            summary = ""
            if tid in self.prompt.tools:
                summary = self.prompt.tools[tid].get("summary", "")
            schemas.append(
                {
                    "type": "function",
                    "function": {
                        "name": tid,
                        "description": summary,
                        "parameters": {
                            "type": "object",
                            "properties": props,
                            "required": required,
                        },
                    },
                }
            )
        return schemas

    # ── SELECT: LLM 이 닫힌 집합에서 tool 1개 선택 ────────────────────────
    def _select(self, statuses: dict[str, ToolStatus]) -> Optional[LLMToolCall]:
        """ephemeral user(tool_status) 렌더 -> completion -> 첫 tool_call 1개.

        직전 verdict 가 BLOCKED/ERROR/TIMEOUT 이면 adapt_user 프롬프트로 피벗한다.
        렌더 실패/LLM 장애 시 **빈 프롬프트 호출 금지** -> 결정론 폴백표로 직행.
        """
        # (1) tool_status 스냅샷 user 메시지 렌더(StrictUndefined). 실패=폴백.
        try:
            ctx = build_prompt_context(self.goal, self.kb, statuses)
            use_adapt = self._should_adapt()
            tmpl = self.prompt.adapt_user if use_adapt and self.prompt.adapt_user else self.prompt.user
            user_text = render(tmpl, ctx)
            if use_adapt:
                user_text = f"{user_text}\n\n{self._adapt_hint_block(statuses)}"
        except Exception:
            return self._fallback_select(statuses)
        self.msgs.append(Message(role="user", content=user_text))

        # (2) LLM 호출(replay 우선 -> 오프라인 결정론).
        mock = self.replay(self._step, statuses) if self.replay is not None else None
        res = llm.completion(
            model=self.model,
            messages=[m.model_dump() for m in self.msgs],
            tools=self._tools_api(),
            tool_choice="required",
            temperature=self.temperature,
            mock_response=mock,
        )
        match res:
            case Ok(resp):
                assistant = llm.make_assistant_message(resp)
                if assistant is not None:
                    self.msgs.append(assistant)
                tc = llm.first_tool_call(resp)  # 턴당 tool 1개
                return tc if tc is not None else self._fallback_select(statuses)
            case Err(_):
                # LLM 장애 -> 결정론 폴백(빈/오류 프롬프트로 재호출하지 않음).
                return self._fallback_select(statuses)
        return self._fallback_select(statuses)

    def _should_adapt(self) -> bool:
        if not self.steps:
            return False
        return self.steps[-1].verdict in _ADAPT_VERDICTS

    def _adapt_hint_block(self, statuses: dict[str, ToolStatus]) -> str:
        """Attach last-failure context + enabler candidates for ADAPT prompting."""
        if not self.steps:
            return "# adapt context\n- none"
        last = self.steps[-1]
        cands = self._adapt_candidates(statuses, exclude=last.tool_id)
        cand_txt = ", ".join(cands) if cands else "none"
        return (
            "# adapt context\n"
            f"- last_tool: {last.tool_id}\n"
            f"- last_verdict: {last.verdict}\n"
            f"- last_blocked_by: {last.blocked_by}\n"
            f"- enabler_candidates(runnable_nonblocked): {cand_txt}"
        )

    def _adapt_candidates(
        self, statuses: dict[str, ToolStatus], *, exclude: Optional[str] = None, limit: int = 8
    ) -> list[str]:
        out: list[str] = []
        for tid, st in statuses.items():
            if exclude and tid == exclude:
                continue
            if not st.runnable:
                continue
            if st.effect_eval.kind == EffectEvalKind.BLOCKED:
                continue
            out.append(tid)
            if len(out) >= limit:
                break
        return out

    def _fallback_select(self, statuses: dict[str, ToolStatus]) -> Optional[LLMToolCall]:
        """결정론 폴백표(레시피 아님, 상태 기반): runnable ∧ 非Blocked tool 1개.

        목표부합(SetMode/Disrupt/SetFlag/Produce) 우선, 없으면 runnable recon.
        아무 것도 없으면 None -> 드라이버가 교착으로 종료.
        """
        blocked = {EffectEvalKind.BLOCKED}
        # ADAPT 경로: 직전 실패/차단이면 같은 tool 반복을 피하고 enabler 후보를 우선.
        if self._should_adapt():
            last_tid = self.steps[-1].tool_id if self.steps else None
            for tid, st in statuses.items():
                if last_tid and tid == last_tid:
                    continue
                if st.runnable and st.effect_eval.kind not in blocked:
                    spec = get_spec(tid)
                    params = self._default_params(spec)
                    return self._synthetic_call(tid, params)
        # 1순위: runnable + 상태변경/산출 효과(Blocked 아님)
        for tid, st in statuses.items():
            if st.runnable and st.effect_eval.kind not in blocked:
                spec = get_spec(tid)
                params = self._default_params(spec)
                return self._synthetic_call(tid, params)
        return None

    @staticmethod
    def _default_params(spec: ToolSpec) -> dict[str, Any]:
        """폴백용 최소 파라미터(choices/default 첫값). 허용값만."""
        out: dict[str, Any] = {}
        for key, pspec in spec.params.items():
            if pspec.default is not None:
                out[key] = pspec.default
            elif pspec.choices:
                out[key] = pspec.choices[0]
        return out

    @staticmethod
    def _synthetic_call(tid: str, params: dict[str, Any]) -> LLMToolCall:
        from core.common.types import ToolCallFunction

        return LLMToolCall(
            id=f"fallback_{tid}",
            function=ToolCallFunction(name=tid, arguments=json.dumps(params)),
        )

    # ── ACT: wire tool_call -> 닫힌 ToolCall 검증 -> tool_wrap 실행 ──────────
    async def _handle_tool_call(self, tc: LLMToolCall) -> tuple[str, Optional[str]]:
        """LLMToolCall -> 검증 -> 실행. (verdict, blocked_by) 반환 + role='tool' 관찰 누적.

        닫힘 3중: name∈ToolId(get_spec KeyError) -> params∈ParamSpec -> legality pre_hook.
        """
        name = tc.function.name
        # (1) arguments JSON 파싱
        try:
            params: dict[str, Any] = json.loads(tc.function.arguments or "{}")
            if not isinstance(params, dict):
                raise ValueError("arguments not an object")
        except Exception:
            self._observe(tc.id, "ERROR", "ERROR: tool arguments not valid JSON")
            return "ERROR", None

        # (2) 닫힌 화이트리스트: name ∈ ToolId(=REGISTRY 키) 이고 scope 안
        if name not in self._tools:
            avail = ",".join(self._ids)
            self._observe(tc.id, "ERROR", f"ERROR: {name} NOT DEFINED. Available: {avail}")
            return "ERROR", None
        spec = get_spec(name)

        # (3) params 검증(허용값 밖 거부) — 닫힌 ToolCall 정규화
        if (why := _validate_params(spec, params)) is not None:
            self._observe(tc.id, "ERROR", f"ERROR: {why}")
            return "ERROR", None
        _closed: ToolCall = ToolCall(id=name, params=params)  # 닫힘 검증(id∈ToolId)

        # (4) 실행(tool_wrap: pre=legality 하드게이트, post=kb_update/redact)
        res = await self._tools[name](**_closed.params)

        # (5) 관찰(role='tool') 누적 + verdict 도출
        if isinstance(res, ToolSuccess):
            payload = res.result
            # exec_meta.killed=True(하드타임아웃 강제종료) -> TIMEOUT(누수감시 신호 반영).
            #   보수판정: killed payload 는 accepted/effect 가 이미 0(safeexec.parse_output).
            if getattr(payload, "killed", False):
                self._observe(tc.id, name, _safe_dump(payload))
                return "TIMEOUT", None
            blocked_by = getattr(payload, "blocked_by", None)
            verdict = "BLOCKED" if blocked_by else "OK"
            self._observe(tc.id, name, _safe_dump(payload))
            return verdict, blocked_by
        # ToolError (legality 반려·실행 오류 등)
        self._observe(tc.id, name, f"ERROR: {res.error}")
        return "ERROR", None

    def _observe(self, call_id: str, name: str, content: str) -> None:
        """role='tool' 관찰 메시지 누적(tool_call_id 매칭). 데이터=비신뢰."""
        self.msgs.append(
            Message(role="tool", tool_call_id=call_id, name=name, content=content)
        )

    async def _poll_observer(self) -> None:
        """Pull passive observation notes and append as bounded context lines."""
        if self._observer is None:
            return
        with contextlib.suppress(Exception):
            notes = await self._observer.sample_notes()
            if not notes:
                return
            # Keep deterministic summaries only; never pass through raw payload bytes.
            joined = " | ".join(str(n) for n in notes[:4])
            if joined == self._last_obs_note:
                return
            self._last_obs_note = joined
            self.msgs.append(Message(role="user", content=f"[observer] {joined}"))

    def _append_evidence(self, step: StepRecord) -> None:
        """Collect non-load-bearing evidence narration for operator reporting only."""
        if self._evidence is None:
            return
        with contextlib.suppress(Exception):
            note = self._evidence.narrate(
                goal=self.goal,
                kb=self.kb,
                statuses=self._statuses(),
                last_step=step,
            ).strip()
            if note:
                self._evidence_notes.append(note)

    # ── init 자동 baseline 정찰 시드 (12 §5, 선택) ───────────────────────
    async def seed_recon(self) -> None:
        """LLM 계획 전 KB 시드(12 §5 init baseline). 동일 runner_factory 로 recon 러너 조립.

        recon_reach -> (net_core 도달 시) recon_session 을 실행해 reach/unauth/seid 를
        KB 에 병합(kb_update 경유). 레시피 아님(사실 세우기). 미배선/Err 러너는 조용히 skip
        (unwired 기본은 Err -> no-op). StepRecord 를 남기지 않는다(정찰=상시·비-스텝).
        """
        from core.modules.recon import build_recon_runners, run_baseline_recon

        recon_runners = build_recon_runners(self._rf)
        await run_baseline_recon(recon_runners, self.kb)

    # ── 드라이버 루프 (종료=결정론) ──────────────────────────────────────
    async def run(self) -> CampaignResult:
        """캠페인 실행. 종료: goal_reached ∨ max_steps ∨ 교착(무진전 max_pivots).

        LLM 은 종료 권한 없음 — 이 루프가 유일 종료 주체.
        """
        stalls = 0
        try:
            if self._auto_seed_recon:
                await self.seed_recon()  # init baseline: KB 시드(12 §5)
            while True:
                # 1. 결정론 종료 판정(선행)
                if goal_reached(self.kb, self.goal):
                    break
                if self._step >= self.max_steps:
                    break
                if stalls >= self.max_pivots:  # 교착 하드캡
                    break

                await self._poll_observer()  # optional passive signal (default off)
                statuses = self._statuses()
                before = self.kb.snapshot()

                tc = self._select(statuses)
                if tc is None:
                    # 가용 tool 없음 -> 교착
                    break

                verdict, blocked_by = await self._handle_tool_call(tc)
                self.steps.append(
                    StepRecord(
                        step=self._step,
                        tool_id=tc.function.name,
                        params=_str_params(tc.function.arguments),
                        verdict=verdict,
                        blocked_by=blocked_by,
                    )
                )
                self._append_evidence(self.steps[-1])
                self._step += 1

                # 2. 진전성: KB 무변화면 stall 카운트(동일상태 순환 차단)
                after = self.kb.snapshot()
                stalls = 0 if after != before else stalls + 1
        finally:
            # 종료계약(09 §1 자원회수): 캠페인 종료 시 backend teardown
            #   — 자식·소켓·임시파일·기동 사이드카 회수(orphan 0). best-effort.
            await self._teardown()

        return self._assemble()

    async def _teardown(self) -> None:
        """backend 수명 종료(자원회수). 미주입/오류는 조용히 무시(캠페인 결과 불변)."""
        if self._backend is None:
            return
        try:
            await self._backend.teardown()
        except Exception:
            pass

    # ── terminate 조립기(드라이버) ───────────────────────────────────────
    def _assemble(self) -> CampaignResult:
        """steps + kb.snapshot() + goal_reached 로 CampaignResult 조립(15 §2).

        완전분리: 감독 verdict 필드 없음. 자기 ACK 판정만.
        """
        reached = goal_reached(self.kb, self.goal)
        defenses = self._defenses_bypassed()
        wins = self._win_causes()
        return CampaignResult(
            goal_reached=reached,
            chain=list(self.steps),
            defenses_bypassed=defenses,
            win_causes=wins,
            kb_final=self.kb.snapshot(),
            evidence_notes=list(self._evidence_notes),
        )

    def _defenses_bypassed(self) -> list[str]:
        """OK 로 끝난 INJECT 인데 signing==on 이면 서명 방어 우회로 집계(표시)."""
        out: list[str] = []
        if self.kb.scalars.signing.value == "on":
            for s in self.steps:
                if s.verdict == "OK" and get_spec(s.tool_id).kind.value == "INJECT":
                    out.append("signing")
                    break
        return sorted(set(out))

    def _win_causes(self) -> list[str]:
        """성공(OK) 스텝의 spec.win_cause 집계(none 제외). 표시 전용."""
        causes: list[str] = []
        for s in self.steps:
            if s.verdict == "OK":
                wc = get_spec(s.tool_id).win_cause.value
                if wc and wc != "none":
                    causes.append(wc)
        return sorted(set(causes))


# ═══════════════════════════════════════════════════════════════════════════
# 헬퍼(직렬화·마스킹)
# ═══════════════════════════════════════════════════════════════════════════


def _safe_dump(payload: Any) -> str:
    """result payload -> JSON 문자열(관찰용). 실패 시 repr. 비밀 원값 미포함(마스킹 전제)."""
    try:
        if hasattr(payload, "model_dump"):
            return json.dumps(payload.model_dump(), ensure_ascii=False, default=str)
        return json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:
        return repr(payload)


def _str_params(arguments: str) -> dict[str, str]:
    """LLMToolCall.arguments(JSON str) -> StepRecord.params(str dict)."""
    try:
        d = json.loads(arguments or "{}")
        if isinstance(d, dict):
            return {str(k): str(v) for k, v in d.items()}
    except Exception:
        pass
    return {}


__all__ = ["AttackOrchestrator", "Runner", "RunnerFactory", "ReplayHook"]
