"""core.common.llm — 동기 litellm 래퍼 (아카이브 crs/common/llm_api.py sync-mirror).

역할(P3, 과제 §12):
  1. completion(...) — litellm 단일 호출점. **replay(고정 응답 주입, 오프라인/테스트용)** +
     **live(실 litellm 호출)** 2모드. 반환 Result[ModelResponse](Ok/Err).
  2. ModelResponse / Choice / AgentResult[T] — 아카이브 core.py 봉투 중 P0 types.py 에
     아직 없는 3종만 신규 정의(Message/LLMToolCall/AgentAction 은 types.py 재사용).
  3. 오프라인 재현용 mock 빌더(mock_tool_response) + ReplayLLM 스크립트 헬퍼.

divergence(20 §1 C1 sync 단일스레드): acompletion->litellm.completion,
  asyncio.sleep->time.sleep, PrioritySemaphore/OTEL/telemetry 전량 드롭.
  MAX_RETRIES/슬립 상한을 축소(캠페인 hang 회귀 방지).

가드(과제 §12-1):
  - **빈 프롬프트/렌더 실패 호출 금지**: messages 가 비었거나 판단근거(content/tool_calls)가
    전무하면 실호출 없이 Err 반환(빈 프롬프트로 API 태우지 않음).
  - **비밀 로깅 금지**: 이 모듈은 secret_params 원값을 로그·에러에 절대 싣지 않는다.
    (비밀 주입은 executor.run 의 vault->stdin 경로 책임 — 여기서는 프롬프트/응답만 다룸.)

thinking OFF · temperature=0.7 고정(18 A6/A7). 작성 2026-07-05.
"""

from __future__ import annotations

import sys
import time
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict

from core.common.types import LLMToolCall, Message, ToolCallFunction
from core.modules.tool_wrap import CRSError, Err, Ok, Result

# Windows 콘솔(cp949)에서 한글/유니코드 출력 깨짐 방지 (과제 지침).
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass


# ═══════════════════════════════════════════════════════════════════════════
# 0. 상수 (아카이브 llm_api 축소본 — sync hang 회귀 방지)
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_TEMP = 0.7          # 18 A6
MAX_RETRIES = 3             # 아카이브 8 -> 축소(단일 캠페인 블록 최소화)
RETRY_DELAY_S = 2           # 아카이브 EXCEPTION_DELAY 20 -> 축소
RATE_LIMIT_DELAY_S = 5      # 아카이브 15 -> 축소
MAX_SLEEP_S = 30            # 슬립 하드캡(hang 방지)

# temp 0.7 유지하는 Anthropic 계열 thinking 비활성 마커(18 A7).
_ANTHROPIC_HINTS = ("claude", "anthropic")

type ToolChoice = Literal["auto", "required", "none"]


# ═══════════════════════════════════════════════════════════════════════════
# 1. 응답 봉투 (core.py ModelResponse/Choice/AgentResult 미러 — P0 미보유 3종)
#    Message/LLMToolCall/AgentAction 은 core.common.types 재사용(재정의 금지).
# ═══════════════════════════════════════════════════════════════════════════


class Choice(BaseModel):
    """LLM 응답 선택지 (core.py Choice 미러, logprobs 드롭)."""

    model_config = ConfigDict(extra="ignore")
    message: Message
    finish_reason: Optional[str] = None


class ModelResponse(BaseModel):
    """litellm 완료 응답 봉투 (core.py 미러)."""

    model_config = ConfigDict(extra="ignore")
    choices: list[Choice] = []
    cost: float = 0.0
    usage: dict[str, Any] = {}

    def first_message(self) -> Optional[Message]:
        return self.choices[0].message if self.choices else None


class AgentResult[T](BaseModel):
    """에이전트 루프 최종 반환 (core.py AgentResult[T] 미러, PEP695)."""

    model_config = ConfigDict(extra="ignore")
    response: Optional[T] = None
    terminated: bool = False
    msgs: list[dict[str, Any]] = []


# ═══════════════════════════════════════════════════════════════════════════
# 2. replay 빌더 — 오프라인/심사 재현용 고정 응답(litellm 미호출)
# ═══════════════════════════════════════════════════════════════════════════


def mock_tool_response(
    name: str,
    arguments: str = "{}",
    *,
    call_id: str = "call_0",
    content: Optional[str] = None,
    cost: float = 0.0,
) -> dict[str, Any]:
    """단일 tool_call 을 담은 ModelResponse 형태의 dict 생성(replay 주입용).

    completion(mock_response=...) 에 넘기면 litellm 호출 없이 이 응답이 그대로 반환된다.
    arguments 는 JSON **문자열**(OpenAI wire 규약, LLMToolCall.function.arguments).
    """
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "cost": cost,
        "usage": {},
    }


class ReplayLLM:
    """녹화 스크립트 재생기(오프라인 결정론). (tool_name, arguments) 시퀀스를 순서대로 방출.

    orchestrator 는 매 스텝 `replay(step)` 을 호출해 mock_response dict 를 받는다.
    스크립트 소진 시 None -> orchestrator 결정론 폴백 경로로.
    """

    def __init__(self, script: list[tuple[str, str]]) -> None:
        # (name, arguments-json-str) 목록. 원값 비밀 미포함(프롬프트/응답만).
        self._script = list(script)

    def __call__(self, step: int, *_a: Any, **_k: Any) -> Optional[dict[str, Any]]:
        if 0 <= step < len(self._script):
            name, args = self._script[step]
            return mock_tool_response(name, args, call_id=f"call_{step}")
        return None


# ═══════════════════════════════════════════════════════════════════════════
# 3. completion — 동기 단일 호출점 (replay | live)
# ═══════════════════════════════════════════════════════════════════════════


def _prompt_is_empty(messages: list[dict[str, Any]]) -> bool:
    """빈 프롬프트 가드(과제 §12-1). 판단근거(content/tool_calls)가 전무하면 True."""
    if not messages:
        return True
    for m in messages:
        if m.get("content") or m.get("tool_calls"):
            return False
    return True


def _build_response(raw: dict[str, Any]) -> ModelResponse:
    """dict -> ModelResponse. cost 키 보정(litellm model_dump 는 cost 미포함일 수 있음)."""
    if "cost" not in raw:
        raw = {**raw, "cost": 0.0}
    return ModelResponse(**raw)


def completion(
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: Optional[list[dict[str, Any]]] = None,
    tool_choice: Optional[ToolChoice] = None,
    temperature: float = DEFAULT_TEMP,
    mock_response: Optional[dict[str, Any]] = None,
    use_caching: bool = True,
    n: int = 1,
    api_key: Optional[str] = None,
) -> Result[ModelResponse]:
    """litellm 단일 호출 래퍼(sync). Ok(ModelResponse) | Err(CRSError).

    replay: mock_response 가 주어지면 **litellm 미호출**로 그 응답을 그대로 반환
      (오프라인/심사 재현 결정론). live: 실제 litellm.completion 호출.

    가드: 빈 프롬프트면 즉시 Err(호출 안 함). 재시도/폴백은 상한 내에서만(hang 방지).
    비밀 로깅 금지: 예외 메시지에 messages 원문을 싣지 않는다.
    """
    # ── 빈 프롬프트 가드 (렌더 실패/빈 호출 차단) ──
    if _prompt_is_empty(messages):
        return Err(CRSError("empty prompt — completion 호출 거부(빈 프롬프트 가드)"))

    # ── replay(오프라인 고정 응답) ──
    if mock_response is not None:
        try:
            return Ok(_build_response(mock_response))
        except Exception as e:  # 스키마 불일치
            return Err(CRSError(f"replay mock_response 파싱 실패: {type(e).__name__}"))

    # ── live(실 litellm 호출) ──
    retries = 0
    while True:
        try:
            import litellm  # 지연 import(모듈 로드 시 네트워크/키 불요)

            kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "n": n,
            }
            if api_key:
                kwargs["api_key"] = api_key   # provider-agnostic: 운영자 단일 .env 키 명시 주입(로그 미노출)
            if tools:
                kwargs["tools"] = tools
                if tool_choice is not None:
                    kwargs["tool_choice"] = tool_choice
            # thinking OFF(temp 0.7 유지, 18 A7) — Anthropic 계열만 명시.
            if any(h in model.lower() for h in _ANTHROPIC_HINTS):
                kwargs["thinking"] = {"type": "disabled"}

            raw = litellm.completion(**kwargs)  # type: ignore[attr-defined]
            data = raw.model_dump() if hasattr(raw, "model_dump") else dict(raw)
            try:
                cost = float(litellm.completion_cost(raw, model=model))  # type: ignore[attr-defined]
            except Exception:
                cost = 0.0
            return Ok(_build_response({**data, "cost": cost}))

        except Exception as e:  # noqa: BLE001 — 광범위 폴백(상한 내)
            name = type(e).__name__
            if "RateLimit" in name and retries < MAX_RETRIES:
                retries += 1
                time.sleep(min(RATE_LIMIT_DELAY_S * retries, MAX_SLEEP_S))
                continue
            if "ContextWindow" in name:
                return Err(CRSError("context window exceeded"))
            if retries < MAX_RETRIES:
                retries += 1
                time.sleep(min(RETRY_DELAY_S * retries, MAX_SLEEP_S))
                continue
            # 비밀 로깅 금지: 예외 타입만 노출, messages/args 원문 미포함.
            return Err(CRSError(f"completion 실패({name}): max_retries={MAX_RETRIES} 초과"))


# ═══════════════════════════════════════════════════════════════════════════
# 4. wire 응답 파서 헬퍼 — ModelResponse -> 첫 tool_call(LLMToolCall)
# ═══════════════════════════════════════════════════════════════════════════


def first_tool_call(resp: ModelResponse) -> Optional[LLMToolCall]:
    """응답 assistant 메시지의 **첫 tool_call** 1개만 채택(턴당 tool 1개, 18 A3).

    다중 tool_call 이 와도 첫 1개만 반환(나머지 무시) — 결정론.
    """
    msg = resp.first_message()
    if msg is None or not msg.tool_calls:
        return None
    return msg.tool_calls[0]


def make_assistant_message(resp: ModelResponse) -> Optional[Message]:
    """응답의 assistant 메시지를 그대로 반환(msgs 누적용). 없으면 None."""
    return resp.first_message()


__all__ = [
    "Choice",
    "ModelResponse",
    "AgentResult",
    "ToolChoice",
    "mock_tool_response",
    "ReplayLLM",
    "completion",
    "first_tool_call",
    "make_assistant_message",
    "LLMToolCall",
    "Message",
    "ToolCallFunction",
    "DEFAULT_TEMP",
]
