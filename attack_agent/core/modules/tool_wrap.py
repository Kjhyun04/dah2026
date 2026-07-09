"""core.modules.tool_wrap — 이질 내부함수(safe-exec 러너)를 통일 tool로 (06 §6 · REF §1).

아카이브 crs/common/utils.py tool_wrap 규격 계승:
  Callable[P, Coro[Result[R]]]  ->  ToolT[P, R]
  Ok  -> ToolSuccess / Err·CRSError -> ToolError.
  pre_hooks(실행 전 차단, 11 §2 Legality 하드게이트) · post_hooks(결과 가공, F5 redact).

self-contained: 아카이브의 result 패키지 대신 최소 Ok/Err 구현(의존 최소화).
작성 2026-07-05.
"""

from __future__ import annotations

import functools
from typing import Any, Awaitable, Callable, Coroutine, Optional, Sequence, Union

from core.common.types import AgentAction, ToolError, ToolResult, ToolSuccess

# ═══════════════════════════════════════════════════════════════════════════
# 1. Result / CRSError — 아카이브 규격 최소 구현 (result 패키지 대체)
# ═══════════════════════════════════════════════════════════════════════════


class CRSError(Exception):
    """처리된 모든 실패의 공통 예외 (core.py CRSError 미러)."""

    def __init__(self, error: str, extra: Optional[dict[str, Any]] = None) -> None:
        super().__init__(error)
        self.error = error
        self.extra = extra

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.error!r}, extra={self.extra})"


class Ok[T]:
    """성공 결과 컨테이너 (result.Ok 미러)."""

    __slots__ = ("value",)
    __match_args__ = ("value",)

    def __init__(self, value: T) -> None:
        self.value = value


class Err:
    """실패 결과 컨테이너 (result.Err 미러). error = CRSError."""

    __slots__ = ("error",)
    __match_args__ = ("error",)

    def __init__(self, error: CRSError) -> None:
        self.error = error


type Result[T] = Union[Ok[T], Err]
type Coro[R] = Coroutine[Any, Any, R]

# hook 타입 (utils.py 미러)
type PreHook = Callable[..., Awaitable[Optional[ToolResult[Any]]]]
type PostHook = Callable[..., Awaitable[ToolResult[Any]]]


# ═══════════════════════════════════════════════════════════════════════════
# 2. 어댑터 (utils.py to_tool_result / pre_hook / post_hook / tool_wrap 미러)
# ═══════════════════════════════════════════════════════════════════════════


def to_tool_result[T](result: Result[T]) -> ToolResult[T]:
    """Result[T] -> ToolResult[T] (utils.py 미러). Ok->ToolSuccess / Err->ToolError."""
    match result:
        case Ok(res):
            return ToolSuccess[T](res)
        case Err(e):
            return ToolError(e.error, extra=e.extra, action=None)
    raise TypeError(f"expected Ok|Err, got {type(result)!r}")


def _apply_pre_hook(fn: Callable[..., Coro[ToolResult[Any]]], hook: PreHook):
    """실행 전 hook. ToolResult 반환 시 즉시 반환하고 tool 미실행 (utils.py)."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> ToolResult[Any]:
        if hook_res := await hook(*args, **kwargs):
            return hook_res
        return await fn(*args, **kwargs)

    return wrapper


def _apply_post_hook(fn: Callable[..., Coro[ToolResult[Any]]], hook: PostHook):
    """실행 후 hook. 결과 검사·가공 (utils.py). redact 2차·로깅 등."""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> ToolResult[Any]:
        return await hook(await fn(*args, **kwargs), *args, **kwargs)

    return wrapper


def tool_wrap[T](
    fn: Callable[..., Coro[Result[T]]],
    pre_hooks: Sequence[PreHook] = (),
    post_hooks: Sequence[PostHook] = (),
) -> Callable[..., Coro[ToolResult[T]]]:
    """Result 코루틴 함수를 tool로 래핑 (utils.py tool_wrap 미러).

    Ok->ToolSuccess / Err·CRSError->ToolError. pre_hooks(차단)·post_hooks(가공) 적용.
    """

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> ToolResult[T]:
        try:
            return to_tool_result(await fn(*args, **kwargs))
        except CRSError as e:
            return ToolError(e.error, extra=e.extra, action=None)

    wrapped: Callable[..., Coro[ToolResult[T]]] = wrapper
    for h in pre_hooks:
        wrapped = _apply_pre_hook(wrapped, h)
    for h in post_hooks:
        wrapped = _apply_post_hook(wrapped, h)
    return wrapped


__all__ = [
    "CRSError",
    "Ok",
    "Err",
    "Result",
    "to_tool_result",
    "tool_wrap",
    "AgentAction",
]
