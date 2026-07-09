"""DefResult[T] / def_tool_wrap — 통합 도구 반환 봉투(H-A, Robo Duck 계승).

계약(GATE0): 모든 도구는 DefResult 를 반환한다(예외 누출 없음). 래퍼의
``except`` 는 CRSError 만 잡는다 — 따라서 모든 도구 본문은 CRSError 를 raise 하거나
(ValueError/TimeoutError 는 CRSError 로 감싼다) 그렇지 않으면 예외가 누출된다. def_tool_wrap 은
pre_hooks(예: legality)를 먼저, 그다음 본문, 그다음 post_hooks(예: world_update)를 실행한다.

이것은 형식(form) 코어다. 실제 subprocess 부작용은
``mdg.safe_exec.backend.Backend.run`` 뒤에 존재한다(불변식2.) — 도구는 여기서 프로세스를 생성하지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Generic, Optional, TypeVar, Union

T = TypeVar("T")


class CRSError(Exception):
    """도구가 raise 할 수 있는 유일한 예외 타입. def_tool_wrap 은 이것만 잡는다."""


@dataclass
class DefOk(Generic[T]):
    value: T
    ok: bool = field(default=True, init=False)


@dataclass
class DefErr:
    message: str
    kind: str = "CRSError"
    ok: bool = field(default=False, init=False)


DefResult = Union[DefOk[T], DefErr]

PreHook = Callable[..., None]      # veto 하려면 CRSError 를 raise(예: legality)
PostHook = Callable[[object], object]


def def_tool_wrap(
    fn: Callable[..., T],
    pre_hooks: Optional[list[PreHook]] = None,
    post_hooks: Optional[list[PostHook]] = None,
) -> Callable[..., DefResult[T]]:
    """도구 본문을 감싼다: Ok -> DefOk / CRSError -> DefErr. 예외는 절대 누출되지 않는다.

    주의(H-A verify-fix): CRSError 만 잡힌다. 맨 ValueError/TimeoutError 는
    누출된다 — 모든 도구 본문은 CRSError 를 raise 해야 한다. verify_tools 는 registry
    완전성을 강제한다; CRSError 규율은 리뷰 + 이 시그니처로 강제된다.
    """
    pre = pre_hooks or []
    post = post_hooks or []

    def wrapped(*args, **kwargs) -> DefResult[T]:
        try:
            for hook in pre:
                hook(*args, **kwargs)          # veto 하려면 CRSError 를 raise 할 수 있음
            out: object = fn(*args, **kwargs)
            for hook in post:
                out = hook(out)
            return DefOk(out)                  # type: ignore[arg-type]
        except CRSError as exc:
            return DefErr(message=str(exc), kind="CRSError")

    wrapped.__name__ = getattr(fn, "__name__", "tool")
    return wrapped
