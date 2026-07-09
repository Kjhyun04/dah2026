"""DefResult[T] / def_tool_wrap — unified tool return envelope (H-A, Robo Duck 계승).

Contract (GATE0): every tool returns DefResult (no exception leak). The wrapper's
``except`` catches CRSError ONLY — so every tool body must raise CRSError (wrap
ValueError/TimeoutError into CRSError) or the exception leaks. def_tool_wrap runs
pre_hooks (e.g. legality) then the body then post_hooks (e.g. world_update).

This is the form core. Actual subprocess side effects live behind
``mdg.safe_exec.backend.Backend.run`` (불변식2.) — tools never spawn processes here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Generic, Optional, TypeVar, Union

T = TypeVar("T")


class CRSError(Exception):
    """The ONLY exception type tools may raise. def_tool_wrap catches this only."""


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

PreHook = Callable[..., None]      # raises CRSError to veto (e.g. legality)
PostHook = Callable[[object], object]


def def_tool_wrap(
    fn: Callable[..., T],
    pre_hooks: Optional[list[PreHook]] = None,
    post_hooks: Optional[list[PostHook]] = None,
) -> Callable[..., DefResult[T]]:
    """Wrap a tool body: Ok -> DefOk / CRSError -> DefErr. Exceptions never leak.

    NOTE (H-A verify-fix): only CRSError is caught. A bare ValueError/TimeoutError
    would leak — every tool body must raise CRSError. verify_tools enforces registry
    completeness; the CRSError discipline is enforced by review + this signature.
    """
    pre = pre_hooks or []
    post = post_hooks or []

    def wrapped(*args, **kwargs) -> DefResult[T]:
        try:
            for hook in pre:
                hook(*args, **kwargs)          # may raise CRSError to veto
            out: object = fn(*args, **kwargs)
            for hook in post:
                out = hook(out)
            return DefOk(out)                  # type: ignore[arg-type]
        except CRSError as exc:
            return DefErr(message=str(exc), kind="CRSError")

    wrapped.__name__ = getattr(fn, "__name__", "tool")
    return wrapped
