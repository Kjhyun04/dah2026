"""Clock 프로토콜 (PA-7) — 주입식. 노드는 clock.now()/clock.sleep() 만 호출한다;
노드 내 직접 time.* 호출은 AST 로 금지된다(verify_routing). VirtualClock 은
결정론 replay 를 위해 JSONL ts 를 읽는다.
"""
from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...


class RealClock:
    """Production clock. 코어에서 time.* 가 호출되는 유일한 곳."""
    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class VirtualClock:
    """Replay clock: JSONL ts 스트림에서 전진한다(결정론)."""
    def __init__(self, ts_stream: list[float] | None = None, start: float = 0.0):
        self._stream = list(ts_stream or [])
        self._i = 0
        self._t = start

    def now(self) -> float:
        if self._i < len(self._stream):
            self._t = self._stream[self._i]
            self._i += 1
        return self._t

    def sleep(self, seconds: float) -> None:
        self._t += seconds
