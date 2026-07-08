"""Clock protocol (PA-7) — injected. Nodes call clock.now()/clock.sleep() only;
direct time.* calls in nodes are AST-forbidden (verify_routing). VirtualClock reads
JSONL ts for deterministic replay.
"""
from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...


class RealClock:
    """Production clock. The ONLY place time.* is called for the core."""
    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class VirtualClock:
    """Replay clock: advances from a JSONL ts stream (deterministic)."""
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
