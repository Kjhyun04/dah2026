"""BaseCollector — out-of-graph long-lived daemon (PA-7, PS-2, PS-5).

A collector is a background thread that periodically observes ONE vantage point and
pushes signed SensorEnvelopes onto the shared ``queue.Queue`` that ``sense`` drains
non-blocking. Collectors are NOT graph nodes: the graph stays synchronous and
deterministic while observation runs asynchronously here.

Invariant boundaries honoured:
  - 불변식②: subprocess-based observation (tcpdump/ss/docker logs/nsenter) is issued
    ONLY through the injected ``Backend`` (safe-exec). Pure network polling (httpx)
    and config reads do not spawn processes and are done directly.
  - PS-2 : every envelope is HMAC-signed here (source keyring) so ``sense`` can verify
    at drain. The HMAC key lives in this process's keyring, never in State (PS-3).
  - DoS  : the output queue is bounded; on Full we drop + count (no unbounded growth).

Subclasses implement ``collect() -> list[dict]`` returning payload dicts. Returning
[] is normal (no signal this cycle) and still a SUCCESS — a quiet tick refreshes the
liveness ``heartbeat()`` so the watchdog sees a live collector. A cycle whose collect()
RAISES withholds the beat, so a persistently-erroring collector goes silent and the
watchdog (G7) marks it dead — an error is never mistaken for a healthy quiet tick.
"""
from __future__ import annotations

import queue
import secrets
import threading
from typing import Optional

from ..core.clock import Clock, RealClock
from .ingest import Keyring, SensorEnvelope, compute_hmac


class BaseCollector(threading.Thread):
    source_id: str = "base"
    domain: Optional[str] = None

    def __init__(self, out_queue: "queue.Queue", keyring: Keyring, kid: str, *,
                 backend=None, clock: Optional[Clock] = None, interval_s: float = 2.0,
                 source_id: Optional[str] = None, name: Optional[str] = None):
        super().__init__(daemon=True, name=name or self.__class__.__name__)
        self.out = out_queue
        self.keyring = keyring
        self.kid = kid
        self.backend = backend
        self.clock: Clock = clock or RealClock()
        self.interval_s = interval_s
        if source_id is not None:
            self.source_id = source_id
        self._seq = 0
        self._stop = threading.Event()
        self._last_hb = 0.0
        self.drops = 0
        self.errors = 0

    # -- to override ------------------------------------------------------- #
    def collect(self) -> list[dict]:
        raise NotImplementedError

    # -- envelope signing (PS-2) ------------------------------------------ #
    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def make_envelope(self, payload: dict) -> SensorEnvelope:
        env = SensorEnvelope(
            payload=payload, source_id=self.source_id, kid=self.kid,
            seq=self._next_seq(), ts=self.clock.now(), nonce=secrets.token_hex(8),
        )
        key = self.keyring.get(self.kid)
        if key is not None:
            env.hmac = compute_hmac(env, key)
        return env

    def push(self, env: SensorEnvelope) -> None:
        try:
            self.out.put_nowait(env)                 # async push, non-blocking
        except queue.Full:
            self.drops += 1                          # DoS cap: drop, never block/grow

    def emit(self, payload: dict) -> None:
        self.push(self.make_envelope(payload))

    # -- lifecycle --------------------------------------------------------- #
    def heartbeat(self) -> float:
        return self._last_hb

    def tick_once(self) -> int:
        """One collection cycle (directly testable without a thread). Returns the number
        of payloads emitted. Refreshes the liveness heartbeat ONLY on a cycle that finishes
        without raising: a quiet tick (collect() -> []) is a success and DOES beat, but a
        cycle whose collect() RAISES withholds the beat (the exception propagates to the
        caller — run() counts it — so the heartbeat line below is never reached), leaving a
        persistently-erroring collector stale for the watchdog (G7) to mark dead."""
        n = 0
        for payload in (self.collect() or []):
            self.emit(payload)
            n += 1
        self._last_hb = self.clock.now()             # success only; unreached if collect() raised
        return n

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick_once()
            except Exception:                        # a collector must never crash the process
                self.errors += 1
                # heartbeat deliberately NOT refreshed on error: a failed cycle must let the beat
                # go stale so the watchdog (G7) can tell a persistently-erroring collector apart
                # from a healthy quiet one (which beats via tick_once's success path).
            self._stop.wait(self.interval_s)

    def stop(self) -> None:
        self._stop.set()

    # -- helper for subprocess-observation collectors --------------------- #
    def _observe(self, argv: list[str], timeout_s: float = 8.0):
        """Route a read-only observation command through the safe-exec Backend
        (불변식②). Returns an ExecResult or None if no backend is wired."""
        if self.backend is None:
            return None
        from ..safe_exec.backend import ExecRequest
        return self.backend.run(ExecRequest(argv=argv, timeout_s=timeout_s, read_only=True))
