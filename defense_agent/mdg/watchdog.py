"""Watchdog (G7) — independent liveness monitor for the out-of-graph collectors.

A standalone daemon thread that watches each registered collector's heartbeat. If a
collector goes silent past ``max_silence_s`` it is marked dead and:
  - optionally restarted (a fresh thread instance via a supplied factory), and
  - a signed ``sensor_loss`` envelope is enqueued so the pipeline can SEE the gap.
    (Wiring this into compute_impact's present-set/all-stale hold is a follow-up per
    the P0 panel-3 residual note; the watchdog is the missing liveness SOURCE.)

The watchdog is deliberately minimal and core-independent: it imports only the ingest
envelope helpers (to sign a sensor_loss signal that passes the PS-2 gate) and the
Clock. It never touches MDGState or the graph directly.
"""
from __future__ import annotations

import secrets
import threading
from typing import Callable, Optional

from .collector.ingest import Keyring, SensorEnvelope, compute_hmac
from .core.clock import Clock, RealClock


class Watchdog(threading.Thread):
    def __init__(self, collectors: list, *, clock: Optional[Clock] = None,
                 inbox=None, keyring: Optional[Keyring] = None, kid: str = "",
                 max_silence_s: float = 10.0, interval_s: float = 2.0,
                 restart: bool = False,
                 restart_factory: Optional[Callable[[object], object]] = None):
        super().__init__(daemon=True, name="Watchdog")
        self.collectors = list(collectors)
        self.clock: Clock = clock or RealClock()
        self.inbox = inbox
        self.keyring = keyring
        self.kid = kid
        self.max_silence_s = max_silence_s
        self.interval_s = interval_s
        self.restart = restart
        self.restart_factory = restart_factory
        self._stop = threading.Event()
        self._seq = 0
        self.dead: set[str] = set()

    # -- liveness check (directly testable) ------------------------------- #
    def check_once(self) -> dict[str, bool]:
        """Return {collector_name: alive}. Emits sensor_loss + optional restart for
        collectors that crossed the silence threshold (edge-triggered)."""
        now = self.clock.now()
        status: dict[str, bool] = {}
        for i, c in enumerate(self.collectors):
            name = getattr(c, "name", getattr(c, "source_id", f"c{i}"))
            hb = c.heartbeat()
            # hb==0 means "never reported yet"; only flag after we've had a chance.
            silent = hb > 0 and (now - hb) > self.max_silence_s
            alive = not silent
            status[name] = alive
            if silent and name not in self.dead:
                self.dead.add(name)
                self._emit_sensor_loss(getattr(c, "source_id", name))
                if self.restart and self.restart_factory is not None:
                    self._restart(i, c)
            elif alive and name in self.dead:
                self.dead.discard(name)          # recovered
        return status

    def _restart(self, idx: int, dead_collector) -> None:
        try:
            fresh = self.restart_factory(dead_collector)  # type: ignore[misc]
            if fresh is not None:
                self.collectors[idx] = fresh
                fresh.start()
        except Exception:
            pass

    def _emit_sensor_loss(self, source_id: str) -> None:
        if self.inbox is None or self.keyring is None:
            return
        self._seq += 1
        env = SensorEnvelope(
            payload={"metric": "sensor_loss", "value": source_id, "band": "normal",
                     "channel": "watchdog", "confidence": 1.0},
            source_id="watchdog", kid=self.kid, seq=self._seq,
            ts=self.clock.now(), nonce=secrets.token_hex(8),
        )
        key = self.keyring.get(self.kid)
        if key is not None:
            env.hmac = compute_hmac(env, key)
        try:
            self.inbox.put_nowait(env)
        except Exception:
            pass

    # -- lifecycle -------------------------------------------------------- #
    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.check_once()
            except Exception:
                pass
            self._stop.wait(self.interval_s)

    def stop(self) -> None:
        self._stop.set()
