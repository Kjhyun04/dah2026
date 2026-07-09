"""Watchdog (G7) — 그래프 밖(out-of-graph) 콜렉터를 위한 독립 liveness 모니터.

각 등록된 콜렉터의 하트비트를 감시하는 독립 데몬 스레드. 콜렉터가 ``max_silence_s`` 를 넘겨
침묵하면 dead 로 표시하고:
  - 선택적으로 재시작(공급된 factory 로 새 스레드 인스턴스 생성), 그리고
  - 서명된 ``sensor_loss`` 엔벨로프를 enqueue 해 파이프라인이 그 공백을 볼(SEE) 수 있게 한다.
    (이를 compute_impact 의 present-set/all-stale hold 로 배선하는 것은 P0 panel-3 잔여 노트에
    따른 후속 작업; watchdog 은 빠져 있던 liveness 소스(SOURCE)이다.)

watchdog 은 의도적으로 최소·코어 독립: ingest 엔벨로프 헬퍼(PS-2 게이트를 통과하는 sensor_loss
시그니처에 서명하기 위함)와 Clock 만 import 한다. MDGState 나 그래프를 직접 건드리지 않는다.
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

    # -- liveness 체크(직접 테스트 가능) ---------------------------------- #
    def check_once(self) -> dict[str, bool]:
        """{collector_name: alive} 를 반환. 침묵 임계를 넘긴 콜렉터에 대해 sensor_loss 를
        emit 하고 선택적으로 재시작한다(edge-triggered)."""
        now = self.clock.now()
        status: dict[str, bool] = {}
        for i, c in enumerate(self.collectors):
            name = getattr(c, "name", getattr(c, "source_id", f"c{i}"))
            hb = c.heartbeat()
            # hb==0 은 "아직 보고된 적 없음" 을 의미; 기회가 있었던 뒤에만 flag.
            silent = hb > 0 and (now - hb) > self.max_silence_s
            alive = not silent
            status[name] = alive
            if silent and name not in self.dead:
                self.dead.add(name)
                self._emit_sensor_loss(getattr(c, "source_id", name))
                if self.restart and self.restart_factory is not None:
                    self._restart(i, c)
            elif alive and name in self.dead:
                self.dead.discard(name)          # 복구됨
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

    # -- 생명주기(lifecycle) ---------------------------------------------- #
    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.check_once()
            except Exception:
                pass
            self._stop.wait(self.interval_s)

    def stop(self) -> None:
        self._stop.set()
