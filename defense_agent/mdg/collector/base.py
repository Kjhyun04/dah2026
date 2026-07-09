"""BaseCollector — 그래프 외부의 장수(long-lived) 데몬 (PA-7, PS-2, PS-5).

collector는 하나의 관측 지점(vantage point)을 주기적으로 관측하고, 서명된
SensorEnvelope를 ``sense``가 non-blocking으로 비우는 공유 ``queue.Queue``에 밀어
넣는 백그라운드 스레드다. collector는 그래프 노드가 아니다: 관측이 여기서 비동기로
도는 동안 그래프는 동기·결정론을 유지한다.

준수하는 불변식 경계:
  - 불변식2.: subprocess 기반 관측(tcpdump/ss/docker logs/nsenter)은 오직 주입된
    ``Backend``(safe-exec)를 통해서만 발행한다. 순수 네트워크 폴링(httpx)과
    config 읽기는 프로세스를 스폰하지 않으므로 직접 수행한다.
  - PS-2 : 모든 envelope는 여기서 HMAC 서명(source keyring)되어 ``sense``가 drain
    시점에 검증할 수 있다. HMAC 키는 이 프로세스의 keyring에 존재하며 State에는 절대
    두지 않는다 (PS-3).
  - DoS  : 출력 queue는 유계다; Full이면 drop + 카운트한다(무한 증가 없음).

서브클래스는 payload dict를 반환하는 ``collect() -> list[dict]``를 구현한다. []
반환은 정상(이번 사이클에 신호 없음)이며 여전히 SUCCESS다 — 조용한 tick도 생존성
``heartbeat()``를 갱신하여 watchdog이 살아있는 collector로 본다. collect()가 RAISE한
사이클은 beat를 보류하므로, 지속적으로 에러 나는 collector는 침묵하고 watchdog(G7)이
죽은 것으로 표시한다 — 에러가 건강한 조용한 tick으로 오인되는 일은 없다.
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

    # -- 오버라이드 대상 --------------------------------------------------- #
    def collect(self) -> list[dict]:
        raise NotImplementedError

    # -- envelope 서명 (PS-2) --------------------------------------------- #
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
            self.out.put_nowait(env)                 # 비동기 push, non-blocking
        except queue.Full:
            self.drops += 1                          # DoS 상한: drop, block/증가 없음

    def emit(self, payload: dict) -> None:
        self.push(self.make_envelope(payload))

    # -- 생명주기 --------------------------------------------------------- #
    def heartbeat(self) -> float:
        return self._last_hb

    def tick_once(self) -> int:
        """한 번의 수집 사이클(스레드 없이 직접 테스트 가능). emit된 payload 개수를
        반환한다. 생존성 heartbeat는 RAISE 없이 끝난 사이클에서만 갱신한다: 조용한
        tick(collect() -> [])은 성공이므로 beat하지만, collect()가 RAISE한 사이클은
        beat를 보류한다(예외가 호출자에게 전파되어 run()이 카운트하므로 아래 heartbeat
        줄에는 도달하지 않는다). 그 결과 지속적으로 에러 나는 collector는 stale 상태로
        남아 watchdog(G7)이 죽은 것으로 표시한다."""
        n = 0
        for payload in (self.collect() or []):
            self.emit(payload)
            n += 1
        self._last_hb = self.clock.now()             # 성공 시에만; collect()가 raise하면 미도달
        return n

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick_once()
            except Exception:                        # collector는 절대 프로세스를 죽여선 안 됨
                self.errors += 1
                # 에러 시 heartbeat를 의도적으로 갱신하지 않음: 실패한 사이클은 beat를 stale
                # 하게 두어야 watchdog(G7)이 지속적으로 에러 나는 collector를 건강한 조용한
                # collector(tick_once의 성공 경로로 beat)와 구분할 수 있다.
            self._stop.wait(self.interval_s)

    def stop(self) -> None:
        self._stop.set()

    # -- subprocess 관측 collector용 헬퍼 --------------------------------- #
    def _observe(self, argv: list[str], timeout_s: float = 8.0):
        """read-only 관측 명령을 safe-exec Backend를 통해 라우팅한다
        (불변식2.). ExecResult를 반환하며 backend가 배선되지 않았으면 None."""
        if self.backend is None:
            return None
        from ..safe_exec.backend import ExecRequest
        return self.backend.run(ExecRequest(argv=argv, timeout_s=timeout_s, read_only=True))
