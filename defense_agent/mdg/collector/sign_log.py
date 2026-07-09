"""SignLogCollector — uav_proxy docker-logs 서명 drop-line tail (P3-Q2, §9-B).

§9-B MAVLink2 업링크 서명 강제는 uav_proxy 에 있다. UNSIGNED 명령이 주입되면
proxy가 이를 drop하고 stdout에 권위 있는 drop line을 출력한다:

    [proxy] 서명검증 실패 -> SITL 차단 (누적 N)

이 line은 서명 강제가 ON임을 나타내는 POSITIVE 증거다(uav_proxy가 실제로 unsigned
명령을 차단함). 이 collector는 docker logs uav_proxy 를 read-only로 tail하며(SMF/MME/
Mongo collector와 동일한 sock-proxy GET /containers/{id}/logs 경로) 파생된 Signing_Drop
SensorEv를 방출하고, sense 가 이를 world.signing = CONFIRMED_ON 으로 latch한다
(MONOTONIC; drop line 관측이 유일한 승격 트리거 — 침묵은 절대 승격 안 함, banner
단독으로도 절대 승격 안 함: fail-safe 비대칭, P2-Q2).

원칙(P3-Q2 lock):
  - band=normal / 메트릭이 defaults.METRICS 에 없음 => 이 drop은 distrust를 ZERO로
    더한다(P3-Q4: verify-fail DROP은 침해가 아니라 방어 SUCCESS — 절대 crit_floor를
    발화시켜선 안 됨). 누적 카운터는 순수 활동 메트릭으로만 투영된다.
  - secret-free (PS-3): 파생된 누적 정수만 투영한다; 원본 로그 라인, cipher peer 튜플,
    어떤 키 자재도 envelope에 절대 올리지 않는다.
  - ANSI-strip FIRST (공유 log_common.ansi_strip) 하여 색 escape가 matcher가 기대하는
    토큰 사이에 절대 끼지 못하게 한다.

경계: subprocess(docker logs)는 safe-exec Backend를 통해서만 발행한다(불변식2.);
docker sdk import 없음, sock/proxy URL 리터럴 없음. Null-safe: parse_signing_line(None) -> None.
dry/mock Backend는 라인을 내지 않는다(collector는 아무것도 방출하지 않음 — inert).
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseCollector
from .log_common import ansi_strip

# drop line의 안정적 마커(둘 중 어느 substring이든 verify-fail 차단 이벤트를 식별);
# emoji/화살표는 장식일 뿐 의존하지 않는다. 누적 N 이 누적 카운터를 담는다.
_DROP_MARKERS = ("서명검증 실패", "SITL 차단")
_CUM_RE = re.compile(r"누적\s*(\d+)")


def parse_signing_line(raw: str) -> Optional[dict]:
    """uav_proxy verify-fail drop line에 대해 파생된 Signing_Drop payload를 반환, 아니면 None.

    Null-safe (None/"" -> None). ANSI-strip 먼저(P3-Q2). Positive-only: drop line만이
    payload를 낸다 — drop 부재는 절대 OFF 증거가 아니며 None을 낸다(침묵≠OFF).
    Secret-free: 누적 카운터(파생 int)만 투영하고, 원본 라인은 절대 투영하지 않는다."""
    line = ansi_strip(raw)
    if not line:
        return None
    if not any(mark in line for mark in _DROP_MARKERS):
        return None
    m = _CUM_RE.search(line)
    cumulative = int(m.group(1)) if m else 1
    return {
        # 메트릭은 defaults.METRICS에서 의도적으로 배제됨 -> trust 기여 ZERO
        # (P3-Q4: 차단은 distrust가 아니라 방어 성공). band=normal이 이를 강화한다.
        "metric": "Signing_Drop", "value": cumulative, "band": "normal",
        "domain": "command", "channel": "uav_proxy_signlog",
        "confidence": 0.9, "source": "uav_proxy",
    }


def _docker_logs_argv(container: str, since_s: int) -> list[str]:
    # bounded --since 윈도우(-f 아님)로 daemon read가 결정론적으로 유지되게 한다, SMF/MME/
    # Mongo 로그 collector와 정확히 동일. read-only logs GET은 sock-proxy 화이트리스트 경로.
    return ["docker", "logs", "--since", f"{since_s}s", container]


class SignLogCollector(BaseCollector):
    """Out-of-graph daemon: docker logs uav_proxy 를 tail하여 §9-B 서명 drop-line을
    command 도메인 증거로 방출한다(P3-Q2). 6+1 번째 collector; subprocess는 safe-exec
    Backend를 통해서만 간다(불변식2.). dry/mock backend는 라인을 내지 않는다(inert)."""
    source_id = "uav_signlog"
    domain = "command"

    def __init__(self, *args, container: str = "uav_proxy", since_s: int = 3,
                 dedupe_window_s: float = 60.0, **kw):
        super().__init__(*args, **kw)
        self.container = container
        self.since_s = since_s
        # Coarse-bucket dedupe (MongoLogCollector 선례): 연속으로 겹치는 --since 윈도우
        # 전반에서 관측된 동일 누적 카운터는 한 번만 방출되고, 이후 윈도우는 RE-EMIT한다
        # (latch/활동 신호가 영구히 억제되지 않고, proxy 재시작 후 카운터 reset이 영원히
        # 가려지지 않도록). 주입된 clock을 사용한다.
        self.dedupe_window_s = float(dedupe_window_s)
        self._seen: set[str] = set()

    def collect(self) -> list[dict]:
        res = self._observe(_docker_logs_argv(self.container, self.since_s))
        if res is None or res.dry_run:
            return []
        win = self.dedupe_window_s if self.dedupe_window_s > 0 else 1.0
        bucket = int(self.clock.now() // win)
        payloads: list[dict] = []
        # docker logs는 stdout에 쓴다; 일부 빌드는 stderr로 방출 — 둘 다 스캔.
        for chunk in (res.stdout, res.stderr):
            for ln in (chunk or "").splitlines():
                p = parse_signing_line(ln)
                if p is None:
                    continue
                key = f"{p.get('value')}|{bucket}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                payloads.append(p)
        if len(self._seen) > 4096:            # 유계 dedupe 캐시 (DoS 상한)
            self._seen.clear()
        return payloads
