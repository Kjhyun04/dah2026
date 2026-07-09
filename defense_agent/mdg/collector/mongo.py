"""MongoLogCollector — epc_mongo docker-logs stdout JSON tail (A-2).

이 testbed에서 Mongo는 로그 파일이 없으므로(/var/log/mongodb/mongod.log 부재), 유일한
소스는 line-delimited JSON인 docker logs epc_mongo stdout이다. 접근 판정(A-2):
  id == 22943 ("Connection accepted") + attr.remote가 RAN CIDR(10.44.0.0/16) 내 =
  cellular/공격자 측에서의 이상 DB 접근 -> DB_Access (identity_access).
  id == 22944 ("Connection ended")는 무시.

tail 명령은 safe-exec Backend를 통해 발행된다(불변식2.). 매 사이클 유계 --since
윈도만 읽는다(-f 아님)므로 동기 drain이 결정론을 유지한다.

PS-1 해결(P1 패널, 확정): sock-proxy 화이트리스트에 read-only
GET /containers/{id}/logs 엔드포인트를 추가(Option A) — log-shipping sidecar가 아님.
inspect는 이미 화이트리스트에 있고 stdout보다 엄격히 더 많은 것을 노출하므로, read-only
logs GET은 신뢰 경계를 넓히지 않는다. 따라서 docker logs가 메커니즘으로 유지된다(프록시
에서 라우팅); 이 동일 경로가 지연된 SMF/MME 로그 collector에도 쓰인다. 파서 자체는
소켓 독립적이고 유닛 테스트되었다.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Optional

from ..config import defaults
from .base import BaseCollector

_ID_ACCEPTED = 22943
_ID_ENDED = 22944
# 이식성(finding P2-3): RAN/cellular 측(DB 접근에 대해 이상)은 하드코딩된 ^10\.44\.
# 접두 대신 config ran_cidr에 대해 CIDR 검사되므로, 파서는 다른 RAN CIDR을 가진
# 인스턴스에서 config를 따른다. 기본값은 config.INPUT_SPEC(10.44.0.0/16)을 미러링하여
# 확정된 live-wire 동작이 변경되지 않는다.
_DEFAULT_RAN_CIDR: str = str(defaults.INPUT_SPEC.get("ran_cidr") or "10.44.0.0/16")


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    if not ip or not cidr:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def parse_mongo_line(line: str, ran_cidr: str = _DEFAULT_RAN_CIDR) -> Optional[dict]:
    """RAN CIDR에서의 accepted 연결에 대한 접근 payload를 반환, 없으면 None.

    Null-safe: None/"" -> None. 이식성: 이상-소스 판정은 (config 기반) ran_cidr에
    대한 CIDR 멤버십 검사이며, 중복된 리터럴이 아니다."""
    line = (line or "").strip()
    if not line or "22943" not in line:
        return None
    try:
        obj = json.loads(line)
    except (ValueError, json.JSONDecodeError):
        return None
    if obj.get("id") != _ID_ACCEPTED:
        return None
    remote = str(obj.get("attr", {}).get("remote", ""))
    host = remote.split(":")[0]
    if not _ip_in_cidr(host, ran_cidr):
        return None                          # sgi/normal 측 -> 신호 아님
    return {
        "metric": "DB_Access", "value": 1, "band": "warning",
        "domain": "identity_access", "channel": "mongo_conn_log",
        "confidence": 0.60, "remote": remote,
    }


def _docker_logs_argv(container: str, since_s: int) -> list[str]:
    return ["docker", "logs", "--since", f"{since_s}s", container]


class MongoLogCollector(BaseCollector):
    source_id = "mongo_log"
    domain = "identity_access"

    def __init__(self, *args, container: str = "epc_mongo", since_s: int = 3,
                 ran_cidr: str = _DEFAULT_RAN_CIDR,
                 dedupe_window_s: float = 60.0, **kw):
        super().__init__(*args, **kw)
        self.container = container
        self.since_s = since_s
        self.ran_cidr = ran_cidr or _DEFAULT_RAN_CIDR
        # dedupe는 원시 remote가 아니라 COARSE 시간 버킷으로 스코프된다: 순수 remote
        # 키는 재접속하는 IP를 영구히 억제한다(RAN 측에서의 실제 반복 DB 접근이 4096 상한
        # flush 전까지 영원히 마스킹됨). floor(now / dedupe_window_s)로 버킷팅하면
        # 윈도 내 중첩 dedupe(연속으로 겹치는 --since 윈도에 걸쳐 보이는 동일 accept
        # 줄은 한 번만 emit)를 유지하면서, 이후 윈도에서 동일 remote를 RE-EMIT한다. 버킷은
        # collector의 주입된 clock(BaseCollector.clock)을 사용; 별도 시간 소스 없음. 이는
        # 탐지-완전성 수정이며 emit되는 어떤 scalar도 변경하지 않는다(metric/value/band/
        # domain/weight/confidence는 그대로).
        self.dedupe_window_s = float(dedupe_window_s)
        self._seen: set[str] = set()          # rolling 윈도 내 {remote|bucket}

    def collect(self) -> list[dict]:
        res = self._observe(_docker_logs_argv(self.container, self.since_s))
        if res is None or res.dry_run:
            return []
        # 사이클당 clock 1회 읽기 -> 이번 사이클에 캡처된 모든 줄에 대해 안정적 버킷
        # (한 drain의 모든 줄은 버킷을 공유; 순서/줄 간 결정론 유지).
        win = self.dedupe_window_s if self.dedupe_window_s > 0 else 1.0
        bucket = int(self.clock.now() // win)
        payloads: list[dict] = []
        # docker logs는 stdout에 JSON을 쓴다; 일부 빌드는 stderr로 emit — 둘 다 스캔.
        for chunk in (res.stdout, res.stderr):
            for ln in (chunk or "").splitlines():
                p = parse_mongo_line(ln, self.ran_cidr)
                if p is None:
                    continue
                key = f"{p.get('remote')}|{bucket}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                payloads.append(p)
        if len(self._seen) > 4096:            # 유계 dedupe 캐시(DoS 상한) — 유지
            self._seen.clear()
        return payloads
