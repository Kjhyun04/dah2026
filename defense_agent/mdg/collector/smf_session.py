"""SmfSessionTable — SMF 로그 tail을 통한 IMSI <-> 동적 tun-IP 세션 테이블 (P4-1/P4-4).

FEASIBILITY §2 ("IMSI join 불가 -> time-window만")는 여기서 정정된다: Open5GS SMF
로그는 실제로 세션 create/delete 시 IMSI<->할당 IP 바인딩을 방출하므로, ``docker logs
epc_smf`` stdout의 라이브 tail은 양방향 세션 테이블을 만든다. 그 테이블은 세 가지에
대한 유일한 join key다(P4-1):

  1. command_source 관점 귀속(어떤 IMSI가 UE-pool source IP를 소유하는가),
  2. ``docker pause`` 타깃 해석 — PRIMARY layer-1 경로(P2-Q1): UE-pool source IP
     -> IMSI(이 테이블) -> container(정적 ``spec.imsi_container_map`` boot 상수),
     이는 exec/nsenter가 필요 없다. 라이브 tun-scan 역맵은 SECONDARY ground-
     truth 교차확인(C-3 / resolve.reverse_container_for_ip layer 2)이지 primary가 아니다.
  3. cross-plane 상관 join(메트릭 delete diff + 로그 delete 이벤트, P4-4).

소스(A-1): mongo ``subscribers`` 는 IMSI만 담는다(동적 IP 없음); tun_srsue IP는
``docker inspect`` 에 없다. SMF 로그가 이 바인딩의 유일한 소스다.

파싱 원칙: ANSI-strip FIRST (P4-5) — 라이브 라인은 색 escape가 붙어 있어, strip을
건너뛰면 모든 regex가 miss한다. 순수 관측, 상태 변화 zero.
"""
from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Optional

from ..config import defaults
from .base import BaseCollector
from .log_common import ansi_strip, parse_epc_ts

# 이식성(GATE2, finding P2-3): regex는 임의의 IPv4를 캡처하고 pool 멤버십은
# ``spec.ue_pool_cidr`` 에 대해 CIDR로 검사한다 — 중복된 "10.45" 리터럴이 아님.
# UE pool이 다른 인스턴스에서 파서는 조용히 매칭을 멈추는 대신 config를 따른다. 기본값은
# config.INPUT_SPEC(10.45.0.0/16)를 미러링하여 lock된 live-wire 동작이 바뀌지 않게 한다.
_DEFAULT_POOL_CIDR: str = str(defaults.INPUT_SPEC.get("ue_pool_cidr") or "10.45.0.0/16")
_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
# Create: "... UE IMSI[001010000000001] ... IPv4[10.45.0.2] ..."  (P4-1 lock된 형태)
_CREATE_RE = re.compile(r"UE IMSI\[(\d+)\].*?IPv4\[" + _IPV4 + r"\]")
# Delete: "Removed Session: UE IMSI:[imsi-001..] ... IPv4:[10.45.0.3]"  (P4-1 lock된 형태)
_REMOVE_RE = re.compile(r"Removed Session: UE IMSI:\[imsi-(\d+)\].*?IPv4:\[" + _IPV4 + r"\]")


def _ip_in_pool(ip: str, cidr: str) -> bool:
    """CIDR 멤버십(config 기반 pool 필터), junk 입력에 대해서도 total."""
    if not ip or not cidr:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


@dataclass
class SessionEvent:
    op: str            # "add" | "remove"
    imsi: str
    ip: str
    ts: str = ""       # 원본 MM/DD HH:MM:SS.mmm 토큰 (P4-5), best-effort


def parse_smf_line(raw: str, pool_cidr: str = _DEFAULT_POOL_CIDR) -> Optional[SessionEvent]:
    """SMF 로그 한 줄을 SessionEvent로 파싱, 아니면 None. ANSI-strip 먼저(P4-5).

    delete를 create보다 먼저 검사하는데, delete 라인은 create regex에 매칭되지 않지만,
    순서를 명시적으로 두어 두 개의 구별되는 wire 포맷을 문서화한다
    (create는 ``IMSI[..] IPv4[..]`` vs remove는 ``UE IMSI:[imsi-..] IPv4:[..]``).

    Null-safe: None/"" raw -> None (``re.search(None)`` crash 없음). 이식성: IPv4가
    ``pool_cidr``(config ``ue_pool_cidr``) 안에 드는 세션만 추적하므로, non-pool 라인은
    과거의 하드코딩된 ``10.45`` prefix와 동일하게 무시된다 — 단 이제는 중복 리터럴이
    아니라 config를 따른다(finding P2-3).
    """
    line = ansi_strip(raw)
    if not line:                          # null-safe: ansi_strip(None)->None; re.search(None) 금지
        return None
    ts = parse_epc_ts(line)
    mr = _REMOVE_RE.search(line)
    if mr and _ip_in_pool(mr.group(2), pool_cidr):
        return SessionEvent(op="remove", imsi=mr.group(1), ip=mr.group(2), ts=ts)
    mc = _CREATE_RE.search(line)
    if mc and _ip_in_pool(mc.group(2), pool_cidr):
        return SessionEvent(op="add", imsi=mc.group(1), ip=mc.group(2), ts=ts)
    return None


class SmfSessionTable:
    """SMF 로그 이벤트로 채워지는 스레드 안전 양방향 IMSI<->tun-IP 맵.

    collector daemon이 다른 스레드에서 라인을 채우는 동안 ``sense``/``correlate`` 가
    스냅샷을 읽으므로, 모든 mutation/lookup은 lock으로 보호된다. ``recent`` 는 P4-4
    time-window join을 위해 최신 delete 이벤트의 유계 ring을 유지한다.
    """

    def __init__(self, recent_max: int = 256, pool_cidr: str = _DEFAULT_POOL_CIDR):
        self._lock = threading.Lock()
        self.imsi_to_ip: dict[str, str] = {}
        self.ip_to_imsi: dict[str, str] = {}
        self.recent: list[SessionEvent] = []       # 유계 (add & remove 둘 다)
        self._recent_max = recent_max
        self.pool_cidr = pool_cidr or _DEFAULT_POOL_CIDR   # config 기반 pool 필터 (finding P2-3)

    # -- mutation ---------------------------------------------------------- #
    def add(self, imsi: str, ip: str) -> None:
        with self._lock:
            # 재사용된 IP가 낡은 IMSI를 계속 가리켜선 안 됨: 기존 바인딩 축출
            old_ip = self.imsi_to_ip.get(imsi)
            if old_ip and old_ip != ip:
                self.ip_to_imsi.pop(old_ip, None)
            old_imsi = self.ip_to_imsi.get(ip)
            if old_imsi and old_imsi != imsi:
                self.imsi_to_ip.pop(old_imsi, None)
            self.imsi_to_ip[imsi] = ip
            self.ip_to_imsi[ip] = imsi

    def remove(self, imsi: str, ip: str = "") -> None:
        with self._lock:
            ip = ip or self.imsi_to_ip.get(imsi, "")
            self.imsi_to_ip.pop(imsi, None)
            if ip:
                self.ip_to_imsi.pop(ip, None)

    def feed_line(self, raw: str) -> Optional[SessionEvent]:
        """로그 한 줄을 파싱 + 적용. 이벤트를 반환한다(호출자가 emit/join하도록)."""
        ev = parse_smf_line(raw, self.pool_cidr)
        if ev is None:
            return None
        if ev.op == "add":
            self.add(ev.imsi, ev.ip)
        else:
            self.remove(ev.imsi, ev.ip)
        with self._lock:
            self.recent.append(ev)
            if len(self.recent) > self._recent_max:       # 유계 (DoS 상한)
                self.recent = self.recent[-self._recent_max:]
        return ev

    # -- lookup (스냅샷 읽기) ------------------------------------------ #
    def imsi_for_ip(self, ip: str) -> Optional[str]:
        with self._lock:
            return self.ip_to_imsi.get(ip)

    def ip_for_imsi(self, imsi: str) -> Optional[str]:
        with self._lock:
            return self.imsi_to_ip.get(imsi)

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self.imsi_to_ip)

    def recent_removes(self, pool_cidr: str = "") -> list[SessionEvent]:
        """P4-4 귀속 join(메트릭 diff + 로그 delete)을 위한 delete 이벤트.

        Pool 멤버십은 하드코딩된 ``10.45`` prefix가 아니라 ``pool_cidr``(기본 ``self.pool_cidr``,
        config ``ue_pool_cidr``)에 대해 CIDR로 검사된다(finding P2-3)."""
        cidr = pool_cidr or self.pool_cidr
        with self._lock:
            return [e for e in self.recent if e.op == "remove" and _ip_in_pool(e.ip, cidr)]


def _docker_logs_argv(container: str, since_s: int) -> list[str]:
    # bounded --since 윈도우(-f 아님)로 daemon의 read가 결정론적으로 유지되게 한다,
    # MongoLogCollector와 동일. read-only logs GET은 sock-proxy 화이트리스트 경로(PS-1).
    return ["docker", "logs", "--since", f"{since_s}s", container]


class SmfSessionCollector(BaseCollector):
    """Out-of-graph daemon: ``docker logs epc_smf`` 를 tail하며 공유 SmfSessionTable을
    유지하고, 세션 add/remove를 P4-4 join의 증거로 방출한다.

    ``build_epc_collectors`` 를 통해 opt-in으로 배선된다(기본 6-collector 세트에는 미포함);
    유지하는 테이블은 ``correlate``(join) 및 타깃 ``resolve``(pause 역맵)와 공유된다.
    subprocess(docker logs)는 safe-exec Backend를 통해서만 간다(불변식2.); dry/mock
    backend는 라이브 라인을 내지 않는다(테이블은 그냥 비어 있음).
    """
    source_id = "smf_session"
    domain = "session_network"

    def __init__(self, *args, table: Optional[SmfSessionTable] = None,
                 container: str = "epc_smf", since_s: int = 3,
                 pool_cidr: str = _DEFAULT_POOL_CIDR, **kw):
        super().__init__(*args, **kw)
        self.table = table or SmfSessionTable(pool_cidr=pool_cidr)
        self.container = container
        self.since_s = since_s
        self._seen: set[str] = set()               # --since 윈도우 내 dedupe

    def collect(self) -> list[dict]:
        res = self._observe(_docker_logs_argv(self.container, self.since_s))
        if res is None or res.dry_run:
            return []
        payloads: list[dict] = []
        for chunk in (res.stdout, res.stderr):
            for ln in (chunk or "").splitlines():
                ev = self.table.feed_line(ln)
                if ev is None:
                    continue
                key = f"{ev.op}:{ev.imsi}:{ev.ip}:{ev.ts}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                # 세션 REMOVE만이 방어적 귀속 신호(P4-4); ADD는 테이블 유지보수.
                # remove는 low-band 귀속 증거로 방출한다.
                if ev.op == "remove":
                    payloads.append({
                        "metric": "PFCP_Delete_Attempt", "value": 1, "band": "warning",
                        "domain": "session_network", "channel": "nas_log",
                        "confidence": 0.85, "imsi": ev.imsi, "ip": ev.ip,
                    })
        if len(self._seen) > 4096:
            self._seen.clear()
        return payloads
