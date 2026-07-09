"""MmeLogTail — epc_mme docker-logs stdout tail: attach / IMSI 이벤트 (P4-5).

DESIGN_DECISIONS P4-5에 따라, attach/IMSI/service-request 관측은 MME 로그를 단일
소스로 사용한다(MME :9090 메트릭은 희소함 — enb/enb_ue/mme_session만). 따라서 Rogue-UE
attach 탐지(TM3)는 MME-로그 tail이다. EPC 로그 파스 규율은 공유된다(``log_common``):
먼저 ANSI-strip, 그다음 regex; 타임스탬프 형식 ``MM/DD HH:MM:SS.mmm``은 ``parse_epc_ts``로
고정된다.

이는 ``tests/verify_parsers.py``가 실행하는 파서 집합의 P4-5 멤버다. 순수 관측,
state-change-0; ``docker logs`` 읽기는 SMF/Mongo 로그 collector와 똑같이 safe-exec
Backend를 통해 라우팅된다(불변식2.). dry/mock Backend는 줄을 산출하지 않는다(collector는
단순히 아무것도 emit하지 않음).

경계: 여기에 docker sdk import 없음, sock/proxy URL 리터럴 없음(verify_grep0). Null-safe:
``parse_mme_line(None)`` -> None (``re.search(None)`` 크래시 없음).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .base import BaseCollector
from .log_common import ansi_strip, parse_epc_ts

# Open5GS MME 줄은 IMSI를 ``IMSI[001010000000001]`` 또는 ``IMSI[imsi-001010000000001]``
# NAI 형태로 담는다; 둘 다 허용. 15자리 IMSI (관대하게 6..15).
_IMSI_RE = re.compile(r"IMSI\[(?:imsi-)?(\d{6,15})\]")

# event-kind 키워드(attach/identity/auth/service/detach). 첫 매치 우선; 없으면 "event".
_KIND_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("Attach", "attach"),
    ("attach", "attach"),
    ("Detach", "detach"),
    ("detach", "detach"),
    ("Service", "service"),
    ("Authentication", "auth"),
    ("Identity", "identity"),
    ("TAU", "tau"),
    ("Tracking", "tau"),
)


@dataclass
class AttachEvent:
    imsi: str
    kind: str = "event"   # attach|detach|service|auth|identity|tau|event
    ts: str = ""          # 원시 MM/DD HH:MM:SS.mmm 토큰 (P4-5), best-effort


def _kind_for(line: str) -> str:
    for token, kind in _KIND_KEYWORDS:
        if token in line:
            return kind
    return "event"


def parse_mme_line(raw: str) -> Optional[AttachEvent]:
    """MME 로그 한 줄을 AttachEvent(IMSI + kind + ts)로 파싱, 없으면 None.

    먼저 ANSI-strip(P4-5). None/""에 대해 Null-safe(None 반환; re.search(None) 없음).
    줄은 IMSI 토큰을 담을 때만 이벤트다; kind는 attach/identity/service/auth 키워드
    어휘에서 나온 best-effort 라벨이다."""
    line = ansi_strip(raw)
    if not line:
        return None
    m = _IMSI_RE.search(line)
    if not m:
        return None
    return AttachEvent(imsi=m.group(1), kind=_kind_for(line), ts=parse_epc_ts(line))


def _docker_logs_argv(container: str, since_s: int) -> list[str]:
    # 유계 --since 윈도(-f 아님)로 데몬 읽기를 결정론으로 유지, SMF/Mongo 로그 collector와
    # 동일. read-only logs GET은 sock-proxy 화이트리스트 경로다.
    return ["docker", "logs", "--since", f"{since_s}s", container]


class MmeLogTail(BaseCollector):
    """그래프 외부 데몬: ``docker logs epc_mme``를 tail하고 attach/IMSI 이벤트를
    identity-도메인 증거로 emit한다(P4-5). Rogue-UE attach 분류(TM3)는 correlation
    계층에 맡긴다; 이 collector는 순수 attach-이벤트 관측이다.

    기본 6-collector 집합에는 포함되지 않음(opt-in EPC log-tail, P1-Q3); subprocess는
    오직 safe-exec Backend를 통한다(불변식2.). dry/mock backend는 줄을 산출하지 않음."""
    source_id = "mme_log"
    domain = "identity_access"

    def __init__(self, *args, container: str = "epc_mme", since_s: int = 3, **kw):
        super().__init__(*args, **kw)
        self.container = container
        self.since_s = since_s
        self._seen: set[str] = set()               # --since 윈도 내 dedupe

    def collect(self) -> list[dict]:
        res = self._observe(_docker_logs_argv(self.container, self.since_s))
        if res is None or res.dry_run:
            return []
        payloads: list[dict] = []
        for chunk in (res.stdout, res.stderr):
            for ln in (chunk or "").splitlines():
                ev = parse_mme_line(ln)
                if ev is None:
                    continue
                key = f"{ev.kind}:{ev.imsi}:{ev.ts}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                # attach는 TM3 rogue-UE 관측면; low-band identity 증거로 emit(분류는
                # correlate로 지연). 다른 kind는 컨텍스트다.
                if ev.kind == "attach":
                    payloads.append({
                        "metric": "UE_Attach", "value": 1, "band": "warning",
                        "domain": "identity_access", "channel": "nas_log",
                        "confidence": 0.85, "imsi": ev.imsi,
                    })
        if len(self._seen) > 4096:
            self._seen.clear()
        return payloads
