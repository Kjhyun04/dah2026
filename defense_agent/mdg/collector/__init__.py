"""Collector — 그래프 밖 장수 데몬; keyring 소유자 (PS-2/PS-5).

수집기 6종 (P1 관측 엔진):
  AirCommandTap          air 측 netns 사이드카 — gcs_proxy eth0 UDP:14556 (command)
  AirTelemetryTap        air 측 netns 사이드카 — 14560 + uav_ue lo:14550 cross-tap
  NetworkMetricCollector network — NF :9090 Prometheus 폴링 (httpx)
  MongoLogCollector      mongo — docker logs stdout JSON
  MissionConfigCollector mission — config 파생 컨텍스트
  SignLogCollector       command — uav_proxy docker logs §9-B signing drop-line (P3-Q2)

``build_collectors``는 표준 세트를 하나의 출력 큐 + keyring에 배선한다.
"""
from __future__ import annotations

import queue as _queue
from typing import Optional

from .air_side import AirCommandTap, AirTelemetryTap
from .base import BaseCollector
from .ingest import Keyring, SensorEnvelope, compute_hmac, verify_envelope
from .log_common import ansi_strip
from .mission import MissionConfigCollector
from .mme_log import MmeLogTail
from .mongo import MongoLogCollector
from .network import NetworkMetricCollector
from .sign_log import SignLogCollector
from .smf_session import SmfSessionCollector, SmfSessionTable

__all__ = [
    "BaseCollector", "AirCommandTap", "AirTelemetryTap", "NetworkMetricCollector",
    "MongoLogCollector", "MissionConfigCollector",
    "SignLogCollector", "SmfSessionCollector", "SmfSessionTable", "MmeLogTail", "ansi_strip",
    "Keyring", "SensorEnvelope", "compute_hmac", "verify_envelope",
    "build_collectors", "build_epc_collectors", "build_source_domains",
]


def build_source_domains(collectors: list) -> dict[str, str]:
    """P3-Q5 liveness 귀속용 {source_id -> domain} (watchdog sensor_loss -> 죽은 도메인 ->
    compute_trust present-set 제외). collector 로스터 자체의 ``.source_id``/``.domain``에서
    구성한다(watchdog는 ``value=source_id``를 방출); 도메인 없는 collector는 생략된다
    (netns-무관 인프라 collector)."""
    out: dict[str, str] = {}
    for c in collectors:
        dom = getattr(c, "domain", None)
        sid = getattr(c, "source_id", None)
        if dom and sid:
            out[str(sid)] = str(dom)
    return out


def build_collectors(out_queue: "_queue.Queue", keyring: Keyring, kid: str, *,
                     backend=None, clock=None,
                     netns_prefix_map: Optional[dict[str, list[str]]] = None,
                     ) -> list[BaseCollector]:
    """하나의 queue + keyring/kid를 공유하는 표준 collector 세트를 인스턴스화한다.
    각 collector는 봉투를 ``kid``로 서명한다; ``sense``가 drain에서 검증한다.

    ``netns_prefix_map``(container -> nsenter prefix)는 recon->collector 브리지다
    (P1-netns): recon_boot이 sock-proxy inspect로 호스트 PID를 해소하고 런처가 이를 여기서
    ``nsenter --target <pid> --net --`` prefix로 변환한다. 맵에 없는 컨테이너
    (``.get`` -> None)는 자신의 netns collector를 inert로 둔다 — ip-netns-exec를 지어내지
    않고, 오조준 라이브 탭도 없다. NetworkMetric/Mongo/Mission은 netns-무관이다.
    """
    m = netns_prefix_map or {}
    common = dict(backend=backend, clock=clock)
    # 명령/텔레 평면 blind-gap 복원(적대검증 medium/low): 두 air 탭만 interval_s≈0.1로
    # 배선해 tcpdump를 back-to-back 재무장시킨다. 이러면 듀티사이클이 약 100%가 된다. default 2.0s면 매
    # 사이클 tcpdump(≤창) 후 _stop.wait(2.0) 무캡처 대기로 약 50% 듀티사이클이 되어,
    # 14556에 도착하는 단발 COMMAND_LONG(disarm/SET_MODE 등)이 blind-gap에 소실될 수
    # 있다. read_only 관측은 pool=1 세마포어를 잡지 않으므로(backend.run) 연속 재무장이
    # act 노드/타 collector를 굶기지 않아 이번 성능수정과 상충하지 않는다. -c count는
    # 유지(버스트 시 조기 종료)하여 텔레탭 손실-온셋 샘플링 공백도 함께 줄인다.
    air_common = dict(common, interval_s=0.1)
    return [
        # AirCommandTap DISABLED (라이브 수집기 제외) — 14556 업링크 명령-탭이 정상 업링크(드론
        #   GUIDED@30m 유지용 GCS setpoint 등)를 Unauthorized_Command 로 오탐 → single-signal →
        #   backdoor_pause(web_backend docker_pause) → 8080 대시보드 중단을 유발하는 오탐 경로라
        #   라이브에서 제거. 클래스/테스트/verifier 는 유지(부재=idle-baseline=
        #   healthy 로 안전 처리, verifier.py:185). 재활성 원하면 아래 라인 주석 해제 + 오탐 baseline 필요.
        # AirCommandTap(out_queue, keyring, kid, netns_prefix=m.get("gcs_proxy"), **air_common),
        AirTelemetryTap(out_queue, keyring, kid, netns_prefix=m.get("uav_ue"), **air_common),
        NetworkMetricCollector(out_queue, keyring, kid, **common),
        MongoLogCollector(out_queue, keyring, kid, **common),
        MissionConfigCollector(out_queue, keyring, kid, **common),
        # §9-B uplink-signing posture: uav_proxy drop-line tail (P3-Q2). netns-무관
        # (docker logs, Mongo와 동일). 그 ``Signing_Drop`` 근거가 sense에서 world.signing ->
        # CONFIRMED_ON으로 latch한다(MONOTONIC). domain='command' -> watchdog liveness 귀속을
        # 위해 source-domain 맵(build_source_domains)에 등록된다.
        SignLogCollector(out_queue, keyring, kid, **common),
    ]


def build_epc_collectors(out_queue: "_queue.Queue", keyring: Keyring, kid: str, *,
                         backend=None, clock=None,
                         session_table: Optional[SmfSessionTable] = None,
                         smf_container: str = "epc_smf",
                         mme_container: str = "epc_mme",
                         ) -> tuple[list[BaseCollector], SmfSessionTable]:
    """옵트인 EPC log-tail collector (P4-1/P4-5). collector 리스트에 더해 공유
    SmfSessionTable을 반환하므로 ``correlate``(P4-4 join)와 타깃 ``resolve``(C-3 pause 역맵)가
    동일한 라이브 IMSI<->tun-IP 바인딩을 읽는다. 기본 6-세트에 속하지 않으며; read-only 로그
    경로가 operator 승인되면 런타임 런처가 명시적으로 배선한다.
    SMF session-table tail(P4-1)과 MME attach/IMSI tail(P4-5)을 포함한다.
    """
    table = session_table or SmfSessionTable()
    common = dict(backend=backend, clock=clock)
    collectors: list[BaseCollector] = [
        SmfSessionCollector(out_queue, keyring, kid, table=table,
                            container=smf_container, **common),
        MmeLogTail(out_queue, keyring, kid, container=mme_container, **common),
    ]
    return collectors, table
