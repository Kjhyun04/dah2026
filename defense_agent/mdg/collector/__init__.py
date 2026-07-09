"""Collector — out-of-graph long-lived daemons; keyring owner (PS-2/PS-5).

Seven collectors (P1 observation engine):
  AirCommandTap          air-side netns sidecar — gcs_proxy eth0 UDP:14556 (command)
  AirTelemetryTap        air-side netns sidecar — 14560 + uav_ue lo:14550 cross-tap
  NetworkMetricCollector network — NF :9090 Prometheus polling (httpx)
  WebProbeCollector      web — 5762 ss-only, pool=1
  MongoLogCollector      mongo — docker logs stdout JSON
  MissionConfigCollector mission — config-derived context
  SignLogCollector       command — uav_proxy docker logs §9-B signing drop-line (P3-Q2)

``build_collectors`` wires the standard set against one output queue + keyring.
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
from .web import WebProbeCollector

__all__ = [
    "BaseCollector", "AirCommandTap", "AirTelemetryTap", "NetworkMetricCollector",
    "WebProbeCollector", "MongoLogCollector", "MissionConfigCollector",
    "SignLogCollector", "SmfSessionCollector", "SmfSessionTable", "MmeLogTail", "ansi_strip",
    "Keyring", "SensorEnvelope", "compute_hmac", "verify_envelope",
    "build_collectors", "build_epc_collectors", "build_source_domains",
]


def build_source_domains(collectors: list) -> dict[str, str]:
    """{source_id -> domain} for the P3-Q5 liveness attribution (watchdog sensor_loss ->
    dead domain -> compute_trust present-set exclusion). Built from the collector roster's
    own ``.source_id``/``.domain`` (the watchdog emits ``value=source_id``); collectors
    without a domain are omitted (netns-agnostic infra collectors)."""
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
    """Instantiate the standard 7-collector set sharing one queue + keyring/kid.
    Each collector signs its envelopes with ``kid``; ``sense`` verifies at drain.

    ``netns_prefix_map`` (container -> nsenter prefix) is the recon->collector bridge
    (P1-netns): recon_boot resolves host PIDs via the sock-proxy inspect and the launcher
    turns them into ``nsenter --target <pid> --net --`` prefixes here. A container absent
    from the map (``.get`` -> None) leaves its netns collector inert — no ip-netns-exec
    invention, no mis-targeted live tap. NetworkMetric/Mongo/Mission are netns-agnostic.
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
        AirCommandTap(out_queue, keyring, kid, netns_prefix=m.get("gcs_proxy"), **air_common),
        AirTelemetryTap(out_queue, keyring, kid, netns_prefix=m.get("uav_ue"), **air_common),
        NetworkMetricCollector(out_queue, keyring, kid, **common),
        WebProbeCollector(out_queue, keyring, kid, netns_prefix=m.get("uav_ue"), **common),
        MongoLogCollector(out_queue, keyring, kid, **common),
        MissionConfigCollector(out_queue, keyring, kid, **common),
        # §9-B uplink-signing posture: uav_proxy drop-line tail (P3-Q2). netns-agnostic
        # (docker logs, like Mongo). Its ``Signing_Drop`` evidence latches world.signing ->
        # CONFIRMED_ON in sense (MONOTONIC). domain='command' -> registered in the source-
        # domain map (build_source_domains) for watchdog liveness attribution.
        SignLogCollector(out_queue, keyring, kid, **common),
    ]


def build_epc_collectors(out_queue: "_queue.Queue", keyring: Keyring, kid: str, *,
                         backend=None, clock=None,
                         session_table: Optional[SmfSessionTable] = None,
                         smf_container: str = "epc_smf",
                         mme_container: str = "epc_mme",
                         ) -> tuple[list[BaseCollector], SmfSessionTable]:
    """Opt-in EPC log-tail collectors (P4-1/P4-5). Returns the collector list PLUS the shared
    SmfSessionTable so ``correlate`` (P4-4 join) and target ``resolve`` (C-3 pause reverse
    map) read the same live IMSI<->tun-IP bindings. Not part of the default 6-set; wired
    explicitly by the runtime launcher once the read-only logs path is operator-approved.
    Includes the SMF session-table tail (P4-1) and the MME attach/IMSI tail (P4-5).
    """
    table = session_table or SmfSessionTable()
    common = dict(backend=backend, clock=clock)
    collectors: list[BaseCollector] = [
        SmfSessionCollector(out_queue, keyring, kid, table=table,
                            container=smf_container, **common),
        MmeLogTail(out_queue, keyring, kid, container=mme_container, **common),
    ]
    return collectors, table
