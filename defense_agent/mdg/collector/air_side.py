"""Air-side collectors (2) — netns-sidecar MAVLink taps (B-3/B-4, D-1).

Both join a target container's network namespace (via the recon-injected
``nsenter --target <pid> --net --`` prefix; None => inert) and run ``tcpdump`` through
the safe-exec Backend (불변식②). They observe the plaintext MAVLink planes the testbed
exposes:

  AirCommandTap   — uplink command entry on gcs_proxy eth0 UDP:14556 (B-3). Idle
                    baseline is 0 (traffic only under attack), so ANY packet is an
                    Unauthorized_Command signal; count -> band.
  AirTelemetryTap — downlink telemetry (14560) + uav_ue lo:14550 cross-tap (B-4/D-1).
                    Emits a link-health / HEARTBEAT-presence signal; pymavlink is used
                    to decode sys id when available (optional import).

Live tool constraint (B-2): the air image has tcpdump but no curl/nc, so these use
tcpdump only. A dry/mock Backend yields no threat signal (heartbeat still refreshes).
"""
from __future__ import annotations

from typing import Optional

from .base import BaseCollector


def _tcpdump_argv(netns_prefix: list[str], iface: str, port: int, count: int) -> list[str]:
    # -l line-buffered, -n no-resolve, -c bounded count (so tcpdump self-terminates),
    # -q quiet. UDP filter pinned to the command/telemetry port.
    return list(netns_prefix) + [
        "tcpdump", "-l", "-n", "-q", "-c", str(count), "-i", iface,
        "udp", "port", str(port),
    ]


def _count_packets(stdout: str) -> int:
    """Count tcpdump packet lines (each captured packet is one line with ' IP ')."""
    if not stdout:
        return 0
    return sum(1 for ln in stdout.splitlines() if " IP " in ln or " > " in ln)


class AirCommandTap(BaseCollector):
    """gcs_proxy eth0 UDP:14556 command tap -> Unauthorized_Command (command domain)."""
    source_id = "air_command_tap"
    domain = "command"

    def __init__(self, *args, container: str = "gcs_proxy", iface: str = "eth0",
                 port: int = 14556, count: int = 20,
                 netns_prefix: Optional[list[str]] = None, **kw):
        super().__init__(*args, **kw)
        self.iface = iface
        self.port = port
        self.count = count
        # netns entry prefix = canonical ["nsenter","--target","<pid>","--net","--"],
        # built by nsenter_helper from the recon-resolved host PID and injected via
        # build_collectors. None = unresolved target => this tap runs inert (no fallback;
        # ip-netns-exec is NOT invented — it would silently fail/mis-target on docker).
        self.netns_prefix = netns_prefix

    def collect(self) -> list[dict]:
        if self.netns_prefix is None:
            return []                                   # inert: unresolved netns target
        # 짧은 deadline: idle 인터페이스에서 tcpdump가 count 패킷을 기다리며 무한 블로킹하지
        # 않도록 ~2.0s 마감을 준다. -c count는 유지하되(공격 시 즉시 count까지 캡처) idle이면
        # 타임아웃이 먼저 끊어 빈 stdout(=n<=0)으로 즉시 반환 → 관측은 세마포어 미획득이라
        # 집행 경로를 막지 않지만, 짧은 마감으로 관측 스레드 자체의 정체도 방지한다.
        res = self._observe(
            _tcpdump_argv(self.netns_prefix, self.iface, self.port, self.count),
            timeout_s=2.0,
        )
        if res is None or res.dry_run:
            return []                                   # no live capture -> no signal
        n = _count_packets(res.stdout)
        if n <= 0:
            return []                                   # idle baseline (B-3): 0 = normal
        band = "warning" if n == 1 else "critical"      # Unauthorized_Command bands
        return [{
            "metric": "Unauthorized_Command", "value": n, "band": band,
            "domain": "command", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95,
        }]


class AirTelemetryTap(BaseCollector):
    """Downlink telemetry (14560) + uav_ue lo:14550 cross-tap (D-1). Emits link-health
    / HEARTBEAT-presence on the communication domain.

    P5-Q2 note: this runs a SINGLE tcpdump on one iface/port and emits ONE dict (fixed
    source_id/channel), so 14560 and lo:14550 are NOT separable in the recorded evidence —
    they collapse into one telemetry root. The verifier's anti-spoof '∧' is therefore
    realized CROSS-PLANE (comm heartbeat ∧ command-plane gcs_proxy), not within this tap.
    Only a future collector SPLIT (distinct source_ids for 14560 vs lo:14550) would make a
    within-telemetry 14560∧14550 conjunction meaningful."""
    source_id = "air_telemetry_tap"
    domain = "communication"

    def __init__(self, *args, container: str = "uav_ue", iface: str = "lo",
                 port: int = 14550, count: int = 6, expect_sys: int = 1,
                 netns_prefix: Optional[list[str]] = None, **kw):
        super().__init__(*args, **kw)
        self.iface = iface
        self.port = port
        self.count = count
        self.expect_sys = expect_sys
        self.netns_prefix = netns_prefix          # None => inert (no ip-netns-exec fallback)

    def collect(self) -> list[dict]:
        if self.netns_prefix is None:
            return []                                   # inert: unresolved netns target
        # deadline ~3.0s: ~1Hz HEARTBEAT에서 2s 창은 약 2패킷만 보여 HB jitter>2s이거나
        # 샘플링 공백이 짧은 실공백과 정렬되면 n==0→Packet_Loss(warning) 오탐이 났다. 창을
        # 3.0s로 소폭 확대해 최소 한 번의 HB를 안정적으로 포착, 오탐을 완화한다(손실-온셋
        # 지연은 interval_s≈0.1 back-to-back 재무장으로 별도 완화). count는 유지하되
        # 타임아웃이 먼저 끊는다 — 실제 손실이면 빈 반환(n==0)이 Packet_Loss로 정상 처리된다.
        res = self._observe(
            _tcpdump_argv(self.netns_prefix, self.iface, self.port, self.count),
            timeout_s=3.0,
        )
        if res is None or res.dry_run:
            return []
        n = _count_packets(res.stdout)
        # link present if we saw downlink packets; loss signal if the cross-tap is silent
        if n > 0:
            band = "normal"
            metric, value = "Link_Heartbeat", n
        else:
            band = "warning"
            metric, value = "Packet_Loss", 100          # silent cross-tap = suspected loss
        return [{
            "metric": metric, "value": value, "band": band,
            "domain": "communication", "channel": "plaintext_mavlink_tap",
            "confidence": 0.95,
        }]
