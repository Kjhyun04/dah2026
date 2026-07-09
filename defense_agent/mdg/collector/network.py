"""NetworkMetricCollector — 4G NF들의 :9090 Prometheus 폴링 (P4-2/P4-3, B-1/B-2).

각 NF의 ``/metrics`` 를 net_core 상에서 httpx로 폴링한다(air 이미지에는 curl/nc가
없음, B-2). trip 신호는 POSITIVE 카운터 diff 만 사용한다(P4-3): ``*_active`` gauge는
이 testbed에서 NEGATIVE로 나오며(pfcp_sessions_active = -8) trip에는 절대 쓰지 않는다.
음수 카운터 diff(NF 재시작)는 신호를 내지 않고 baseline을 재파종한다.

NF별 메트릭 맵(라이브 확인된 IP):
  SMF 10.50.0.4:9090 — s5c_rx_deletesession (PFCP 세션 삭제), *_parse_failed
  UPF 10.50.0.7:9090 — fivegs_ep_n3_gtp_in/outdatapktn3upf (N3 데이터플레인 볼륨)
  MME 10.50.0.2:9090 — enb/enb_ue/mme_session (희소)

httpx는 subprocess가 아니라 네트워크 클라이언트이므로, 이 collector는
Backend를 쓰지 않는다(불변식2. 는 subprocess 부작용만 다룸).
"""
from __future__ import annotations

from typing import Optional

from .base import BaseCollector

# NF -> (주소, [감시할 카운터 메트릭명]) ; gauge는 의도적으로 제외.
NF_TARGETS: dict[str, dict] = {
    "smf": {"addr": "10.50.0.4:9090", "counters": [
        "s5c_rx_deletesession", "s5c_rx_createsession",
        "s5c_rx_parse_failed", "gtp_node_s5c_rx_parse_failed", "gtp_new_node_failed",
    ]},
    "upf": {"addr": "10.50.0.7:9090", "counters": [
        "fivegs_ep_n3_gtp_indatapktn3upf", "fivegs_ep_n3_gtp_outdatapktn3upf",
    ]},
    "mme": {"addr": "10.50.0.2:9090", "counters": []},
}

# 어떤 카운터 -> 방어 메트릭명 + 도메인 (thresholds.yaml). PFCP trip 신호에는
# s5c deletesession/parse-failed 계열만 매핑된다.
_SIGNAL_MAP: dict[str, tuple[str, str]] = {
    "s5c_rx_deletesession": ("PFCP_Delete_Attempt", "session_network"),
    "s5c_rx_parse_failed": ("PFCP_Delete_Attempt", "session_network"),
    "gtp_node_s5c_rx_parse_failed": ("PFCP_Delete_Attempt", "session_network"),
    "gtp_new_node_failed": ("PFCP_Delete_Attempt", "session_network"),
}

# non-trip 관측용 카운터: D.METRICS에 없는 메트릭명으로 방출되며(compute_trust ->
# trust 기여 0) band="normal"로 고정되어 correlate가 이들로는 절대 trip하지 않는다
# (correlate.py의 band 게이트). UPF N3 데이터플레인 볼륨은 HIGH-rate 정상 트래픽이며,
# 절대 PFCP danger 신호로 날조되어서는 안 된다(self-DoS 가드, audit row G).
_NONTRIP_MAP: dict[str, str] = {
    "fivegs_ep_n3_gtp_indatapktn3upf": "N3_Data_Volume",
    "fivegs_ep_n3_gtp_outdatapktn3upf": "N3_Data_Volume",
}


def parse_prometheus(text: str) -> dict[str, float]:
    """Prometheus 텍스트 exposition을 파싱한다. 한 메트릭명의 모든 label-set을 SUM으로
    집계한다(그래서 ``m{addr="x"} 8`` 같은 peer별 series는 계열 합계로 합쳐짐)."""
    out: dict[str, float] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # "name{labels} value" 또는 "name value" 를 분리
        brace = line.find("{")
        if brace != -1:
            name = line[:brace]
            close = line.find("}", brace)
            rest = line[close + 1:].strip() if close != -1 else ""
        else:
            parts = line.split()
            name = parts[0] if parts else ""
            rest = parts[1] if len(parts) > 1 else ""
        if not name or not rest:
            continue
        val = rest.split()[0]
        try:
            out[name] = out.get(name, 0.0) + float(val)
        except ValueError:
            continue
    return out


def counter_diff(prev: Optional[float], cur: float) -> Optional[float]:
    """양수 diff = 신호; diff<0 (reset/restart) -> None (baseline 재파종);
    최초 관측(prev is None) -> None (baseline 확립, 신호 없음)."""
    if prev is None:
        return None
    d = cur - prev
    if d < 0:
        return None                       # NF 재시작/reset -> 신호가 아니라 재파종
    return d


def _band_for_delete(delta: float) -> str:
    if delta <= 0:
        return "normal"
    if delta == 1:
        return "warning"
    if delta <= 3:
        return "critical"
    return "danger"


class NetworkMetricCollector(BaseCollector):
    source_id = "net_metric"
    domain = "session_network"

    def __init__(self, *args, targets: Optional[dict] = None, timeout_s: float = 3.0, **kw):
        super().__init__(*args, **kw)
        self.targets = targets or NF_TARGETS
        self.timeout_s = timeout_s
        self._prev: dict[str, float] = {}     # "nf:metric" -> 마지막 값

    def _fetch(self, addr: str) -> Optional[str]:
        try:
            import httpx  # 로컬 의존성 사용 가능
        except Exception:                     # pragma: no cover
            return None
        try:
            r = httpx.get(f"http://{addr}/metrics", timeout=self.timeout_s)
            if r.status_code == 200:
                return r.text
        except Exception:
            return None
        return None

    def _process_text(self, nf: str, watch: list[str], text: str) -> list[dict]:
        parsed = parse_prometheus(text)
        payloads: list[dict] = []
        for name in watch:
            if name not in parsed:
                continue
            cur = parsed[name]
            key = f"{nf}:{name}"
            delta = counter_diff(self._prev.get(key), cur)
            self._prev[key] = cur
            if delta is None or delta <= 0:
                continue
            sig = _SIGNAL_MAP.get(name)
            if sig is not None:
                metric, domain = sig
                band = _band_for_delete(delta)
            elif name in _NONTRIP_MAP:
                # 관측 전용: 절대 PFCP trip으로 날조되지 않음.
                metric, domain, band = _NONTRIP_MAP[name], "session_network", "normal"
            else:
                continue        # 알 수 없는 카운터: 건너뜀, PFCP trip으로 기본 처리 금지
            payloads.append({
                "metric": metric, "value": int(delta),
                "band": band, "domain": domain,
                "channel": "prometheus_9090", "confidence": 0.90,
            })
        return payloads

    def collect(self) -> list[dict]:
        payloads: list[dict] = []
        for nf, spec in self.targets.items():
            watch = spec.get("counters") or []
            if not watch:
                continue
            text = self._fetch(spec["addr"])
            if text is None:
                continue
            payloads.extend(self._process_text(nf, watch, text))
        return payloads
