"""NetworkMetricCollector — :9090 Prometheus polling of 4G NFs (P4-2/P4-3, B-1/B-2).

Polls each NF's ``/metrics`` over net_core with httpx (the air image has no curl/nc,
B-2). Trip signals are POSITIVE counter diffs ONLY (P4-3): the ``*_active`` gauges go
NEGATIVE on this testbed (pfcp_sessions_active = -8) and are never used for a trip.
A negative counter diff (NF restart) reseeds baseline instead of signalling.

Per-NF metric map (live-confirmed IPs):
  SMF 10.50.0.4:9090 — s5c_rx_deletesession (PFCP session delete), *_parse_failed
  UPF 10.50.0.7:9090 — fivegs_ep_n3_gtp_in/outdatapktn3upf (N3 data-plane volume)
  MME 10.50.0.2:9090 — enb/enb_ue/mme_session (sparse)

httpx is a network client, not a subprocess, so this collector does not use the
Backend (불변식2. concerns only subprocess side effects).
"""
from __future__ import annotations

from typing import Optional

from .base import BaseCollector

# NF -> (address, [counter metric names to watch]) ; gauges deliberately excluded.
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

# which counter -> defense metric name + domain (thresholds.yaml). ONLY the
# s5c deletesession/parse-failed family maps to the PFCP trip signal.
_SIGNAL_MAP: dict[str, tuple[str, str]] = {
    "s5c_rx_deletesession": ("PFCP_Delete_Attempt", "session_network"),
    "s5c_rx_parse_failed": ("PFCP_Delete_Attempt", "session_network"),
    "gtp_node_s5c_rx_parse_failed": ("PFCP_Delete_Attempt", "session_network"),
    "gtp_new_node_failed": ("PFCP_Delete_Attempt", "session_network"),
}

# non-trip observability counters: emitted under a metric name that is NOT in
# D.METRICS (compute_trust -> 0 trust contribution) and pinned to band="normal"
# so correlate never trips on them (band gate at correlate.py). UPF N3 data-plane
# volume is HIGH-rate normal traffic; it must never be fabricated into a PFCP
# danger signal (self-DoS guard, audit row G).
_NONTRIP_MAP: dict[str, str] = {
    "fivegs_ep_n3_gtp_indatapktn3upf": "N3_Data_Volume",
    "fivegs_ep_n3_gtp_outdatapktn3upf": "N3_Data_Volume",
}


def parse_prometheus(text: str) -> dict[str, float]:
    """Parse Prometheus text exposition. Aggregates all label-sets of a metric name
    by SUM (so per-peer series like ``m{addr="x"} 8`` collapse to the family total)."""
    out: dict[str, float] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # split "name{labels} value" or "name value"
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
    """Positive diff = signal; diff<0 (reset/restart) -> None (reseed baseline);
    first observation (prev is None) -> None (establish baseline, no signal)."""
    if prev is None:
        return None
    d = cur - prev
    if d < 0:
        return None                       # NF restart/reset -> reseed, not a signal
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
        self._prev: dict[str, float] = {}     # "nf:metric" -> last value

    def _fetch(self, addr: str) -> Optional[str]:
        try:
            import httpx  # local dep available
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
                # observability only: never fabricated into a PFCP trip.
                metric, domain, band = _NONTRIP_MAP[name], "session_network", "normal"
            else:
                continue        # unknown counter: skip, do NOT default to a PFCP trip
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
