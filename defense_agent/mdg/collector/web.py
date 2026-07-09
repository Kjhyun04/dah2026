"""WebProbeCollector — 5762 ss-only, pool=1 (backdoor detection).

Joins the target container's netns and runs ``ss`` ONLY (ss-only constraint) to test
port 5762 (the ArduPilot backdoor). A single established connection on 5762 is the
danger signal (Port_5762_State = ESTAB_PRESENT); LISTEN with no ESTAB is normal.

pool=1 (G4): ss on 5762 is serialized through a dedicated PrioritySemaphore(1) so the
probe never fans out / contends. The probe issues exactly one ss invocation per cycle
through the safe-exec Backend (불변식2.).
"""
from __future__ import annotations

from typing import Optional

from ..safe_exec.backend import ExecRequest, PrioritySemaphore
from .base import BaseCollector


def _ss_argv(netns_prefix: list[str], port: int) -> list[str]:
    # -H no header, -t tcp, -a all, -n numeric; filter to the backdoor port.
    return list(netns_prefix) + [
        "ss", "-H", "-tan", "state", "established", f"( sport = :{port} or dport = :{port} )",
    ]


def parse_ss_established(stdout: str, port: int) -> int:
    """Count ESTAB rows referencing the port. ``ss -H`` already filters to established;
    we still confirm the port token to be robust against filter differences."""
    if not stdout:
        return 0
    tok = f":{port}"
    n = 0
    for ln in stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if tok in ln and ("ESTAB" in ln or "estab" in ln or ln[0].isdigit() or "." in ln.split()[0]):
            n += 1
    return n


def parse_ss_peer(stdout: str, port: int) -> str:
    """Extract the peer source IP from the first ESTAB row referencing ``port``.

    ss row (``ss -H -tan state established``): the ``state`` filter OMITS the State column,
    so the real row is 4 columns ``<Recv-Q> <Send-Q> <local>:5762 <peer>:<port>`` (NOT the
    5-column ``ESTAB 0 0 <local> <peer>`` form). Either way the local/peer ``addr:port`` are the
    LAST TWO whitespace tokens; the peer is the endpoint whose port is NOT ``port``. Returns the
    peer IP, or "" on any parse failure (fail-closed).
    """
    if not stdout:
        return ""
    tok = f":{port}"
    for ln in stdout.splitlines():
        ln = ln.strip()
        if not ln or tok not in ln:
            continue
        parts = ln.split()
        if len(parts) < 4:                   # Recv-Q Send-Q local peer (State column filtered out)
            continue
        # peer=parts[-1], local=parts[-2]; pick the endpoint whose port != port.
        for addr in (parts[-1], parts[-2]):
            ip, sep, p = addr.rpartition(":")
            if not sep or not ip or p == str(port):
                continue
            return ip.strip("[]")            # strip IPv6 brackets if present
    return ""


class WebProbeCollector(BaseCollector):
    source_id = "web_5762_probe"
    domain = "command"

    def __init__(self, *args, container: str = "uav_ue", port: int = 5762,
                 netns_prefix: Optional[list[str]] = None,
                 semaphore: Optional[PrioritySemaphore] = None, **kw):
        super().__init__(*args, **kw)
        self.port = port
        # None => inert (no ip-netns-exec fallback); canonical prefix injected by recon.
        self.netns_prefix = netns_prefix
        self._sem = semaphore or PrioritySemaphore(1)     # pool=1, ss-only

    def collect(self) -> list[dict]:
        if self.backend is None or self.netns_prefix is None:
            return []                                      # inert: unresolved netns target
        argv = _ss_argv(self.netns_prefix, self.port)
        with self._sem:                                    # pool=1 serialization
            res = self.backend.run(ExecRequest(argv=argv, timeout_s=5.0, read_only=True))
        if res.dry_run:
            return []
        estab = parse_ss_established(res.stdout, self.port)
        if estab <= 0:
            return []                                      # LISTEN_NO_ESTAB = normal
        peer = parse_ss_peer(res.stdout, self.port)        # "" on parse failure (fail-closed)
        return [{
            "metric": "Port_5762_State", "value": "ESTAB_PRESENT", "band": "danger",
            "domain": "command", "channel": "port_5762_read", "confidence": 0.90,
            "source": peer,                                # peer IP를 attribution selector로 사용
        }]
