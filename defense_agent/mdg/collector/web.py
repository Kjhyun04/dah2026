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


def _iptables_argv(netns_prefix: list[str], chain: str) -> list[str]:
    """Read-only listing with EXACT counters. Separate short flags (-n -v -x -L) so
    backend.is_read_only_argv recognizes the -L listing verb and no mutating verb is present."""
    return list(netns_prefix) + ["iptables", "-n", "-v", "-x", "-L", chain]


def parse_dah5762_syn_count(stdout: str) -> int:
    """SYN packet counter (pkts, col0) of the DAH5762 chain's SYN-counting rule, identified by
    the ``DAH5762_SYN`` marker (NFLOG --nflog-prefix or --comment). Chain absent / read failed
    -> -1 (inert). Chain present but no SYN row yet -> 0. pkts is always col0 under ``-x``."""
    if not stdout:
        return -1                                          # chain absent / read failed -> inert
    for ln in stdout.splitlines():
        if "DAH5762_SYN" in ln:                            # the SYN counting rule
            parts = ln.split()
            if parts and parts[0].isdigit():
                return int(parts[0])                       # pkts col0 (exact, -x)
    return 0 if "DAH5762" in stdout else -1                # chain present but no SYN row -> 0


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
        self._syn_seen = 0                                # DAH5762 SYN counter high-water (delta gate)

    def collect(self) -> list[dict]:
        if self.backend is None or self.netns_prefix is None:
            return []                                      # inert: unresolved netns target
        out: list[dict] = []

        # (1) sustained-connection path — ss ESTAB snapshot. Carries the peer IP (droppable
        #     attribution target for a real nsenter DROP recovery on a held backdoor).
        argv = _ss_argv(self.netns_prefix, self.port)
        with self._sem:                                    # pool=1 serialization
            res = self.backend.run(ExecRequest(argv=argv, timeout_s=5.0, read_only=True))
        if not res.dry_run and parse_ss_established(res.stdout, self.port) > 0:
            peer = parse_ss_peer(res.stdout, self.port)    # "" on parse failure (fail-closed)
            out.append({
                "metric": "Port_5762_State", "value": "ESTAB_PRESENT", "band": "danger",
                "domain": "command", "channel": "port_5762_read", "confidence": 0.90,
                "source": peer,                            # peer IP = attribution selector (droppable)
            })

        # (2) brief-connection path — DAH5762 SYN counter (deterministic; catches sub-poll
        #     connections the 5s ss snapshot misses). Delta-gated: only a NEW SYN since last
        #     poll emits. source='' (aggregate counter has no peer) => detection-only — a brief
        #     conn is already gone so nothing to DROP, but the pipeline still reaches orient/
        #     decide (LLM engages). Emitted only when ss did NOT already flag (prefer peer row).
        cargv = _iptables_argv(self.netns_prefix, "DAH5762")
        with self._sem:
            cres = self.backend.run(ExecRequest(argv=cargv, timeout_s=5.0, read_only=True))
        if not cres.dry_run:
            cnt = parse_dah5762_syn_count(cres.stdout)
            if cnt >= 0:
                if cnt < self._syn_seen:                   # counter reset (testbed/netns restart)
                    self._syn_seen = 0
                if cnt > self._syn_seen:
                    self._syn_seen = cnt
                    if not out:
                        out.append({
                            "metric": "Port_5762_State", "value": "ESTAB_PRESENT", "band": "danger",
                            "domain": "command", "channel": "port_5762_syn_count", "confidence": 0.90,
                            "source": "",                  # aggregate counter -> no droppable peer
                        })
        return out
