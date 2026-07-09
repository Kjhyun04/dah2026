"""SmfSessionTable — IMSI <-> dynamic tun-IP session table via SMF log tail (P4-1/P4-4).

FEASIBILITY §2 ("IMSI join impossible -> time-window only") is CORRECTED here: the
Open5GS SMF log actually emits the IMSI<->assigned-IP binding on session create/delete,
so a live tail of ``docker logs epc_smf`` stdout yields a bidirectional session table.
That table is the SINGLE join key for three things (P4-1):

  1. command_source vantage attribution (which IMSI owns a UE-pool source IP),
  2. ``docker pause`` target resolution — PRIMARY layer-1 path (P2-Q1): UE-pool source IP
     -> IMSI (this table) -> container (static ``spec.imsi_container_map`` boot constant),
     which needs no exec/nsenter. The live tun-scan reverse map is the SECONDARY ground-
     truth cross-check (C-3 / resolve.reverse_container_for_ip layer 2), not the primary.
  3. cross-plane correlation join (metric delete diff + log delete event, P4-4).

Sources (A-1): mongo ``subscribers`` holds only the IMSI (no dynamic IP); the tun_srsue
IP is absent from ``docker inspect``. The SMF log is the ONLY source of the binding.

Parsing discipline: ANSI-strip FIRST (P4-5) — the live lines are colour-escaped, and
skipping the strip makes every regex miss. Pure observation, zero state change.
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

# Portability (GATE2, finding P2-3): the regexes capture ANY IPv4 and the pool
# membership is CIDR-checked against ``spec.ue_pool_cidr`` — NOT a duplicated "10.45"
# literal. On an instance with a different UE pool the parser follows config rather than
# silently ceasing to match. Default mirrors config.INPUT_SPEC (10.45.0.0/16) so the
# locked live-wire behaviour is unchanged.
_DEFAULT_POOL_CIDR: str = str(defaults.INPUT_SPEC.get("ue_pool_cidr") or "10.45.0.0/16")
_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
# Create: "... UE IMSI[001010000000001] ... IPv4[10.45.0.2] ..."  (P4-1 locked shape)
_CREATE_RE = re.compile(r"UE IMSI\[(\d+)\].*?IPv4\[" + _IPV4 + r"\]")
# Delete: "Removed Session: UE IMSI:[imsi-001..] ... IPv4:[10.45.0.3]"  (P4-1 locked shape)
_REMOVE_RE = re.compile(r"Removed Session: UE IMSI:\[imsi-(\d+)\].*?IPv4:\[" + _IPV4 + r"\]")


def _ip_in_pool(ip: str, cidr: str) -> bool:
    """CIDR membership (config-driven pool filter), total over junk input."""
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
    ts: str = ""       # raw MM/DD HH:MM:SS.mmm token (P4-5), best-effort


def parse_smf_line(raw: str, pool_cidr: str = _DEFAULT_POOL_CIDR) -> Optional[SessionEvent]:
    """Parse ONE SMF log line into a SessionEvent, or None. ANSI-strips first (P4-5).

    Delete is checked before create because a delete line does not match the create
    regex, but keeping the order explicit documents the two distinct wire formats
    (``IMSI[..] IPv4[..]`` on create vs ``UE IMSI:[imsi-..] IPv4:[..]`` on remove).

    Null-safe: None/"" raw -> None (no ``re.search(None)`` crash). Portability: only
    sessions whose IPv4 falls inside ``pool_cidr`` (config ``ue_pool_cidr``) are tracked,
    so a non-pool line is ignored the same way the old hardcoded ``10.45`` prefix did —
    but now following config instead of a duplicated literal (finding P2-3).
    """
    line = ansi_strip(raw)
    if not line:                          # null-safe: ansi_strip(None)->None; don't feed re.search(None)
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
    """Thread-safe bidirectional IMSI<->tun-IP map fed by SMF log events.

    A collector daemon feeds lines from another thread while ``sense``/``correlate``
    read snapshots, so all mutation/lookup is guarded by a lock. ``recent`` retains a
    bounded ring of the latest delete events for the P4-4 time-window join.
    """

    def __init__(self, recent_max: int = 256, pool_cidr: str = _DEFAULT_POOL_CIDR):
        self._lock = threading.Lock()
        self.imsi_to_ip: dict[str, str] = {}
        self.ip_to_imsi: dict[str, str] = {}
        self.recent: list[SessionEvent] = []       # bounded (both add & remove)
        self._recent_max = recent_max
        self.pool_cidr = pool_cidr or _DEFAULT_POOL_CIDR   # config-driven pool filter (finding P2-3)

    # -- mutation ---------------------------------------------------------- #
    def add(self, imsi: str, ip: str) -> None:
        with self._lock:
            # a re-used IP must not keep pointing at a stale IMSI: evict old binding
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
        """Parse + apply one log line. Returns the event (for the caller to emit/join)."""
        ev = parse_smf_line(raw, self.pool_cidr)
        if ev is None:
            return None
        if ev.op == "add":
            self.add(ev.imsi, ev.ip)
        else:
            self.remove(ev.imsi, ev.ip)
        with self._lock:
            self.recent.append(ev)
            if len(self.recent) > self._recent_max:       # bounded (DoS cap)
                self.recent = self.recent[-self._recent_max:]
        return ev

    # -- lookup (snapshot reads) ------------------------------------------ #
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
        """Delete events for the P4-4 attribution join (metric diff + log delete).

        Pool membership is CIDR-checked against ``pool_cidr`` (default ``self.pool_cidr``,
        config ``ue_pool_cidr``) rather than a hardcoded ``10.45`` prefix (finding P2-3)."""
        cidr = pool_cidr or self.pool_cidr
        with self._lock:
            return [e for e in self.recent if e.op == "remove" and _ip_in_pool(e.ip, cidr)]


def _docker_logs_argv(container: str, since_s: int) -> list[str]:
    # bounded --since window (NOT -f) so the daemon's read stays deterministic, same as
    # MongoLogCollector. The read-only logs GET is the sock-proxy whitelisted path (PS-1).
    return ["docker", "logs", "--since", f"{since_s}s", container]


class SmfSessionCollector(BaseCollector):
    """Out-of-graph daemon: tails ``docker logs epc_smf`` and maintains a shared
    SmfSessionTable, emitting session add/remove as evidence for the P4-4 join.

    Wired opt-in (not part of the default 6-collector set) via ``build_epc_collectors``;
    the table it maintains is shared with ``correlate`` (join) and target ``resolve``
    (pause reverse-map). Subprocess (docker logs) goes through the safe-exec Backend
    only (불변식2.); a dry/mock backend yields no live lines (table simply stays empty).
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
        self._seen: set[str] = set()               # dedupe within the --since window

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
                # only session REMOVE is a defensive attribution signal (P4-4); ADD is
                # table upkeep. Emit removes as low-band attribution evidence.
                if ev.op == "remove":
                    payloads.append({
                        "metric": "PFCP_Delete_Attempt", "value": 1, "band": "warning",
                        "domain": "session_network", "channel": "nas_log",
                        "confidence": 0.85, "imsi": ev.imsi, "ip": ev.ip,
                    })
        if len(self._seen) > 4096:
            self._seen.clear()
        return payloads
