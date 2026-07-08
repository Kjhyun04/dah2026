"""MmeLogTail — epc_mme docker-logs stdout tail: attach / IMSI events (P4-5).

Per DESIGN_DECISIONS P4-5, attach/IMSI/service-request observation uses the MME log as
the SINGLE source (the MME :9090 metrics are sparse — only enb/enb_ue/mme_session). Rogue-UE
attach detection (TM3) is therefore the MME-log tail. The EPC log parse discipline is shared
(``log_common``): ANSI-strip FIRST, then regex; the timestamp format ``MM/DD HH:MM:SS.mmm``
is fixed via ``parse_epc_ts``.

This is the P4-5 member of the parser set that ``tests/verify_parsers.py`` exercises. Pure
observation, state-change-0; the ``docker logs`` read is routed through the safe-exec Backend
(불변식②) exactly like the SMF/Mongo log collectors. A dry/mock Backend yields no lines
(the collector simply emits nothing).

Boundaries: no docker sdk import, no sock/proxy URL literal here (verify_grep0). Null-safe:
``parse_mme_line(None)`` -> None (never an ``re.search(None)`` crash).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .base import BaseCollector
from .log_common import ansi_strip, parse_epc_ts

# Open5GS MME lines carry the IMSI as either ``IMSI[001010000000001]`` or the
# ``IMSI[imsi-001010000000001]`` NAI form; accept both. 15-digit IMSI (6..15 to be lenient).
_IMSI_RE = re.compile(r"IMSI\[(?:imsi-)?(\d{6,15})\]")

# event-kind keywords (attach/identity/auth/service/detach). First hit wins; else "event".
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
    ts: str = ""          # raw MM/DD HH:MM:SS.mmm token (P4-5), best-effort


def _kind_for(line: str) -> str:
    for token, kind in _KIND_KEYWORDS:
        if token in line:
            return kind
    return "event"


def parse_mme_line(raw: str) -> Optional[AttachEvent]:
    """Parse ONE MME log line into an AttachEvent (IMSI + kind + ts), or None.

    ANSI-strips first (P4-5). Null-safe over None/"" (returns None; no re.search(None)).
    A line is an event only if it carries an IMSI token; the kind is a best-effort label
    from the attach/identity/service/auth keyword vocabulary."""
    line = ansi_strip(raw)
    if not line:
        return None
    m = _IMSI_RE.search(line)
    if not m:
        return None
    return AttachEvent(imsi=m.group(1), kind=_kind_for(line), ts=parse_epc_ts(line))


def _docker_logs_argv(container: str, since_s: int) -> list[str]:
    # bounded --since window (NOT -f) so the daemon read stays deterministic, same as the
    # SMF/Mongo log collectors. The read-only logs GET is the sock-proxy whitelisted path.
    return ["docker", "logs", "--since", f"{since_s}s", container]


class MmeLogTail(BaseCollector):
    """Out-of-graph daemon: tails ``docker logs epc_mme`` and emits attach/IMSI events as
    identity-domain evidence (P4-5). Rogue-UE attach classification (TM3) is left to the
    correlation layer; this collector is pure attach-event observation.

    Not part of the default 6-collector set (opt-in EPC log-tail, P1-Q3); subprocess goes
    through the safe-exec Backend only (불변식②). A dry/mock backend yields no lines."""
    source_id = "mme_log"
    domain = "identity_access"

    def __init__(self, *args, container: str = "epc_mme", since_s: int = 3, **kw):
        super().__init__(*args, **kw)
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
                ev = parse_mme_line(ln)
                if ev is None:
                    continue
                key = f"{ev.kind}:{ev.imsi}:{ev.ts}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                # attach is the TM3 rogue-UE observation surface; emit as low-band identity
                # evidence (classification is deferred to correlate). Other kinds are context.
                if ev.kind == "attach":
                    payloads.append({
                        "metric": "UE_Attach", "value": 1, "band": "warning",
                        "domain": "identity_access", "channel": "nas_log",
                        "confidence": 0.85, "imsi": ev.imsi,
                    })
        if len(self._seen) > 4096:
            self._seen.clear()
        return payloads
