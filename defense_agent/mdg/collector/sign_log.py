"""SignLogCollector — uav_proxy docker-logs signing drop-line tail (P3-Q2, §9-B).

The §9-B MAVLink2 uplink-signing enforcement lives in ``uav_proxy``. When an UNSIGNED
command is injected the proxy drops it and prints an authoritative drop line to stdout:

    [proxy] 서명검증 실패 -> SITL 차단 (누적 N)

That line is POSITIVE evidence that signing enforcement is ON (uav_proxy actually blocked
an unsigned command). This collector tails ``docker logs uav_proxy`` read-only (same
sock-proxy ``GET /containers/{id}/logs`` path as the SMF/MME/Mongo collectors) and emits a
derived ``Signing_Drop`` SensorEv that ``sense`` latches into ``world.signing`` = CONFIRMED_ON
(MONOTONIC; a drop line seen is the ONLY promotion trigger — silence never promotes, banner
alone never promotes: fail-safe asymmetry, P2-Q2).

Discipline (P3-Q2 lock):
  - band=normal / metric NOT in ``defaults.METRICS`` => the drop adds ZERO distrust
    (P3-Q4: a verify-fail DROP is defense SUCCESS, not a compromise — it must never fire the
    crit_floor). The cumulative counter is projected as a bare activity metric only.
  - secret-free (PS-3): only the derived cumulative integer is projected; the raw log line,
    cipher peer tuple, and any key material are NEVER placed on the envelope.
  - ANSI-strip FIRST (shared ``log_common.ansi_strip``) so colour escapes can never sit
    between the tokens the matcher expects.

Boundaries: subprocess (``docker logs``) issued ONLY through the safe-exec Backend (불변식2.);
no docker sdk import, no sock/proxy URL literal. Null-safe: ``parse_signing_line(None)`` -> None.
A dry/mock Backend yields no lines (the collector simply emits nothing — inert).
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseCollector
from .log_common import ansi_strip

# The drop line's stable markers (either substring identifies a verify-fail block event);
# the emoji/arrow are cosmetic and NOT relied on. ``누적 N`` carries the cumulative counter.
_DROP_MARKERS = ("서명검증 실패", "SITL 차단")
_CUM_RE = re.compile(r"누적\s*(\d+)")


def parse_signing_line(raw: str) -> Optional[dict]:
    """Return a derived Signing_Drop payload for a uav_proxy verify-fail drop line, else None.

    Null-safe (None/"" -> None). ANSI-strips first (P3-Q2). Positive-only: ONLY a drop line
    yields a payload — the absence of drops is never OFF evidence and yields None (silence≠OFF).
    Secret-free: projects only the cumulative counter (derived int), never the raw line."""
    line = ansi_strip(raw)
    if not line:
        return None
    if not any(mark in line for mark in _DROP_MARKERS):
        return None
    m = _CUM_RE.search(line)
    cumulative = int(m.group(1)) if m else 1
    return {
        # metric is deliberately absent from defaults.METRICS -> ZERO trust contribution
        # (P3-Q4: a block is defense success, not distrust). band=normal reinforces this.
        "metric": "Signing_Drop", "value": cumulative, "band": "normal",
        "domain": "command", "channel": "uav_proxy_signlog",
        "confidence": 0.9, "source": "uav_proxy",
    }


def _docker_logs_argv(container: str, since_s: int) -> list[str]:
    # bounded --since window (NOT -f) so the daemon read stays deterministic, exactly like
    # the SMF/MME/Mongo log collectors. read-only logs GET is the sock-proxy whitelisted path.
    return ["docker", "logs", "--since", f"{since_s}s", container]


class SignLogCollector(BaseCollector):
    """Out-of-graph daemon: tails ``docker logs uav_proxy`` and emits the §9-B signing
    drop-line as command-domain evidence (P3-Q2). The 6+1 collector; subprocess goes through
    the safe-exec Backend only (불변식2.). A dry/mock backend yields no lines (inert)."""
    source_id = "uav_signlog"
    domain = "command"

    def __init__(self, *args, container: str = "uav_proxy", since_s: int = 3,
                 dedupe_window_s: float = 60.0, **kw):
        super().__init__(*args, **kw)
        self.container = container
        self.since_s = since_s
        # Coarse-bucket dedupe (MongoLogCollector precedent): the same cumulative counter seen
        # across consecutive overlapping ``--since`` windows is emitted once, while a later
        # window RE-EMITS (so the latch/activity signal is not permanently suppressed and a
        # counter reset after a proxy restart is not masked forever). Uses the injected clock.
        self.dedupe_window_s = float(dedupe_window_s)
        self._seen: set[str] = set()

    def collect(self) -> list[dict]:
        res = self._observe(_docker_logs_argv(self.container, self.since_s))
        if res is None or res.dry_run:
            return []
        win = self.dedupe_window_s if self.dedupe_window_s > 0 else 1.0
        bucket = int(self.clock.now() // win)
        payloads: list[dict] = []
        # docker logs writes to stdout; some builds emit on stderr — scan both.
        for chunk in (res.stdout, res.stderr):
            for ln in (chunk or "").splitlines():
                p = parse_signing_line(ln)
                if p is None:
                    continue
                key = f"{p.get('value')}|{bucket}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                payloads.append(p)
        if len(self._seen) > 4096:            # bounded dedupe cache (DoS cap)
            self._seen.clear()
        return payloads
