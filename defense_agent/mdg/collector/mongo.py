"""MongoLogCollector — epc_mongo docker-logs stdout JSON tail (A-2).

Mongo has no log file on this testbed (/var/log/mongodb/mongod.log absent), so the
only source is ``docker logs epc_mongo`` stdout, which is line-delimited JSON. Access
verdict (A-2):
  id == 22943 ("Connection accepted") + attr.remote in the RAN CIDR (10.44.0.0/16) =
  anomalous DB access from the cellular/attacker side -> DB_Access (identity_access).
  id == 22944 ("Connection ended") is ignored.

The tail command is issued through the safe-exec Backend (불변식②). Only a bounded
``--since`` window is read each cycle (not -f) so the sync drain stays deterministic.

PS-1 resolution (P1 panel, locked): the sock-proxy whitelist gains a read-only
``GET /containers/{id}/logs`` endpoint (Option A) — NOT a log-shipping sidecar. inspect
is already whitelisted and exposes strictly more than stdout, so a read-only logs GET does
not widen the trust boundary. ``docker logs`` therefore stays the mechanism (routed at the
proxy); this same path serves the deferred SMF/MME log collectors. The parser itself is
socket-independent and unit-tested.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Optional

from ..config import defaults
from .base import BaseCollector

_ID_ACCEPTED = 22943
_ID_ENDED = 22944
# Portability (finding P2-3): the RAN/cellular side (anomalous for DB access) is
# CIDR-checked against config ``ran_cidr`` instead of a hardcoded ``^10\.44\.`` prefix,
# so the parser follows config on an instance with a different RAN CIDR. Default mirrors
# config.INPUT_SPEC (10.44.0.0/16) so the locked live-wire behaviour is unchanged.
_DEFAULT_RAN_CIDR: str = str(defaults.INPUT_SPEC.get("ran_cidr") or "10.44.0.0/16")


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    if not ip or not cidr:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def parse_mongo_line(line: str, ran_cidr: str = _DEFAULT_RAN_CIDR) -> Optional[dict]:
    """Return an access payload for an accepted connection from the RAN CIDR, else None.

    Null-safe: None/"" -> None. Portability: the anomalous-source test is a CIDR
    membership check against ``ran_cidr`` (config-driven), not a duplicated literal."""
    line = (line or "").strip()
    if not line or "22943" not in line:
        return None
    try:
        obj = json.loads(line)
    except (ValueError, json.JSONDecodeError):
        return None
    if obj.get("id") != _ID_ACCEPTED:
        return None
    remote = str(obj.get("attr", {}).get("remote", ""))
    host = remote.split(":")[0]
    if not _ip_in_cidr(host, ran_cidr):
        return None                          # sgi/normal side -> not a signal
    return {
        "metric": "DB_Access", "value": 1, "band": "warning",
        "domain": "identity_access", "channel": "mongo_conn_log",
        "confidence": 0.60, "remote": remote,
    }


def _docker_logs_argv(container: str, since_s: int) -> list[str]:
    return ["docker", "logs", "--since", f"{since_s}s", container]


class MongoLogCollector(BaseCollector):
    source_id = "mongo_log"
    domain = "identity_access"

    def __init__(self, *args, container: str = "epc_mongo", since_s: int = 3,
                 ran_cidr: str = _DEFAULT_RAN_CIDR,
                 dedupe_window_s: float = 60.0, **kw):
        super().__init__(*args, **kw)
        self.container = container
        self.since_s = since_s
        self.ran_cidr = ran_cidr or _DEFAULT_RAN_CIDR
        # dedupe is scoped to a COARSE time bucket, not the raw remote: a bare-remote
        # key permanently suppresses a re-connecting IP (a real repeated DB access from
        # the RAN side is masked forever until the 4096 cap flush). Bucketing by
        # ``floor(now / dedupe_window_s)`` keeps the intra-window overlap dedupe (the
        # same accept line seen across consecutive overlapping ``--since`` windows is
        # emitted once) while RE-EMITTING the same remote in a later window. The bucket
        # uses the collector's injected clock (BaseCollector.clock); no separate time
        # source. This is a detection-completeness fix and does NOT change any emitted
        # scalar (metric/value/band/domain/weight/confidence are untouched).
        self.dedupe_window_s = float(dedupe_window_s)
        self._seen: set[str] = set()          # {remote|bucket} within a rolling window

    def collect(self) -> list[dict]:
        res = self._observe(_docker_logs_argv(self.container, self.since_s))
        if res is None or res.dry_run:
            return []
        # one clock read per cycle -> a stable bucket for every line captured this cycle
        # (all lines in one drain share the bucket; ordering/among-line determinism kept).
        win = self.dedupe_window_s if self.dedupe_window_s > 0 else 1.0
        bucket = int(self.clock.now() // win)
        payloads: list[dict] = []
        # docker logs writes JSON to stdout; some builds emit on stderr — scan both.
        for chunk in (res.stdout, res.stderr):
            for ln in (chunk or "").splitlines():
                p = parse_mongo_line(ln, self.ran_cidr)
                if p is None:
                    continue
                key = f"{p.get('remote')}|{bucket}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                payloads.append(p)
        if len(self._seen) > 4096:            # bounded dedupe cache (DoS cap) — retained
            self._seen.clear()
        return payloads
