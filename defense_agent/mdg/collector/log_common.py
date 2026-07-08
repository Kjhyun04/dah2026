"""log_common — shared EPC (Open5GS) log-tail utilities (P4-5).

The SMF/MME/UPF containers emit ANSI-coloured log lines to stdout (live-confirmed:
the SMF session lines carry colour escapes). Every EPC log parser MUST ansi_strip
BEFORE applying its regex — without it the colour escapes sit between the tokens the
regex expects and the match fails silently (P4-1/P4-5).

Pure string helpers only: no subprocess, no docker sdk, no sock/proxy literal.
"""
from __future__ import annotations

import re

# CSI SGR colour sequences: ESC [ <params> m  (Open5GS uses these for level colouring).
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Open5GS log timestamp prefix, e.g. "07/07 03:39:36.461" (MM/DD HH:MM:SS.mmm) — P4-5.
EPC_TS_RE = re.compile(r"(?P<mon>\d{2})/(?P<day>\d{2})\s+"
                       r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\.(?P<ms>\d{3})")


def ansi_strip(s: str) -> str:
    """Remove ANSI SGR colour escapes. MUST run before any EPC-log regex (P4-5)."""
    if not s:
        return s
    return _ANSI_RE.sub("", s)


def parse_epc_ts(line: str) -> str:
    """Return the raw ``MM/DD HH:MM:SS.mmm`` timestamp token if present, else "".

    Null-safe (verify_parsers contract): None/"" -> "" (never a TypeError from
    ``EPC_TS_RE.search(None)``), so the SMF/MME parse path is total over None/empty.
    ``ansi_strip`` returns None unchanged (its ``if not s`` guard), so a None raw line
    reaches here as None; guarding here keeps the whole EPC-log parse path total."""
    if not line:
        return ""
    m = EPC_TS_RE.search(line)
    return m.group(0) if m else ""
