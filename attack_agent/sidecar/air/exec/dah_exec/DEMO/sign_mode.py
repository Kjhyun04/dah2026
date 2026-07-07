#!/usr/bin/env python3
"""forceland (INJECT): guarded LAND command through web endpoint."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_URL = os.environ.get("WEB_CMD_URL", "http://172.30.0.20:8080/api/cmd")
CONFIRM_ENV = os.environ.get("FORCELAND_CONFIRM", "0").lower() in {"1", "true", "yes", "on"}


def emit(accepted: bool, blocked_by: str | None, mode: int | None = None) -> None:
    out = {
        "accepted": bool(accepted),
        "blocked_by": blocked_by,
        "effect": ({"mode": str(mode)} if (accepted and mode is not None) else {}),
        "signed": None,
    }
    print(json.dumps(out))


def parse_mode(argv: list[str]) -> int | None:
    toks: list[str] = []
    for a in argv[1:]:
        toks.extend(str(a).split())
    i = 0
    mode: int | None = 9
    while i < len(toks):
        if toks[i] == "mode" and i + 1 < len(toks):
            try:
                mode = int(toks[i + 1])
            except ValueError:
                mode = None
            i += 2
            continue
        i += 1
    return mode


def post_mode(url: str, mode: int) -> tuple[bool, int]:
    payload = json.dumps({"mode": mode}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            code = int(resp.getcode() or 0)
            return 200 <= code < 300, code
    except urllib.error.HTTPError as e:
        return False, int(e.code)
    except Exception:
        return False, 0


def main() -> None:
    mode = parse_mode(sys.argv)
    if mode != 9:
        emit(False, "baseline")
        return
    if not CONFIRM_ENV:
        # Extra script-level safety even if orchestrator HITL gate is enabled.
        emit(False, "baseline")
        return

    ok, code = post_mode(DEFAULT_URL, 9)
    if ok:
        emit(True, None, 9)
        return
    if code in (401, 403):
        emit(False, "auth")
    else:
        emit(False, "no_effect")


if __name__ == "__main__":
    main()
