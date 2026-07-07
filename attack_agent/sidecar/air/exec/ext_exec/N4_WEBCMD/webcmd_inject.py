#!/usr/bin/env python3
"""webcmd (INJECT): call unauth web command endpoint with requested mode."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "http://172.30.0.20:8080/api/cmd"


def emit(accepted: bool, blocked_by: str | None, mode: int | None = None) -> None:
    out = {
        "accepted": bool(accepted),
        "blocked_by": blocked_by,
        "effect": ({"mode": str(mode)} if (accepted and mode is not None) else {}),
        "signed": None,
    }
    print(json.dumps(out))


def parse_args(argv: list[str]) -> tuple[str, int | None]:
    toks: list[str] = []
    for a in argv[1:]:
        toks.extend(str(a).split())
    endpoint: str | None = None
    mode: int | None = None
    i = 0
    while i < len(toks):
        if toks[i] == "mode" and i + 1 < len(toks):
            try:
                mode = int(toks[i + 1])
            except ValueError:
                mode = None
            i += 2
            continue
        if endpoint is None:
            endpoint = toks[i]
        i += 1

    if not endpoint:
        return DEFAULT_URL, mode
    if "://" not in endpoint:
        endpoint = f"http://{endpoint}"
    u = urllib.parse.urlparse(endpoint)
    scheme = u.scheme or "http"
    host = u.netloc or u.path
    path = u.path if u.netloc else ""
    if not path:
        path = "/api/cmd"
    if ":" not in host:
        host = f"{host}:8080"
    return urllib.parse.urlunparse((scheme, host, path, "", "", "")), mode


def request_mode(url: str, mode: int) -> tuple[bool, int]:
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
    url, mode = parse_args(sys.argv)
    if mode is None:
        emit(False, "no_effect")
        return
    ok, code = request_mode(url, mode)
    if ok:
        emit(True, None, mode)
        return
    if code in (401, 403):
        emit(False, "auth")
    else:
        emit(False, "no_effect")


if __name__ == "__main__":
    main()
