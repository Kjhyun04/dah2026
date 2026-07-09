#!/usr/bin/env python3
"""naive — 대조군(baseline) INJECT (04 registry: Cond(when=NEVER, else_blocked=BASELINE)).

키·서명·ARIA 봉투 없이 암호문 포트(gcs14555)에 평문 MAVLink SET_MODE 를 직접 발신.
암호/서명 계층이 무인증 직접주입을 **폐기** → 자동조종에 절대 도달하지 못함(무해·상태변경0).
Differential BlockProof 의 baseline: 관측결과와 무관하게 항상 accepted=False·blocked_by="baseline".

argv: '<ip>:<port> mode <m>' (동적 IP, 하드코딩 없음). 비행안전 모드만(4/5) 표기.
출력(stdout, 1줄): {"accepted": false, "signed": null, "blocked_by": "baseline", "effect": {}}
"""
from __future__ import annotations

import json
import sys
import time

FLIGHT_SAFE = (4, 5)


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
    return ep if ep.split(":", 1)[0] in ("tcp", "udp", "udpin", "udpout") else "udpout:" + ep


def main() -> int:
    # 대조군 계약: 무엇을 관측하든 baseline 차단(정의상). accepted 절대 아님.
    result = {"accepted": False, "signed": None, "blocked_by": "baseline", "effect": {}}
    endpoint, mode = parse_args(sys.argv)
    conn = conn_str(endpoint)
    if conn is None:
        print(json.dumps(result)); return 2
    try:
        from pymavlink import mavutil
    except Exception:
        print(json.dumps(result)); return 0
    m = None
    try:
        m = mavutil.mavlink_connection(conn, source_system=255, source_component=190)
        # 무인증 naive 직접주입(비행안전 모드만) -> 암호/서명 계층이 폐기.
        target_mode = mode if mode in FLIGHT_SAFE else 5
        for _ in range(3):
            m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
                                 mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            time.sleep(0.05)
        m.mav.set_mode_send(1, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, target_mode)
        time.sleep(0.5)
    except Exception:
        pass
    finally:
        if m is not None:
            try:
                m.close()
            except Exception:
                pass
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
