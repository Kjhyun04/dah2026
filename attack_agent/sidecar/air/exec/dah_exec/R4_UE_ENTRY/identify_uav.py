#!/usr/bin/env python3
"""identify_uav — 5762 HEARTBEAT 1개 읽어 {sysid,type} JSON (RO · 14 §2 확정 측정).

resolve.TargetResolver.verify_uav 의 baked 식별 프로브(default identify_script 경로).
argv[1] = pymavlink 연결 문자열(예: `tcp:10.45.0.2:5762`). 비밀 없음.

출력(stdout, resolve.parse_heartbeat 수용 키):
  {"sysid": <int>, "type": <int>} | {} (미수신) | {"error": "<ExcType>"} (연결 실패)
★ read-only: HEARTBEAT 1개만 읽고 즉시 close. 명령 송신 0. 5762 단일연결.
"""
from __future__ import annotations

import json
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({}))
        return 2
    conn = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    try:
        from pymavlink import mavutil
    except Exception as e:
        print(json.dumps({"error": f"import:{type(e).__name__}"}))
        return 1
    m = None
    try:
        m = mavutil.mavlink_connection(conn)
        hb = m.wait_heartbeat(timeout=timeout)
    except Exception as e:
        print(json.dumps({"error": type(e).__name__}))
        return 1
    finally:
        if m is not None:
            try:
                m.close()
            except Exception:
                pass
    if hb is None:
        print(json.dumps({}))
        return 1
    print(json.dumps({"sysid": hb.get_srcSystem(), "type": int(hb.type)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
