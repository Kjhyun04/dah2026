#!/usr/bin/env python3
"""signkey_leak — 노출된 MAVLink 서명키 회수 (COLLECT · RO · C계층 · H5).

container_access("sgi") 발판에서 노출존에 마운트된 서명키(/sign.key)를 read-only 1회 읽어
CollectResult 계약을 낸다. 상태변경 0(파일 미변경·명령 송신 0). 원문 키는 stdout/로그/argv 에
절대 미노출 — values.sign_key 는 마스킹(앞4문자+…). 실제 키 값은 vault(env)→forge_sign stdin(R6).

argv[1] = (선택) 키 경로 override. 기본 /sign.key. 크기 상한(64KiB)로 폭주 방지.
출력: {"artifacts": ["sign_key"], "values": {"sign_key": "<masked>"}} | {"artifacts": [], "values": {}}
"""
from __future__ import annotations

import json
import sys

DEFAULT_KEY_PATH = "/sign.key"
_MAX = 64 * 1024


def _mask(v: str) -> str:
    return (v[:4] + "…") if len(v) > 4 else "…"


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_KEY_PATH
    try:
        with open(path, "rb") as f:
            key = f.read(_MAX).decode("utf-8", "replace").strip()
    except Exception:
        print(json.dumps({"artifacts": [], "values": {}})); return 1
    if not key:
        print(json.dumps({"artifacts": [], "values": {}})); return 1
    print(json.dumps({"artifacts": ["sign_key"], "values": {"sign_key": _mask(key)}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
