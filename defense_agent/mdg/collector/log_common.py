"""log_common — 공유 EPC (Open5GS) log-tail 유틸리티 (P4-5).

SMF/MME/UPF 컨테이너는 stdout으로 ANSI 컬러 로그 줄을 내보낸다(라이브 확인: SMF
session 줄이 컬러 escape를 담고 있음). 모든 EPC 로그 파서는 regex 적용 전에 반드시
ansi_strip해야 한다 — 그렇지 않으면 컬러 escape가 regex가 기대하는 토큰 사이에 끼어
매치가 조용히 실패한다 (P4-1/P4-5).

순수 문자열 헬퍼만: subprocess 없음, docker sdk 없음, sock/proxy 리터럴 없음.
"""
from __future__ import annotations

import re

# CSI SGR 컬러 시퀀스: ESC [ <params> m  (Open5GS가 레벨 컬러링에 사용).
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Open5GS 로그 타임스탬프 접두, 예: "07/07 03:39:36.461" (MM/DD HH:MM:SS.mmm) — P4-5.
EPC_TS_RE = re.compile(r"(?P<mon>\d{2})/(?P<day>\d{2})\s+"
                       r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\.(?P<ms>\d{3})")


def ansi_strip(s: str) -> str:
    """ANSI SGR 컬러 escape 제거. 모든 EPC-로그 regex 이전에 반드시 실행 (P4-5)."""
    if not s:
        return s
    return _ANSI_RE.sub("", s)


def parse_epc_ts(line: str) -> str:
    """존재하면 원시 MM/DD HH:MM:SS.mmm 타임스탬프 토큰을 반환, 없으면 "".

    Null-safe(verify_parsers 계약): None/"" -> "" (EPC_TS_RE.search(None)에서
    TypeError 없음), 따라서 SMF/MME 파스 경로는 None/빈값에 대해 전역적(total)이다.
    ansi_strip은 None을 변경 없이 반환하므로(그 if not s 가드), None 원시 줄은
    여기 None으로 도달한다; 여기서 가드하여 EPC-로그 파스 경로 전체를 total로 유지."""
    if not line:
        return ""
    m = EPC_TS_RE.search(line)
    return m.group(0) if m else ""
