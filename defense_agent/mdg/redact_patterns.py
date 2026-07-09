"""redact_patterns (PS-3) — secret-pattern 목록의 유일(SINGLE) 원천.

두 redact 경계가 이 하나의 목록을 import 하므로 서로 어긋날 수 없다:
  - 기록 시점 scrub   (core.driver._scrub_str / redact)      — 잔여 secret 을 제거
  - viewer 로드 시점 scan (viewer.app.scan_secrets)            — 잔여물이 있으면 fail-closed

이 모듈은 의도적으로 의존성이 없으며(stdlib ``re`` 만 사용) mdg.* 에서 아무것도 import 하지 않는다.
특히 mdg.core 하위가 아니므로 management-plane Viewer 가 결정 경로를 끌어들이지 않고 import 할 수 있고,
grep0 Verifier 경계도 영향을 받지 않는다.

4개 class 가 다루는 대상: Anthropic 키(sk-ant-…), 일반 sk- 키, api_key/token/hmac/sign_key
할당, 그리고 MDG_CANARY_* 유출 canary(LLM/OP/HMAC).
"""
from __future__ import annotations

import re

# 한 번만 compile 되어 모든 redact/scan 경계가 공유. 순서는 무의미(전부 적용됨).
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"(?i)(api[_-]?key|token|hmac|sign[_-]?key)\s*[=:]\s*[^\s\"']+"),
    re.compile(r"MDG_CANARY_(?:LLM|OP|HMAC)"),
]

__all__ = ["SECRET_PATTERNS"]
