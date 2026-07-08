"""redact_patterns (PS-3) — the SINGLE source of the secret-pattern list.

Both redact boundaries import this one list so they cannot drift:
  - record-time scrub   (core.driver._scrub_str / redact)      — scrubs residual secrets
  - viewer load-time scan (viewer.app.scan_secrets)            — fails closed on residuals

This module is deliberately dependency-free (stdlib ``re`` only) and imports NOTHING from
mdg.* — in particular it is NOT under mdg.core, so the management-plane Viewer can import it
without pulling in the decision path, and the grep0 Verifier boundary is unaffected.

The 4 classes cover: Anthropic keys (sk-ant-…), generic sk- keys, api_key/token/hmac/sign_key
assignments, and the MDG_CANARY_* leak canaries (LLM/OP/HMAC).
"""
from __future__ import annotations

import re

# Compiled once, shared by every redact/scan boundary. Order is not significant (all applied).
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"(?i)(api[_-]?key|token|hmac|sign[_-]?key)\s*[=:]\s*[^\s\"']+"),
    re.compile(r"MDG_CANARY_(?:LLM|OP|HMAC)"),
]

__all__ = ["SECRET_PATTERNS"]
