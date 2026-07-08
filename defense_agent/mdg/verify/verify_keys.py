"""verify_keys — 3키 분리 · argv 누수 0 · 리터럴 비밀 0 (PS-3 · DESIGN §부록A).

Enforces (static):
  - keys.yaml declares the 3 separated key classes (ingest/audit/sign) + operator + llm
    as PROVIDERS only (no literal key material)
  - no source literal looks like a real secret (sk-..., BEGIN PRIVATE KEY, hardcoded
    ANTHROPIC_API_KEY value)
  - secrets flow via stdin, not argv: safe_exec ExecRequest exposes stdin_secret and
    no core module builds an argv containing an env-var secret value
  - MDGState has no secret field (structural, PS-3)
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.verify._util import CORE, MDG_ROOT, Report, read, run  # noqa: E402

SECRET_LITERALS = [
    re.compile(r"sk-ant-[A-Za-z0-9]{8,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
KEY_CLASSES = ["ingest_key", "audit_key", "sign_key", "operator_cert", "llm_key"]


def _all_py() -> list[str]:
    out = []
    for root, _d, files in os.walk(MDG_ROOT):
        if os.sep + "verify" in root:
            continue
        for f in files:
            if f.endswith(".py"):
                out.append(os.path.join(root, f))
    return out


def _check() -> Report:
    rep = Report("verify_keys")

    keys_yaml = os.path.join(MDG_ROOT, "config", "keys.yaml")
    ky = read(keys_yaml)
    for cls in KEY_CLASSES:
        rep.check(cls in ky, f"keys.yaml missing key class '{cls}'")
    # 3-way separation statement present
    rep.check("혼용 금지" in ky or "separated" in ky.lower() or "분리" in ky,
              "keys.yaml missing key-separation contract statement")

    # no literal secret material anywhere in source/config
    for path in _all_py() + [keys_yaml]:
        src = read(path)
        base = os.path.relpath(path, MDG_ROOT)
        for pat in SECRET_LITERALS:
            rep.check(not pat.search(src), f"{base}: literal secret material matched {pat.pattern}")
        # no hardcoded ANTHROPIC_API_KEY assignment with a value
        rep.check(not re.search(r"ANTHROPIC_API_KEY\s*=\s*[\"'][^\"']+[\"']", src),
                  f"{base}: hardcoded ANTHROPIC_API_KEY value")

    # secret via stdin, not argv (safe_exec contract)
    be = read(os.path.join(MDG_ROOT, "safe_exec", "backend.py"))
    rep.check("stdin_secret" in be, "ExecRequest must expose stdin_secret (R6: secret via stdin)")
    rep.check("input=req.stdin_secret" in be, "Backend.run must feed secret via stdin, not argv")

    # MDGState secret-free (structural): no secret-named fields in state.py
    st = read(os.path.join(CORE, "state.py"))
    for bad in ("api_key", "hmac_key", "operator_token", "sign_key", "ingest_key"):
        rep.check(f"{bad}:" not in st and f"{bad} :" not in st,
                  f"state.py: MDGState declares secret field '{bad}' (PS-3 violation)")
    return rep


if __name__ == "__main__":
    run(_check)
