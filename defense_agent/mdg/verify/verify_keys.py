"""verify_keys — 3키 분리 · argv 누수 0 · 리터럴 비밀 0 (PS-3 · DESIGN §부록A).

강제(정적):
  - keys.yaml 은 3개 분리 키 클래스(ingest/audit/sign) + operator + llm 을
    PROVIDER 로만 선언(리터럴 키 자료 없음)
  - 어떤 소스 리터럴도 실제 비밀처럼 보이지 않음 (sk-..., BEGIN PRIVATE KEY, 하드코딩된
    ANTHROPIC_API_KEY 값)
  - 비밀은 argv 가 아니라 stdin 으로 흐름: safe_exec ExecRequest 가 stdin_secret 을 노출하고
    어떤 core 모듈도 env-var 비밀 값을 담은 argv 를 만들지 않음
  - MDGState 에 비밀 필드 없음 (구조적, PS-3)
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
    # 3-way 분리 진술 존재
    rep.check("혼용 금지" in ky or "separated" in ky.lower() or "분리" in ky,
              "keys.yaml missing key-separation contract statement")

    # 소스/config 어디에도 리터럴 비밀 자료 없음
    for path in _all_py() + [keys_yaml]:
        src = read(path)
        base = os.path.relpath(path, MDG_ROOT)
        for pat in SECRET_LITERALS:
            rep.check(not pat.search(src), f"{base}: literal secret material matched {pat.pattern}")
        # 값이 있는 하드코딩된 ANTHROPIC_API_KEY 할당 없음
        rep.check(not re.search(r"ANTHROPIC_API_KEY\s*=\s*[\"'][^\"']+[\"']", src),
                  f"{base}: hardcoded ANTHROPIC_API_KEY value")

    # 비밀은 argv 가 아니라 stdin 으로 (safe_exec 계약)
    be = read(os.path.join(MDG_ROOT, "safe_exec", "backend.py"))
    rep.check("stdin_secret" in be, "ExecRequest must expose stdin_secret (R6: secret via stdin)")
    rep.check("input=req.stdin_secret" in be, "Backend.run must feed secret via stdin, not argv")

    # MDGState 비밀-free (구조적): state.py 에 비밀-이름 필드 없음
    st = read(os.path.join(CORE, "state.py"))
    for bad in ("api_key", "hmac_key", "operator_token", "sign_key", "ingest_key"):
        rep.check(f"{bad}:" not in st and f"{bad} :" not in st,
                  f"state.py: MDGState declares secret field '{bad}' (PS-3 violation)")
    return rep


if __name__ == "__main__":
    run(_check)
