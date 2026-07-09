"""test_record_contract — P0 panel-2 (PS-3): to_record 프로젝션 + redact 스크럽.

leak-0 계약을 고정: (a) allow-list 는 선언된 채널의 부분집합(팬텀 키 없음),
(b) secret 처럼 보이는 필드명은 allow-list 에 없음, (c) 미선언 키는 프로젝션으로
제거됨, (d) 드라이버의 최종 스크럽이 json.dumps(default=str) 우회를
닫음. ``python tests/test_record_contract.py`` 로 실행 가능.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import driver  # noqa: E402
from mdg.core.state import MDGState, _RECORD_ALLOW, to_record  # noqa: E402

_SECRET_NAME_TOKENS = ("api_key", "apikey", "token", "hmac", "sign_key", "signkey",
                       "secret", "operator", "canary")

# secret 형태 카나리를 런타임에 생성(리터럴 분할)하여 verify_keys 의 소스 스캔이
# 이 테스트 파일을 실제 키 자료 포함으로 오판하지 않도록 한다.
_SK = "sk-" + "ant-"
_CANARY_A = _SK + "abcdefgh12345678"
_CANARY_B = _SK + "deadbeefcafe0001"


def test_allow_subset_of_channels():
    ann = set(MDGState.__annotations__.keys())
    phantom = _RECORD_ALLOW - ann
    assert not phantom, f"allow-list has phantom keys not in MDGState: {phantom}"


def test_no_secret_field_in_allow():
    for key in _RECORD_ALLOW:
        low = key.lower()
        for tok in _SECRET_NAME_TOKENS:
            assert tok not in low, f"secret-looking key '{key}' in _RECORD_ALLOW"


def test_undeclared_key_dropped():
    st = {"config_version": "v", "tick_i": 3, "SECRET_smuggled": _CANARY_A}
    rec = to_record(st)  # type: ignore[arg-type]
    assert "SECRET_smuggled" not in rec
    assert rec["config_version"] == "v" and rec["tick_i"] == 3


def test_redact_scrubs_string_leaves():
    rec = {"note": "api_key=" + _CANARY_A, "ok": 1}
    out = driver.redact(rec)
    assert _SK not in out["note"] and "[REDACTED]" in out["note"]
    assert out["ok"] == 1


class _Sneaky:
    """__str__ 가 secret 을 누출하는 비직렬화 객체; _json_safe 는 이를 놓치고
    json.dumps(default=str) 가 redact 실행 후 __str__ 를 합성한다."""
    def __str__(self) -> str:
        return _CANARY_B


def test_final_scrub_closes_default_str_bypass():
    # 드라이버 직렬화 경로 시뮬레이션: redact -> json.dumps(default=str) -> _scrub_str
    safe = driver.redact({"leak": _Sneaky()})  # redact 는 객체를 건드리지 않고 남김(str 아님)
    raw = json.dumps(safe, ensure_ascii=False, default=str)
    assert _CANARY_B in raw                          # 최종 스크럽 전에는 우회 존재
    line = driver._scrub_str(raw)
    assert _CANARY_B not in line                      # 최종 스크럽 패스로 닫힘
    assert "[REDACTED]" in line
    json.loads(line)                                  # 여전히 유효한 JSON


def _run_all() -> int:
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"[FAIL] {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"[ERROR] {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
