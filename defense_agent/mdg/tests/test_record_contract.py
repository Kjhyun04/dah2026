"""test_record_contract — P0 panel-2 (PS-3): to_record projection + redact scrub.

Pins the leak-0 contract: (a) the allow-list is a subset of declared channels (no phantom
keys), (b) no secret-looking field name is in the allow-list, (c) undeclared keys are
dropped by projection, (d) the driver's final scrub closes the json.dumps(default=str)
bypass. Runnable as ``python tests/test_record_contract.py``.
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

# Build secret-shaped canaries at runtime (split literals) so verify_keys' source scan
# does not flag this test file as containing real key material.
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
    """Non-serializable object whose __str__ leaks a secret; _json_safe would miss it and
    json.dumps(default=str) would synthesize its __str__ AFTER redact ran."""
    def __str__(self) -> str:
        return _CANARY_B


def test_final_scrub_closes_default_str_bypass():
    # simulate the driver serialization path: redact -> json.dumps(default=str) -> _scrub_str
    safe = driver.redact({"leak": _Sneaky()})  # redact leaves the object untouched (not str)
    raw = json.dumps(safe, ensure_ascii=False, default=str)
    assert _CANARY_B in raw                          # bypass exists before final scrub
    line = driver._scrub_str(raw)
    assert _CANARY_B not in line                      # closed by the final scrub pass
    assert "[REDACTED]" in line
    json.loads(line)                                  # still valid JSON


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
