#!/usr/bin/env python3
"""verify.py — 전체 무결성 게이트 단일 러너.

사용: python verify.py    (또는 ./dah.sh verify)
11개 게이트(tests/ 6종 + supervisor/viewer 2종)를 repo 루트에서 실행하고 PASS/FAIL 요약.
오프라인·무해(테스트베드 무접속). GitHub 클론 직후 `pip install -e .` 후 바로 실행 가능.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

GATES = [
    "tests/verify_hygiene.py",
    "tests/verify_p0.py",
    "tests/verify_p2.py",
    "tests/verify_models.py",
    "tests/verify_parsers.py",
    "tests/verify_bindings.py",
    "tests/verify_structure.py",
    "tests/verify_prompt.py",
    "tests/verify_quality.py",
    "supervisor/verify_grep0.py",
    "viewer/verify_viewer.py",
]


def main() -> int:
    shutil.rmtree(ROOT / ".cache_verify", ignore_errors=True)
    fails = 0
    for g in GATES:
        r = subprocess.run(
            [sys.executable, g],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        ok = r.returncode == 0
        print(f"  {g:34} {'PASS' if ok else 'FAIL'}")
        if not ok:
            fails += 1
            out = (r.stdout + r.stderr).strip().splitlines()
            if out:
                print("      " + out[-1])
    shutil.rmtree(ROOT / ".cache_verify", ignore_errors=True)
    print("== ALL GATES PASS ==" if fails == 0 else f"== {fails} GATE(S) FAILED ==")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
