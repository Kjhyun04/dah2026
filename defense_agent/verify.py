#!/usr/bin/env python3
"""verify.py — MDG 방어 에이전트 무결성 게이트 단일 러너.

사용: python verify.py    (또는 ./dah.sh verify)
mdg/verify/*.py 정적/오프라인 게이트를 repo 루트에서 `python -m mdg.verify.<gate>` 로
실행하고 PASS/FAIL 요약. 오프라인·무해(테스트베드 무접속·비밀 불필요).
GitHub 클론 직후 `pip install -e .` 후 바로 실행 가능.

게이트(2대 불변식 중심):
  verify_routing              불변식① 결정론 라우팅 (FORBIDDEN_KEYS 제어흐름 회귀가드)
  verify_graph                LangGraph 토폴로지(11노드·cycle-0·trust-root 격리)
  verify_leak0                불변식② leak-0 실행 (비밀 미노출·프로세스 잔여 0)
  verify_no_fw_subproc        방화벽 조작이 subprocess 로 새지 않음(actuator 경유만)
  verify_grep0                방어 core ⟂ verifier(trust-root) 완전분리
  verify_keys                 키/비밀 리터럴 0 (env 이름으로만 주입)
  verify_tools                tool 레지스트리 계약·바인딩
  verify_models               role-to-model 라우팅
  verify_d11_collector_disjoint  6 collector vantage disjoint(귀속 정합)
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

# mdg/verify/ 에서 자동 발견(있는 것만 실행) — 순서는 불변식 우선.
_PREFERRED = [
    "verify_routing",
    "verify_graph",
    "verify_leak0",
    "verify_no_fw_subproc",
    "verify_grep0",
    "verify_keys",
    "verify_tools",
    "verify_models",
    "verify_d11_collector_disjoint",
]


def _discover() -> list[str]:
    vdir = ROOT / "mdg" / "verify"
    present = {
        p.stem
        for p in vdir.glob("verify_*.py")
        if p.name not in ("__init__.py",)
    }
    ordered = [g for g in _PREFERRED if g in present]
    ordered += sorted(present - set(ordered))  # 미열거 게이트도 뒤에 붙임
    return ordered


def main() -> int:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    fails = 0
    gates = _discover()
    for g in gates:
        r = subprocess.run(
            [sys.executable, "-m", f"mdg.verify.{g}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        ok = r.returncode == 0
        print(f"  mdg.verify.{g:34} {'PASS' if ok else 'FAIL'}")
        if not ok:
            fails += 1
            out = (r.stdout + r.stderr).strip().splitlines()
            for line in out[-5:]:
                print("      " + line)
    print("== ALL GATES PASS ==" if fails == 0 else f"== {fails} GATE(S) FAILED ==")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
