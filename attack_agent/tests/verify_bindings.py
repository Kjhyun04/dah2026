"""verify_bindings.py — T-02 registry.exec_binding.script 매핑 검증.

검증:
  1) REGISTRY의 모든 tool이 sidecar exec 루트(air/pfcp) 아래 실제 script 파일로 해석되는지
  2) script 경로 중복(의도/비의도) 현황

사용:
  python verify_bindings.py
"""

from __future__ import annotations
_import_sys=__import__('sys'); _import_os=__import__('os')
from pathlib import Path as _Path
_REPO=_Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path: _import_sys.path.insert(0,str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root → cwd-relative paths resolve

import sys
from pathlib import Path

try:  # Windows 콘솔(cp949) 유니코드 출력 보호.
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.modules.registry import REGISTRY  # noqa: E402


def main() -> int:
    roots = [
        _ROOT / "sidecar" / "air" / "exec",
        _ROOT / "sidecar" / "pfcp" / "exec",
    ]
    missing: list[tuple[str, str]] = []
    scripts: list[str] = []
    dup_count: dict[str, int] = {}

    for tool_id, spec in REGISTRY.items():
        rel = spec.exec_binding.script
        scripts.append(rel)
        dup_count[rel] = dup_count.get(rel, 0) + 1
        found = any((r / rel).exists() for r in roots)
        if not found:
            missing.append((tool_id, rel))

    print(f"tools={len(REGISTRY)}")
    print(f"scripts(total)={len(scripts)} unique={len(set(scripts))}")
    dups = sorted([p for p, c in dup_count.items() if c > 1])
    print(f"duplicate_scripts={len(dups)}")
    for p in dups:
        print(f"  DUP {p} x{dup_count[p]}")

    if missing:
        print(f"missing_bindings={len(missing)}")
        for tid, rel in sorted(missing):
            print(f"  MISS {tid} -> {rel}")
        return 1

    print("ALL BINDINGS RESOLVED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
