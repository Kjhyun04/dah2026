"""구조 위생 오프라인 게이트 — S1(데드코드)·S2(module docstring)·S6(하드코딩 비밀/주소).

무해·오프라인(테스트베드/네트워크/도커 불필요). 순수 정적 분석(AST + tokenize)만 수행.
  S1: core/ 하위 모든 .py(단 __init__.py 제외)가 저장소 어딘가에서 최소 1회 import 되는지.
  S2: core/**/*.py(__init__ 제외)·supervisor/*.py·viewer/*.py 가 모듈 docstring 을 가지는지.
  S6: 실제 코드 라인(주석·docstring·문자열 리터럴 제외)에 하드코딩된 비밀/주소 리터럴이 없는지.
      tokenize 로 COMMENT/STRING 토큰을 공백치환해 docstring 예시 IP(resolve.py 등) 오탐을 피한다.
스타일 = tests/verify_p0.py (check()/집계/exit code): 통과 exit 0, 실패 exit 1 + '- <fail>'.
"""

from __future__ import annotations
_import_sys=__import__('sys'); _import_os=__import__('os')
from pathlib import Path as _Path
_REPO=_Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path: _import_sys.path.insert(0,str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root → cwd-relative paths resolve

import ast
import io
import re
import sys
import tokenize
from pathlib import Path

# Windows 콘솔(cp949)에서 유니코드(—·… 등) 출력 깨짐/크래시 방지.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

REPO = Path(_REPO)

# import 수집 대상 = 프로젝트 자체 소스만(.venv/.git 등 벤더 코드 제외).
_SKIP_DIRS = {".venv", ".git", "__pycache__", ".claude", "node_modules"}


def _iter_project_py():
    """.venv/.git 등을 제외한 저장소 자체 .py 파일 전량."""
    for p in REPO.rglob("*.py"):
        rel = p.relative_to(REPO)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        yield p


def _module_dotted(path: Path) -> str:
    """core/modules/kb.py → 'core.modules.kb'."""
    rel = path.relative_to(REPO).with_suffix("")
    return ".".join(rel.parts)


def _package_parts(path: Path):
    """파일이 속한 패키지의 dotted parts (파일명 제외)."""
    rel = path.relative_to(REPO)
    return list(rel.parts[:-1])


_fail = 0
_fail_labels: list[str] = []


def check(label: str, cond: bool) -> None:
    global _fail
    mark = "PASS" if cond else "FAIL"
    if not cond:
        _fail += 1
        _fail_labels.append(label)
    print(f"  [{mark}] {label}")


# ---------------------------------------------------------------------------
# import 그래프 수집 (S1)
# ---------------------------------------------------------------------------
def collect_imports():
    """저장소 자체 .py 전량에서 import 대상 dotted 경로 + 순수 이름 수집."""
    dotted: set[str] = set()
    names: set[str] = set()
    for path in _iter_project_py():
        try:
            src = path.read_text(encoding="utf-8")
            tree = ast.parse(src, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        pkg_parts = _package_parts(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    dotted.add(a.name)              # 'core.modules.kb'
                    names.add(a.name.split(".")[-1])
            elif isinstance(node, ast.ImportFrom):
                # 상대 import 를 절대 dotted 로 해석.
                if node.level and node.level > 0:
                    base = pkg_parts[: len(pkg_parts) - (node.level - 1)]
                    base_dotted = ".".join(base)
                else:
                    base_dotted = ""
                if node.module:
                    resolved = f"{base_dotted}.{node.module}" if base_dotted else node.module
                else:
                    resolved = base_dotted
                if resolved:
                    dotted.add(resolved)
                for a in node.names:
                    names.add(a.name)               # 'from pkg import kb' → 'kb'
                    if resolved and a.name != "*":
                        dotted.add(f"{resolved}.{a.name}")  # from pkg import submod
    return dotted, names


def run_s1():
    print("=" * 70)
    print("S1 · 데드코드 — core/ 모든 모듈(__init__ 제외)이 최소 1회 import 되는가")
    print("=" * 70)
    dotted, names = collect_imports()
    core_dir = REPO / "core"
    modules = sorted(
        p for p in core_dir.rglob("*.py") if p.name != "__init__.py"
    )
    check("core/ 에 검사할 모듈이 존재", len(modules) > 0)
    for path in modules:
        full = _module_dotted(path)
        modname = path.stem
        referenced = (full in dotted) or (modname in names)
        rel = path.relative_to(REPO).as_posix()
        check(f"{rel} 가 import 됨 (dead-code 아님)", referenced)


# ---------------------------------------------------------------------------
# 모듈 docstring (S2)
# ---------------------------------------------------------------------------
def run_s2():
    print()
    print("=" * 70)
    print("S2 · 모듈 docstring — core/**·supervisor/*·viewer/* 각 파일이 docstring 보유")
    print("=" * 70)
    targets: list[Path] = []
    targets += [p for p in (REPO / "core").rglob("*.py") if p.name != "__init__.py"]
    targets += [p for p in (REPO / "supervisor").glob("*.py") if p.name != "__init__.py"]
    targets += [p for p in (REPO / "viewer").glob("*.py") if p.name != "__init__.py"]
    targets = sorted(set(targets))
    check("S2 검사 대상 파일 존재", len(targets) > 0)
    for path in targets:
        rel = path.relative_to(REPO).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            doc = ast.get_docstring(tree)  # from __future__ 위 최상단 docstring 인식
        except (SyntaxError, UnicodeDecodeError):
            doc = None
        has_doc = bool(doc and doc.strip())
        check(f"{rel} module docstring 보유", has_doc)


# ---------------------------------------------------------------------------
# 하드코딩 비밀/주소 (S6)
# ---------------------------------------------------------------------------
# 실제 코드 라인만 검사(주석·docstring·문자열 리터럴 = 공백치환 후 대조).
_SECRET_PATTERNS = [
    ("64-hex 키", re.compile(r"\b[0-9a-fA-F]{64}\b")),
    ("'sk-or-' OpenRouter 키", re.compile(r"sk-or-")),
    ("실 IP(10.44.)", re.compile(r"\b10\.44\.")),
    ("실 IP(10.45.)", re.compile(r"\b10\.45\.")),
    ("실 IP(172.30.)", re.compile(r"\b172\.30\.")),
    ("실 IP(43.203.)", re.compile(r"\b43\.203\.")),
]


def _blank_strings_and_comments(src: str) -> str:
    """STRING·COMMENT 토큰이 차지하는 문자 스팬을 공백으로 치환한 코드-only 텍스트."""
    lines = src.splitlines(keepends=True)
    # 각 라인을 가변 리스트로.
    buf = [list(ln) for ln in lines]
    try:
        toks = tokenize.generate_tokens(io.StringIO(src).readline)
        for tok in toks:
            if tok.type not in (tokenize.STRING, tokenize.COMMENT):
                continue
            # 3.12+ FSTRING_* 은 STRING 아니지만 아래 반복이 안전하게 처리.
            (srow, scol), (erow, ecol) = tok.start, tok.end
            for row in range(srow, erow + 1):
                idx = row - 1
                if idx < 0 or idx >= len(buf):
                    continue
                line = buf[idx]
                c0 = scol if row == srow else 0
                c1 = ecol if row == erow else len(line)
                for c in range(c0, min(c1, len(line))):
                    if line[c] != "\n":
                        line[c] = " "
    except (tokenize.TokenError, IndentationError):
        # 토큰화 실패 시(부분 파일 등) 보수적으로 원문 유지.
        pass
    return "".join("".join(row) for row in buf)


def run_s6():
    print()
    print("=" * 70)
    print("S6 · 하드코딩 — 실제 코드(주석·docstring·문자열 제외)에 비밀/실IP 리터럴 없음")
    print("=" * 70)
    targets = sorted(_iter_project_py())
    check("S6 검사 대상 파일 존재", len(targets) > 0)
    violations: list[str] = []
    for path in targets:
        rel = path.relative_to(REPO).as_posix()
        try:
            src = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        code_only = _blank_strings_and_comments(src)
        for lineno, line in enumerate(code_only.splitlines(), start=1):
            for name, pat in _SECRET_PATTERNS:
                if pat.search(line):
                    violations.append(f"{rel}:{lineno} [{name}] {line.strip()[:80]}")
    check("코드 라인에 하드코딩 비밀/실IP 리터럴 0", len(violations) == 0)
    for v in violations:
        print(f"      · {v}")


run_s1()
run_s2()
run_s6()

print()
print("=" * 70)
if _fail == 0:
    print("ALL CHECKS PASSED (0 failures)")
    sys.exit(0)
else:
    print(f"{_fail} CHECK(S) FAILED")
    for lbl in _fail_labels:
        print(f"- {lbl}")
    sys.exit(1)
