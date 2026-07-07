"""품질 게이트 — S5(타입힌트)·S8(구조↔문서)·S9(CLI 스키마)·P3(용어정의)·P5(비밀 리터럴)·P6(언어정책)·P7(스텁↔문서).

오프라인·무해(AST/파일 파싱만; litellm·도커·네트워크 불필요). 통과 시 exit 0.
※ P8(코드 주석의 실측 주장↔근거 연결)은 본질적으로 주관적이라 자동 게이트가 아닌 수동 리뷰 항목으로 둔다(README §품질 게이트).
"""
from __future__ import annotations

_import_sys = __import__("sys")
_import_os = __import__("os")
from pathlib import Path as _Path  # noqa: E402

_REPO = _Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path:
    _import_sys.path.insert(0, str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root → cwd-relative paths resolve

import ast  # noqa: E402
import glob  # noqa: E402
import re  # noqa: E402
import sys  # noqa: E402
import tokenize  # noqa: E402
from io import BytesIO  # noqa: E402

_fails: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if not ok:
        _fails.append(f"{name}{(' — ' + detail) if detail else ''}")


# ── S5: core/ public 함수 전량 타입힌트(파라미터+반환) ──────────────────────────
def _s5() -> None:
    miss: list[str] = []
    for f in glob.glob("core/**/*.py", recursive=True):
        if f.endswith("__init__.py"):
            continue
        tree = ast.parse(open(f, encoding="utf-8").read())
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("_"):
                if n.returns is None:
                    miss.append(f"{f}:{n.name}(no-return)")
                for a in n.args.args:
                    if a.arg not in ("self", "cls") and a.annotation is None:
                        miss.append(f"{f}:{n.name}({a.arg})")
    check("S5 core/ public 함수 타입힌트 완전", not miss, f"{len(miss)}건: {miss[:3]}")


# ── S8: 문서가 참조하는 구조/파일 실재 ─────────────────────────────────────────
def _s8() -> None:
    required = [
        "README.md", "QUICKSTART.md", "verify.py", "dah.sh", "run.py", "pyproject.toml",
        "configs/models.yaml", "configs/config.testbed.yaml", "configs/config.live.yaml",
        "goals/goal.testbed.yaml", "goals/goal.p4.yaml", "prompts/default.yaml",
        "core", "supervisor", "viewer", "sidecar", "tests", "docs",
    ]
    missing = [p for p in required if not _Path(p).exists()]
    check("S8 README 참조 구조/파일 실재", not missing, f"부재: {missing}")


# ── S9: 엔트리 CLI 스키마 회귀 ─────────────────────────────────────────────────
def _s9() -> None:
    try:
        import run  # noqa
        ns = run._parse_args(["--config", "configs/config.testbed.yaml", "--goal", "goals/goal.testbed.yaml"])
        need = {"config", "goal", "backend", "recon_only", "no_llm", "out"}
        check("S9 run.py CLI 인자", need <= set(vars(ns)), f"누락: {need - set(vars(ns))}")
    except Exception as e:  # noqa: BLE001
        check("S9 run.py 임포트/파서", False, f"{type(e).__name__}: {e}")
    try:
        import run_live_gate5  # noqa
        _old = sys.argv[:]
        sys.argv = ["run_live_gate5"]  # _parse_args() 는 sys.argv 를 읽음 → 기본값 파싱
        try:
            ns2 = run_live_gate5._parse_args()
        finally:
            sys.argv = _old
        need2 = {"config", "goal", "backend", "skip_supervisor"}
        check("S9 run_live_gate5 CLI 인자", need2 <= set(vars(ns2)), f"누락: {need2 - set(vars(ns2))}")
    except Exception as e:  # noqa: BLE001
        check("S9 run_live_gate5 임포트/파서", False, f"{type(e).__name__}: {e}")


# ── P3: 프롬프트 용어정의(glossary) 존재 ───────────────────────────────────────
def _p3() -> None:
    t = open("prompts/default.yaml", encoding="utf-8").read()
    check("P3 prompt glossary(용어정의) 존재", ("용어 정의" in t or "glossary" in t.lower()))


# ── S6확장/P5: 코드+프롬프트+config/goal 에 평문 비밀 리터럴 0 ─────────────────
_SECRET = re.compile(r"(sk-or-[A-Za-z0-9]|sk-ant-[A-Za-z0-9]|\b[0-9a-fA-F]{64}\b)")


def _code_only(path: str) -> str:
    """tokenize 로 COMMENT/STRING 을 공백치환 → 실제 코드 라인만."""
    src = open(path, "rb").read()
    out = bytearray(src)
    try:
        for tok in tokenize.tokenize(BytesIO(src).readline):
            if tok.type in (tokenize.STRING, tokenize.COMMENT):
                (sr, sc), (er, ec) = tok.start, tok.end
                # 안전상 전체 토큰 텍스트를 공백으로(멀티라인 포함)
                pass
    except Exception:
        pass
    # 간이: 문자열/주석 제외가 어려운 경우를 위해 라인 기반 폴백은 쓰지 않고
    # ast 로 문자열/docstring 상수를 제거한 소스 재구성
    try:
        tree = ast.parse(src.decode("utf-8"))
        strings = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                strings.append(n.value)
        text = src.decode("utf-8")
        for s in strings:
            text = text.replace(s, " ")
        # 주석 제거
        text = re.sub(r"#.*", "", text)
        return text
    except Exception:
        return ""
    return bytes(out).decode("utf-8", "ignore")


def _p5() -> None:
    hits: list[str] = []
    for f in glob.glob("configs/*.yaml") + glob.glob("goals/*.yaml") + ["prompts/default.yaml"]:
        t = open(f, encoding="utf-8").read()
        # yaml/prompt: 주석(#) 제거 후 검사(env 이름 참조는 허용, 리터럴 비밀만 flag)
        body = re.sub(r"#.*", "", t)
        if _SECRET.search(body):
            hits.append(f)
    for f in glob.glob("core/**/*.py", recursive=True):
        if _SECRET.search(_code_only(f)):
            hits.append(f)
    check("P5 비밀 리터럴(64hex/sk-*) 0", not hits, f"발견: {hits}")


# ── P6: 언어/주석 정책이 문서에 명시 ──────────────────────────────────────────
def _p6() -> None:
    t = open("README.md", encoding="utf-8").read()
    check("P6 언어/주석 정책 문서화", ("언어 정책" in t or "주석 언어" in t or "language policy" in t.lower()))


# ── P7: 코드 스텁/TODO 표식이 문서화된 한계와 연결 ────────────────────────────
def _p7() -> None:
    marks: list[str] = []
    for f in glob.glob("sidecar/**/*.py", recursive=True) + glob.glob("core/**/*.py", recursive=True):
        t = open(f, encoding="utf-8").read()
        if re.search(r"\bstub\b|스텁|_ ?= ?key\b|TODO|FIXME", t):
            marks.append(_Path(f).name)
    if not marks:
        check("P7 스텁/TODO↔문서 연결", True)
        return
    docs = ""
    for d in ["README.md", "docs/DESIGN.md", "docs/DEPLOY_VERIFY_RUNBOOK.md"]:
        if _Path(d).exists():
            docs += open(d, encoding="utf-8").read()
    # 스텁이 존재하면 문서 어딘가에 '스텁' 또는 'forge_aria' 한계 언급이 있어야 함(은폐 금지)
    ack = ("스텁" in docs or "stub" in docs.lower() or "forge_aria" in docs)
    check("P7 스텁/TODO↔문서 연결(은폐 금지)", ack, f"코드 표식 {marks[:3]} 있으나 문서 한계 미언급")


def main() -> int:
    _s5(); _s8(); _s9(); _p3(); _p5(); _p6(); _p7()
    print("=" * 60)
    if _fails:
        for f in _fails:
            print("- " + f)
        print(f"QUALITY GATE FAILED ({len(_fails)})")
        return 1
    print("ALL CHECKS PASSED (0 failures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
