"""verify_grep0 — Verifier 분리 (PA-2 · DESIGN §부록A).

강제(정적):
  - 어떤 mdg.core.* 모듈도 mdg.verifier.* 를 import 하지 않음 (core ↛ verifier)
  - 'verifier_truth' 채널/심볼이 state.py (및 core 전체)에 부재
  - 'Truth' 타입이 core 에서 참조되지 않음 (core 는 판정 저장소를 import 불가)
  - 어떤 core 모듈도 docker sdk / socket 경로 / proxy URL 을 import 하지 않음 (PS-1 중첩)
  - core CODE 에 하드코딩된 타겟 리터럴 금지 (GATE2 targets-0, finding P2-3/A-1):
    IPv4 리터럴, INPUT_SPEC 컨테이너/역할 이름 토큰, INPUT_SPEC 포트 int 는
    코드 레벨 상수로 금지되며, 주석/독스트링에서만 허용된다. 금지 집합은
    config.INPUT_SPEC (loader) 에서 소싱하며 두 번째 하드코딩 복사본이 아니므로,
    가드가 선언된 토폴로지를 추적한다. 이것이 바로
    select_policy.py enforce_at 컨테이너-리터럴 회귀를 잡아냈을 장치다.
"""
from __future__ import annotations

import ast
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import loader  # noqa: E402
from mdg.verify._util import CORE, MDG_ROOT, Report, parse, read, run  # noqa: E402


def _core_files() -> list[str]:
    out = []
    for root, _dirs, files in os.walk(CORE):
        for f in files:
            if f.endswith(".py"):
                out.append(os.path.join(root, f))
    return out


def _imports(tree: ast.Module) -> list[str]:
    mods = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods.append(node.module or "")
    return mods


FORBIDDEN_IMPORT_SUBSTR = ["verifier", "docker", "socket"]
FORBIDDEN_LITERALS = ["/var/run/docker.sock", "docker-socket-proxy", "verifier_truth"]

# IPv4 dotted-quad (word-bounded 이므로 리터럴 quad 가 없는 r"\d{1,3}\.\d{1,3}" 같은 regex-패턴
# 문자열은 오탐하지 않고, 실제 a.b.c.d 리터럴만 매칭한다).
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _forbidden_target_literals() -> tuple[dict[str, re.Pattern], set[int]]:
    """core 에서 CODE 레벨 리터럴로 절대 나타나서는 안 되는 토폴로지 토큰 — config.INPUT_SPEC
    에서 소싱(두 번째 하드코딩 복사본 아님). (이름토큰 -> word-bounded regex, 금지 포트 int) 를
    반환. 컨테이너/역할 이름(log-tail 컨테이너 포함) + 선언된 포트 및 nf 메트릭 엔드포인트의
    :port."""
    spec = loader.input_spec()
    tokens: set[str] = set()
    for r in spec.get("roles", []) or []:
        for k in ("role", "container"):
            v = r.get(k)
            if v:
                tokens.add(str(v))
    for v in (spec.get("log_containers", {}) or {}).values():
        if v:
            tokens.add(str(v))
    ports: set[int] = set()
    for v in (spec.get("ports", {}) or {}).values():
        try:
            ports.add(int(v))
        except (TypeError, ValueError):
            pass
    for ep in (spec.get("nf_endpoints", {}) or {}).values():
        m = re.search(r":(\d+)\b", str(ep))
        if m:
            ports.add(int(m.group(1)))
    return {t: re.compile(r"\b" + re.escape(t) + r"\b") for t in tokens}, ports


def _docstring_const_ids(tree: ast.Module) -> set[int]:
    """모듈/클래스/함수 독스트링으로 쓰인 모든 Constant 노드의 id() — 토폴로지 토큰은 거기(서술)
    에서 허용되므로 해당 노드는 리터럴 스캔에서 면제된다. 주석은 AST 에 아예 없으므로 암묵적으로
    면제된다."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                and body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            ids.add(id(body[0].value))
    return ids


def _scan_hardcoded_targets(rep: Report) -> None:
    """Fail-closed AST 스캔: core CODE(주석·독스트링 외부)의 IPv4 / 컨테이너-역할 토큰 /
    선언-포트 리터럴은 모두 GATE2 targets-0 위반(finding P2-3/A-1)이다."""
    token_res, ports = _forbidden_target_literals()
    for path in _core_files():
        tree = parse(path)
        base = os.path.relpath(path, MDG_ROOT)
        doc_ids = _docstring_const_ids(tree)
        hits: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or id(node) in doc_ids:
                continue
            val = node.value
            if isinstance(val, str):
                if _IPV4_RE.search(val):
                    hits.append(f"L{node.lineno} IPv4 literal '{val}'")
                for tok, rx in token_res.items():
                    if rx.search(val):
                        hits.append(f"L{node.lineno} container/role token '{tok}'")
            elif isinstance(val, int) and not isinstance(val, bool) and val in ports:
                hits.append(f"L{node.lineno} declared-port literal {val}")
        rep.check(not hits,
                  f"{base}: hardcoded target literal(s) in core CODE (GATE2 targets-0; source from "
                  f"INPUT_SPEC): {'; '.join(hits)}")


def _check() -> Report:
    rep = Report("verify_grep0")

    for path in _core_files():
        src = read(path)
        tree = parse(path)
        base = os.path.relpath(path, MDG_ROOT)
        for mod in _imports(tree):
            rep.check("verifier" not in mod,
                      f"{base}: core imports verifier module '{mod}' (grep0 violation)")
            rep.check(not (mod == "docker" or mod.startswith("docker.")),
                      f"{base}: core imports docker sdk '{mod}' (PS-1)")
        # 리터럴 스캔
        rep.check("verifier_truth" not in src,
                  f"{base}: 'verifier_truth' symbol present (PA-2 requires absence)")
        for lit in ("/var/run/docker.sock", "docker-socket-proxy"):
            rep.check(lit not in src, f"{base}: forbidden sock/proxy literal '{lit}' (PS-1)")

    # Truth 타입은 core 에서 참조되지 않음
    for path in _core_files():
        src = read(path)
        base = os.path.relpath(path, MDG_ROOT)
        # 부재에 관한 주석 안의 단어는 허용; 심볼 사용 패턴을 검사
        rep.check("import Truth" not in src and "Truth(" not in src and ": Truth" not in src
                  and "list[Truth]" not in src,
                  f"{base}: references Truth type (core must not import verdict store)")

    # GATE2 targets-0: core CODE 에 하드코딩된 IPv4/컨테이너/포트 리터럴 없음 (finding P2-3/A-1).
    _scan_hardcoded_targets(rep)
    return rep


if __name__ == "__main__":
    run(_check)
