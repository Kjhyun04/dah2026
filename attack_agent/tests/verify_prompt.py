"""verify_prompt — 프롬프트/레지스트리 정합 오프라인 게이트 (P1·P2·P4).

무해·오프라인(테스트베드/도커/네트워크/litellm 불필요). 구조 검사는 파일·AST·jinja 렌더 위주.

P1(레시피 금지, V2-D5): prompts/default.yaml 에 '특정 tool id 2개 이상을 순서(sequencing)로
  엮은 처방'(예: "serial5762 다음 oracle 를 써라", "A -> B -> C" 체인)이 없는지 검사.
 휴리스틱(명시): 한 스팬(라인/3라인 창) 안에서 (a) REGISTRY 의 서로 다른 tool id 가 2개 이상
    등장하고 (b) 그 두 id **사이**에 순서 접속어(다음/이후/->/then/순서/뒤에/후에/연쇄)가 놓일 때만
    '레시피'로 flag. 단순 나열(·, 쉼표)·용어정의 번호목록·일반 의사결정 원칙("불확실->먼저 정찰",
    카테고리어 '정찰/recon')은 위반이 아님(접속어가 두 tool id 사이에 없으므로 통과).
  또한 파일 상단(주석 헤더, agents: 이전)에 '레시피 금지' 원칙문이 실재하는지 확인.

P2(StrictUndefined 렌더): core.common.prompt_context 로더로 default.yaml 을 읽어, 대표
  WorldState/Goal(더미)로 각 에이전트 role 의 system/user/adapt_user 템플릿을 실제 렌더해
  jinja2 UndefinedError 가 없는지(모든 {{ agent.* }}/{{ t.* }} 변수 공급) 확인.
  + 양성대조: 없는 변수 참조는 StrictUndefined 로 실제 예외가 나야 함(엄격성 활성 증명).
  + 정적 보강: 템플릿의 모든 agent.*/t.* 토큰을 추출해 빌드된 뷰 컨텍스트에서 해석(대조).
  (jinja2 import 실패 시 렌더는 건너뛰고 정적 대조만 수행 — 한계를 finding 으로 보고.)

P4(tool 3자 정합): REGISTRY 길이==23, ToolId(Literal)==REGISTRY keys,
  default.yaml agents.*.tools keys==REGISTRY keys(3자), 각 tool 의 summary 필드 비어있지 않음.
  주의: ToolSpec(pydantic) 자체엔 description/summary 필드가 없음 -> 사람이 읽는 요약은
    prompts/default.yaml 의 tools[<id>].summary 에 존재. 여기선 그 요약의 비어있지 않음을 검사.

작성 2026-07-07.
"""

from __future__ import annotations
_import_sys=__import__('sys'); _import_os=__import__('os')
from pathlib import Path as _Path
_REPO=_Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path: _import_sys.path.insert(0,str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root -> cwd-relative paths resolve

import re
import sys
from typing import Any, Optional

# Windows 콘솔(cp949)에서 유니코드(—·->… 등) 출력 깨짐/크래시 방지.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

from typing import get_args as _get_args

from core.common.types import ToolId
from core.modules.registry import REGISTRY, get_spec

_YAML_PATH = _REPO / "prompts" / "default.yaml"

_fail = 0
_findings: list[str] = []


def check(label: str, cond: bool) -> None:
    global _fail
    mark = "PASS" if cond else "FAIL"
    if not cond:
        _fail += 1
    print(f"  [{mark}] {label}")


def _read_text(p: _Path) -> str:
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════════════════
# P1 · 레시피 금지 (순서로 엮인 특정 tool id 2개 이상만 flag)
# ═══════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("P1 · 레시피 금지 (V2-D5) — 순서로 엮인 tool id 체인 부재 + 원칙문 실재")
print("=" * 70)

_yaml_text = _read_text(_YAML_PATH)
_yaml_lines = _yaml_text.splitlines()
_TOOL_IDS = sorted(REGISTRY.keys(), key=len, reverse=True)  # 긴 id 우선(부분매칭 방지)

# 순서(sequencing) 접속어만 마커로 취급. 단순 나열(·, ,)·병렬은 제외.
_ORDER_MARKERS = ["그다음", "다음", "이후", "뒤에", "후에", "순서로", "순서대로",
                  "연쇄로", "연쇄", "→", "then", "->"]


def _find_id_hits(span: str) -> list[tuple[int, str]]:
    """스팬 안 tool id 등장 위치 목록 (word-boundary). (start, id)."""
    hits: list[tuple[int, str]] = []
    for tid in _TOOL_IDS:
        for m in re.finditer(r"(?<![\w])" + re.escape(tid) + r"(?![\w])", span):
            hits.append((m.start(), tid))
    hits.sort()
    return hits


def _marker_positions(span: str) -> list[int]:
    pos: list[int] = []
    for mk in _ORDER_MARKERS:
        i = span.find(mk)
        while i != -1:
            pos.append(i)
            i = span.find(mk, i + 1)
    return pos


def _recipe_pair(span: str) -> Optional[tuple[str, str]]:
    """서로 다른 tool id 2개 사이에 순서 접속어가 놓이면 (id1,id2) 반환, 아니면 None."""
    hits = _find_id_hits(span)
    if len({h[1] for h in hits}) < 2:
        return None
    mpos = _marker_positions(span)
    if not mpos:
        return None
    for p1, id1 in hits:
        for p2, id2 in hits:
            if p1 < p2 and id1 != id2 and any(p1 < mp < p2 for mp in mpos):
                return (id1, id2)
    return None


# 스팬 = 각 라인 + 3라인 슬라이딩 창(줄바꿈 처방까지 포착)
_flags: list[str] = []
_seen: set[tuple[str, str]] = set()
for _i in range(len(_yaml_lines)):
    for _w in (1, 3):
        if _i + _w > len(_yaml_lines):
            continue
        _span = "\n".join(_yaml_lines[_i:_i + _w])
        _pair = _recipe_pair(_span)
        if _pair is not None and _pair not in _seen:
            _seen.add(_pair)
            _flags.append(f"L{_i+1}~{_i+_w}: '{_pair[0]}' …순서접속어… '{_pair[1]}' | {_yaml_lines[_i].strip()[:80]}")

if _flags:
    print("  [!] 레시피 후보(순서로 엮인 tool id):")
    for _fl in _flags:
        print("      - " + _fl)
check("레시피(순서로 엮인 특정 tool id 체인) 없음", len(_flags) == 0)
if _flags:
    _findings.append(
        "P1: default.yaml 에서 순서로 엮인 tool id 처방 후보 "
        f"{len(_flags)}건 탐지 — 정직 flag: {_flags}"
    )

# 원칙문 실재: 헤더(주석, 'agents:' 이전)에 '레시피 금지'
_header = _yaml_text.split("agents:", 1)[0]
check("파일 상단 헤더에 '레시피 금지' 원칙문 실재", "레시피 금지" in _header)


# ═══════════════════════════════════════════════════════════════════════════
# P2 · StrictUndefined 렌더 (모든 role system/user/adapt_user)
# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("P2 · StrictUndefined 렌더 — 각 role 템플릿 실제 렌더 + 변수 공급 검증")
print("=" * 70)

# 대표(더미) WorldState/Goal 구성 (오프라인·litellm 불필요 경로).
from core.common.results import ReconResult
from core.common.types import container_access
from core.modules.kb import Goal, WorldState, kb_update, legality

_kb = WorldState.initial(footholds=[container_access("sgi")])
kb_update(_kb, ReconResult(
    reach=[f"{t}@10.50.0.1:0" for t in (
        "net_core", "mongo", "sgi", "uav5762", "s1u", "pivot",
        "gcs14555", "gcs14556", "web8080")],
    signing="on",
))
_goal = Goal(type="signing_bypass", target={"mode": 4})


def _resolve_path(root: Any, dotted: str) -> tuple[bool, Any]:
    """'agent.kb.signing' 같은 점경로를 root(=agent view)에서 속성 워킹으로 해석."""
    cur = root
    parts = dotted.split(".")
    # 'agent' 접두는 root 자체
    if parts and parts[0] == "agent":
        parts = parts[1:]
    for attr in parts:
        if not hasattr(cur, attr):
            return (False, None)
        cur = getattr(cur, attr)
    return (True, cur)


_render_ok = True
try:
    import jinja2  # noqa: F401
    import yaml as _yaml

    from core.common.prompt_context import (
        build_prompt_context,
        load_agent_prompt,
        render,
        scoped_tool_ids,
    )

    _statuses = {tid: legality(get_spec(tid), _kb) for tid in scoped_tool_ids(_goal)}
    _ctx = build_prompt_context(_goal, _kb, _statuses)
    check("build_prompt_context → tool_status 비어있지 않음", len(_ctx.tool_status) >= 1)

    _raw = _yaml.safe_load(_yaml_text) or {}
    _agent_names = list((_raw.get("agents") or {}).keys())
    check("default.yaml 에 최소 1개 agent role 존재", len(_agent_names) >= 1)

    for _name in _agent_names:
        _ap = load_agent_prompt(_name)
        _roles = {"system": _ap.system, "user": _ap.user}
        if _ap.adapt_user:
            _roles["adapt_user"] = _ap.adapt_user
        for _role, _tmpl in _roles.items():
            _err: Optional[str] = None
            try:
                _out = render(_tmpl, _ctx)
            except jinja2.exceptions.UndefinedError as e:
                _err = f"UndefinedError: {e}"
            except Exception as e:  # noqa: BLE001
                _err = f"{type(e).__name__}: {e}"
            check(f"render[{_name}.{_role}] UndefinedError 없음 · 비어있지 않음",
                  _err is None and isinstance(_out, str) and len(_out.strip()) > 0)
            if _err is not None:
                _findings.append(f"P2: render[{_name}.{_role}] 실패 — {_err}")

    # 양성대조: 없는 변수는 StrictUndefined 로 실제 예외가 나야 함(엄격성 활성 증명).
    _strict_raised = False
    try:
        render("{{ agent.__no_such_field_xyz__ }}", _ctx)
    except jinja2.exceptions.UndefinedError:
        _strict_raised = True
    check("StrictUndefined 활성(없는 변수 참조 → UndefinedError)", _strict_raised)

    # 정적 보강(대조): 템플릿의 모든 agent.* / t.* 토큰이 뷰 컨텍스트에서 해석되는지.
    _all_tmpl = "\n".join(
        s for _name in _agent_names
        for s in (
            (lambda a: [a.system, a.user] + ([a.adapt_user] if a.adapt_user else []))(
                load_agent_prompt(_name)
            )
        )
    )
    _agent_tokens = sorted(set(re.findall(r"agent(?:\.[A-Za-z_][\w]*)+", _all_tmpl)))
    _bad = [tok for tok in _agent_tokens if not _resolve_path(_ctx, tok)[0]]
    check(f"모든 agent.* 토큰({len(_agent_tokens)}개) 컨텍스트에서 해석됨", not _bad)
    if _bad:
        _findings.append(f"P2(static): 미해석 agent.* 토큰 {_bad}")

    _sample = _ctx.tool_status[0]
    _t_tokens = sorted({m.split(".", 1)[1] for m in re.findall(r"\bt\.[A-Za-z_][\w]*", _all_tmpl)})
    _bad_t = [attr for attr in _t_tokens if not hasattr(_sample, attr)]
    check(f"모든 t.* 루프변수 토큰({len(_t_tokens)}개) ToolStatusView 에 존재", not _bad_t)
    if _bad_t:
        _findings.append(f"P2(static): ToolStatusView 에 없는 t.* 토큰 {_bad_t}")

except ImportError as e:
    _render_ok = False
    check("jinja2/yaml import (렌더 경로)", False)
    _findings.append(
        f"P2: jinja2/yaml import 실패({e}) — 실제 렌더 생략, 정적 대조로 대체(한계: "
        "조건분기·필터 미평가). 렌더 무예외는 검증하지 못함."
    )


# ═══════════════════════════════════════════════════════════════════════════
# P4 · tool 3자 정합 (REGISTRY == ToolId == default.yaml tools) + summary 비어있지 않음
# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("P4 · tool 3자 정합 — REGISTRY(23)==ToolId==yaml.tools · summary 비어있지 않음")
print("=" * 70)

_reg_keys = set(REGISTRY.keys())
check("REGISTRY 길이 == 23", len(REGISTRY) == 23)

_id_literal = set(_get_args(ToolId))
check("ToolId(Literal) == REGISTRY keys (23)",
      _id_literal == _reg_keys and len(_id_literal) == 23)

# yaml tools 파싱(정적 — litellm/렌더 불필요)
import yaml as _yaml_p4  # noqa: E402

_raw_p4 = _yaml_p4.safe_load(_yaml_text) or {}
_agents_p4 = _raw_p4.get("agents") or {}
# tools 블록을 가진 대표 에이전트(AttackOrchestrator 우선)에서 tools 취득
_tools_block: dict[str, Any] = {}
_owner = None
if "AttackOrchestrator" in _agents_p4 and (_agents_p4["AttackOrchestrator"].get("tools")):
    _owner = "AttackOrchestrator"
    _tools_block = _agents_p4["AttackOrchestrator"]["tools"] or {}
else:
    for _n, _a in _agents_p4.items():
        if _a.get("tools"):
            _owner = _n
            _tools_block = _a["tools"] or {}
            break

_yaml_tool_keys = set(_tools_block.keys())
check(f"yaml.tools 키집합 == REGISTRY keys (3자 정합, owner={_owner})",
      _yaml_tool_keys == _reg_keys)
if _yaml_tool_keys != _reg_keys:
    _only_yaml = sorted(_yaml_tool_keys - _reg_keys)
    _only_reg = sorted(_reg_keys - _yaml_tool_keys)
    _findings.append(
        f"P4: yaml.tools 와 REGISTRY 불일치 — yaml-only={_only_yaml}, reg-only={_only_reg}"
    )

# 각 tool 의 summary 필드 비어있지 않음(공백 제외 길이>0)
_empty_summary: list[str] = []
for _tid, _tv in _tools_block.items():
    _summ = (_tv or {}).get("summary") if isinstance(_tv, dict) else None
    if not (isinstance(_summ, str) and _summ.strip()):
        _empty_summary.append(_tid)
check("모든 yaml.tools[*].summary 비어있지 않음", not _empty_summary)
if _empty_summary:
    _findings.append(f"P4: summary 비어있음 tool={_empty_summary}")

# 참고(정직): ToolSpec(pydantic) 자체엔 summary/description 필드 없음.
_spec_has_summary = any(
    hasattr(get_spec(t), "summary") or hasattr(get_spec(t), "description")
    for t in _reg_keys
)
if not _spec_has_summary:
    print("  [i] ToolSpec 에는 summary/description 필드가 없음 → 요약은 yaml.tools[*].summary 로 검사(위).")


# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
if _findings:
    print("FINDINGS (정직 보고):")
    for _f in _findings:
        print("  - " + _f)
    print("=" * 70)

if _fail == 0:
    print("ALL CHECKS PASSED (0 failures)")
    sys.exit(0)
else:
    print(f"{_fail} CHECK(S) FAILED")
    for _f in _findings:
        print("  - " + _f)
    sys.exit(1)
