"""verify_models — role-to-model 라우팅 정합 (DEFENSE_AGENT_DEV_WORKFLOW line 202:
'verify_models(role-to-model 라우팅 Orient=Sonnet·Decide=Opus·폴백리스트)').

config 측(models.yaml roles)과 code 측(make_orient_llm/make_decide_llm 팩토리 + graph
llm_orient/llm_decide 슬롯)이 일치하고 뒤바뀌지 않았음을 검사하는 정적 검사
(langgraph/pydantic/pyyaml 불필요):

  - core.topology.BIND 는 orient 노드의 llm kwarg 를 슬롯 'llm_orient' 에, decide 노드의
    것을 'llm_decide' 에 매핑(build_graph 와 e2e._TickExecutor 가 함께 소비하는 단일 recipe,
    PA-9) — orient 슬롯은 orient 노드에, decide 슬롯은 decide 노드에 공급(뒤바뀌면
    Sonnet/Opus 오라우팅);
  - build_llm_deps 는 make_orient/decide_llm 을 통해 정확히 {'llm_orient','llm_decide'} 를 반환;
  - orient 팩토리는 roles['orient'] + OrientNote 를 읽고, decide 는 roles['decide'] +
    DecideNote 를 읽음;
  - models.yaml roles.orient -> Sonnet 계열 + OrientNote, roles.decide -> Opus 계열 +
    DecideNote, 각각 head 가 primary 와 다른 비어있지 않은 fallback 리스트를 가짐.

Model-ID CURRENCY (opus-4-8 / sonnet-4-5 / haiku-4-5 미폐기)는 정적으로 결정 불가한
도메인 sign-off 항목(panel ref-align)이며 — 이 verifier 는 라우팅/배선만 검사한다.
"""
from __future__ import annotations

import ast
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import topology  # noqa: E402  (순수 데이터: langgraph/pydantic 없음)
from mdg.verify._util import MDG_ROOT, Report, parse, read, run  # noqa: E402

CORE = os.path.join(MDG_ROOT, "core")
LLM = os.path.join(MDG_ROOT, "llm")
CONFIG = os.path.join(MDG_ROOT, "config")

# role -> (팩토리 파일, 팩토리 fn, 기대 response-model 이름, 기대 llm 슬롯,
#          그 슬롯으로 partial 된 graph 노드, model-계열 substring)
_ROLE_SPEC = {
    "orient": ("orient.py", "make_orient_llm", "OrientNote", "llm_orient", "orient", "sonnet"),
    "decide": ("decide.py", "make_decide_llm", "DecideNote", "llm_decide", "decide", "opus"),
}


# --------------------------------------------------------------------------- #
# topology.BIND — 어느 llm 슬롯이 어느 노드에 바인딩되는가 (단일 소스, PA-9)
# --------------------------------------------------------------------------- #
def _graph_slot_map() -> dict[str, str]:
    """BIND recipe 가 kwarg 'llm' 을 바인딩하는 각 노드에 대한 {node_name -> llm 슬롯 문자열}.

    PA-9 이후 llm 슬롯 바인딩은 ``graph.build_graph`` 와 ``e2e._TickExecutor`` 가 함께 소비하는
    단일 recipe ``core.topology.BIND`` 에 존재 — 따라서 BIND 를 검사하면 두 실행 경로를 한 번에
    검사한다(이전에는 graph.py 의 수작성 partial 을 AST 스캔했다)."""
    return {node: b["llm"] for node, b in topology.BIND.items() if "llm" in b}


def _fn_source(path: str, fn_name: str) -> str:
    """최상위 함수의 소스 텍스트를 반환(const/name 스캔 대상)."""
    tree = parse(path)
    src = read(path)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            return ast.get_source_segment(src, node) or ""
    return ""


# --------------------------------------------------------------------------- #
# models.yaml — role facts (pyyaml 있으면 사용, 없으면 작은 들여쓰기 스캔)
# --------------------------------------------------------------------------- #
def _role_facts_yaml() -> dict:
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    path = os.path.join(CONFIG, "models.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    roles = data.get("roles", {}) or {}
    out: dict = {}
    for role, r in roles.items():
        out[role] = {
            "model": str(r.get("model", "")),
            "response_model": str(r.get("response_model", "")),
            "fallback": list(r.get("fallback", []) or []),
        }
    return out


def _role_facts_scan() -> dict:
    """pyyaml 없는 폴백: 각 role 블록 아래 model/response_model/fallback 를 읽는다."""
    text = read(os.path.join(CONFIG, "models.yaml"))
    out: dict = {}
    for role in _ROLE_SPEC:
        # role 블록 캡처: '  <role>:' 부터 다음 2-space 들여쓰기 키 또는 EOF 까지
        m = re.search(rf"^  {role}:\s*$(?P<body>.*?)(?=^\S|^  \w|\Z)", text,
                      re.MULTILINE | re.DOTALL)
        body = m.group("body") if m else ""
        model = re.search(r'^\s*model:\s*"([^"]+)"', body, re.MULTILINE)
        resp = re.search(r"response_model:\s*\"?([A-Za-z]+)\"?", body)
        fb = re.search(r"fallback:\s*\[([^\]]*)\]", body)
        fbs = [s.strip().strip('"').strip("'") for s in (fb.group(1).split(",") if fb else [])
               if s.strip()]
        out[role] = {
            "model": (model.group(1).strip() if model else ""),
            "response_model": (resp.group(1) if resp else ""),
            "fallback": fbs,
        }
    return out


def _check() -> Report:
    rep = Report("verify_models")

    slot_map = _graph_slot_map()
    deps_src = _fn_source(os.path.join(LLM, "__init__.py"), "build_llm_deps")
    facts = _role_facts_yaml() or _role_facts_scan()

    for role, (ffile, ffn, note, slot, node, family) in _ROLE_SPEC.items():
        # 1) topology.BIND 가 올바른 슬롯을 올바른 노드에 바인딩(뒤바뀌지 않음); graph.py 와
        #    e2e._TickExecutor 가 이 단일 recipe 를 소비(PA-9).
        rep.check(slot_map.get(node) == slot,
                  f"topology.BIND['{node}'] must map llm -> '{slot}' "
                  f"(got {slot_map.get(node)!r})")

        # 2) build_llm_deps 가 매칭 팩토리를 통해 이 슬롯을 노출
        rep.check(f'"{slot}"' in deps_src or f"'{slot}'" in deps_src,
                  f"build_llm_deps must expose '{slot}'")
        rep.check(ffn in deps_src, f"build_llm_deps must call {ffn}()")

        # 3) 팩토리가 roles['<role>'] 를 읽고 매칭 note 타입을 반환
        fsrc = _fn_source(os.path.join(LLM, ffile), ffn)
        rep.check(f'"{role}"' in fsrc or f"'{role}'" in fsrc,
                  f"{ffile}:{ffn} must look up roles['{role}']")
        rep.check(note in fsrc, f"{ffile}:{ffn} must produce {note}")

        # 4) models.yaml role facts: 계열 라우팅 + response_model + fallback 리스트
        f = facts.get(role, {})
        rep.check(family in f.get("model", "").lower(),
                  f"models.yaml roles.{role}.model must be the {family} family "
                  f"(got {f.get('model')!r})")
        rep.check(f.get("response_model") == note,
                  f"models.yaml roles.{role}.response_model must be {note} "
                  f"(got {f.get('response_model')!r})")
        fb = f.get("fallback", [])
        rep.check(len(fb) >= 1, f"models.yaml roles.{role} must declare a fallback list")
        rep.check(bool(fb) and fb[0] != f.get("model"),
                  f"models.yaml roles.{role} fallback head must differ from primary model")

    return rep


def test_verify_models_alignment():
    """pytest 진입점: config<->code role-to-model 라우팅이 정합해야 함(뒤바뀜 없음)."""
    rep = _check()
    assert not rep.fails, "; ".join(rep.fails)


if __name__ == "__main__":
    run(_check)
