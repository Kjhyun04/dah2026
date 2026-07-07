"""verify_viewer — 뷰어 오프라인 자기검증(전부 로컬·exit0 목표·네트워크 0).

검증 항목:
  (1) py_compile: viewer/*.py 전량 컴파일 통과.
  (2) AST 분리(grep0): viewer 가 core/supervisor 정적·동적 import 안 함 ·
      action_log write-open 부재 · server 에 @app.post/put/delete/patch 부재(변경 엔드포인트 0).
  (3) HTML/JS 자기완결: 외부 URL(http(s)://··//cdn··fonts) 부재 · EventSource('/sse') ·
      3패널 컨테이너 id(panel-action/panel-comms/panel-supervisor) 존재.
  (4) ingest 라운드트립: action/evaluation/comms 샘플 로드 · frames_from_evaluation 재구성.
  (5) redact: 계획 secret 주입→마스킹 확인 · build_snapshot 직렬화 전체 _SECRET_RE 잔존 0.
  (6) 분류 정합(soft): registry importable 이면 INJECT 집합 & len==22 경고성 대조(FAIL 아님).

이 파일은 fastapi/uvicorn/pymavlink 미설치라도 통과한다(server 는 compile 만, import 안 함).
작성 2026-07-06.
"""
from __future__ import annotations

import ast
import json
import py_compile
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_fail = 0
_warn = 0


def check(label: str, cond: bool) -> None:
    global _fail
    if not cond:
        _fail += 1
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def warn(label: str, cond: bool) -> None:
    global _warn
    if not cond:
        _warn += 1
    print(f"  [{'ok ' if cond else 'WARN'}] {label}")


# ── (1) py_compile ─────────────────────────────────────────────────────────
print("[1] py_compile")
_py = sorted(_HERE.glob("*.py"))
_compiled = True
for f in _py:
    try:
        py_compile.compile(str(f), doraise=True)
    except py_compile.PyCompileError as e:
        _compiled = False
        print("      compile FAIL:", f.name, e)
check(f"viewer/*.py 컴파일 ({len(_py)} 파일)", _compiled)


# ── (2) AST 분리(grep0) ────────────────────────────────────────────────────
print("[2] AST 분리(grep0)")
_bad_import: list[str] = []
_bad_write: list[str] = []
_bad_route: list[str] = []
_MUT_METHODS = {"post", "put", "delete", "patch"}
_WRITE_MODES = re.compile(r"[wax]")

for f in _py:
    if f.name == "verify_viewer.py":
        continue
    tree = ast.parse(f.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        # 정적 import
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if top in ("core", "supervisor"):
                    _bad_import.append(f"{f.name}: import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if top in ("core", "supervisor"):
                _bad_import.append(f"{f.name}: from {node.module}")
            for a in node.names:
                if a.name in ("core", "supervisor"):
                    _bad_import.append(f"{f.name}: from . import {a.name}")
        elif isinstance(node, ast.Call):
            fn = node.func
            fname = (fn.attr if isinstance(fn, ast.Attribute)
                     else fn.id if isinstance(fn, ast.Name) else "")
            # 동적 import
            if fname in ("import_module", "__import__") and node.args:
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    if a0.value.split(".")[0] in ("core", "supervisor"):
                        _bad_import.append(f"{f.name}: dynamic import {a0.value!r}")
            # write-open 탐지: open(..., mode) with w/a/x  OR  .open(mode=...) with w/a/x
            if fname == "open":
                mode = None
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    mode = node.args[1].value
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
                if isinstance(mode, str) and _WRITE_MODES.search(mode):
                    _bad_write.append(f"{f.name}: open(mode={mode!r})")
            # write_text/write_bytes = 파일 기록(뷰어 금지)
            if fname in ("write_text", "write_bytes"):
                _bad_write.append(f"{f.name}: .{fname}()")
        # 변경 엔드포인트 데코레이터: @app.post/put/delete/patch(...)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                d = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(d, ast.Attribute) and d.attr in _MUT_METHODS:
                    _bad_route.append(f"{f.name}: @*.{d.attr}")

check(f"core/supervisor 정적·동적 import 부재 (위반 {len(_bad_import)})", not _bad_import)
for b in _bad_import:
    print("      ", b)
check(f"파일 write-open/write_text 부재 (위반 {len(_bad_write)})", not _bad_write)
for b in _bad_write:
    print("      ", b)
check(f"변경 엔드포인트(post/put/delete/patch) 부재 (위반 {len(_bad_route)})", not _bad_route)
for b in _bad_route:
    print("      ", b)


# ── (3) HTML/JS 자기완결 ────────────────────────────────────────────────────
print("[3] HTML/JS 자기완결")
_static = _HERE / "static"
_html = (_static / "index.html").read_text(encoding="utf-8")
_js = (_static / "app.js").read_text(encoding="utf-8")
_ext = re.compile(r"https?://|//cdn|fonts\.googleapis|fonts\.gstatic")
_ext_hits = [m.group(0) for m in _ext.finditer(_html + "\n" + _js)]
check(f"외부 URL(http(s)/cdn/fonts) 부재 (hits {len(_ext_hits)})", not _ext_hits)
for h in set(_ext_hits):
    print("      ext:", h)
check("EventSource('/sse') 존재", "EventSource(\"/sse\")" in _js or "EventSource('/sse')" in _js)
for pid in ("panel-action", "panel-comms", "panel-supervisor"):
    check(f"컨테이너 id={pid} 존재", f'id="{pid}"' in _html)


# ── (4) ingest 라운드트립 ──────────────────────────────────────────────────
print("[4] ingest 라운드트립")
from viewer import ingest  # noqa: E402  (경로 삽입 후 import)

_sample = _HERE / "sample"
_act = ingest.load_action_log(_sample / "action.jsonl")
check("load_action_log: steps>0", _act["count"] > 0)
check("campaign.goal_reached bool",
      isinstance((_act["campaign"] or {}).get("goal_reached"), bool))

_ev = ingest.load_evaluation(_sample / "evaluation.json")
check("load_evaluation: schema=='dah.supervisor.evaluation/1'",
      (_ev or {}).get("schema") == "dah.supervisor.evaluation/1")
check("verdict.autonomy_accuracy 존재",
      "autonomy_accuracy" in ((_ev or {}).get("verdict") or {}))

_frames = ingest.load_comms_stream(_sample / "supervisor.jsonl")
check("load_comms_stream: 프레임 dir∈{up,down}",
      bool(_frames) and all(f["dir"] in ("up", "down") for f in _frames))

_recon = ingest.frames_from_evaluation(_ev)
check("frames_from_evaluation: 재구성 비어있지 않음", bool(_recon))
check("재구성 프레임 t 정렬 단조",
      all(_recon[i]["t"] <= _recon[i + 1]["t"] for i in range(len(_recon) - 1)))

_inj = ingest.inject_rows_from_action(_act["steps"])
check("inject_rows: INJECT tool 만 (source=attacker-inject)",
      all(r["tool_id"] in ingest.INJECT_TOOL_IDS and r["source"] == "attacker-inject" for r in _inj))
check("inject_rows: forge_sign/serial5762/naive 포함(3 주입)", len(_inj) == 3)

_snap = ingest.build_snapshot(_sample / "action.jsonl", _sample / "evaluation.json",
                              _sample / "supervisor.jsonl")
check("build_snapshot.banner.mismatch==True (agree=False)", _snap["banner"]["mismatch"] is True)
check("build_snapshot.comms.source=='stream'(스트림 존재)", _snap["comms"]["source"] == "stream")

# 스트림 부재 폴백 → reconstructed
_snap2 = ingest.build_snapshot(_sample / "action.jsonl", _sample / "evaluation.json", None)
check("스트림 부재 → comms.source=='reconstructed'", _snap2["comms"]["source"] == "reconstructed")


# ── (5) redact ─────────────────────────────────────────────────────────────
print("[5] redact")
_secret_hex = "59a5deadbeefcafe0011223344556677"  # 32 hex
_plain = {
    "aria_key": _secret_hex,
    "note": f"leaked key={_secret_hex} inline",
    "mode": "0xABCD",           # 짧은 0x — 보존되어야(임계 미달)
    "seid": "0x1F",
    "nested": {"sign_key": _secret_hex, "list": [_secret_hex, "safe"]},
}
_red = ingest.redact(_plain)
_dump = json.dumps(_red, ensure_ascii=False)
check("redact: 원문 secret hex 미노출", _secret_hex not in _dump)
check("redact: 짧은 0x mode 값 보존", _red["mode"] == "0xABCD")

# build_snapshot 직렬화 전체 _SECRET_RE 잔존 스캔(샘플 기준)
_snap_dump = json.dumps(_snap, ensure_ascii=False, default=str)
_residual = []
for pat in ingest._SECRET_RE:
    _residual += pat.findall(_snap_dump)
check(f"build_snapshot 직렬화 비밀토큰 잔존 0 (found {len(_residual)})", not _residual)


# ── (6) 분류 정합(soft: registry importable 시) ─────────────────────────────
print("[6] 분류 정합 (soft)")
try:
    from core.modules.registry import REGISTRY  # noqa: E402
    from core.common.types import ToolKind  # noqa: E402
    _inj_ids = {tid for tid, spec in REGISTRY.items() if spec.kind == ToolKind.INJECT}
    warn(f"len(REGISTRY)==22 (got {len(REGISTRY)})", len(REGISTRY) == 22)
    warn(f"INJECT_TOOL_IDS == registry INJECT 집합 (diff {ingest.INJECT_TOOL_IDS ^ _inj_ids})",
         ingest.INJECT_TOOL_IDS == _inj_ids)
    _reg_layers = {tid for tid in REGISTRY}
    warn("_LAYER 키가 registry tool 전량 커버",
         set(ingest._LAYER.keys()) >= _reg_layers)
except Exception as e:  # registry 미탑재 환경 → soft skip
    print(f"      [skip] registry 미import ({type(e).__name__}) — 분류정합 soft 생략")


# ── 요약 ────────────────────────────────────────────────────────────────────
print("=" * 60)
if _warn:
    print(f"soft WARN: {_warn} (coupling FAIL 아님)")
if _fail == 0:
    print("VIEWER VERIFY PASSED (offline, 0 failures)")
    sys.exit(0)
print(f"{_fail} CHECK(S) FAILED")
sys.exit(1)
