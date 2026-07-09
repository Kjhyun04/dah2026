"""P2 실행검증 — SidecarManager + recon-only run-driver (오프라인·docker 무접속).

검증 범위(코드+파서만·테스트베드 무실행):
  A. import 스모크: core.driver / core.modules.sidecar / core.orchestrator.
  B. SidecarManager: container_of(순수 해석) · run_argv/exists_argv/reap 조립(금지패턴 부재) ·
     ensure/teardown 오프라인 no-op(mock backend).
  C. build_backend(local) 배선: container_of=SidecarManager 주입 정상.
  D. TargetResolver 연결: config.tgt->role 매핑 + backend 경유.
  E. recon-only 폐루프 dry-run(no_llm seed-only): MockBackend canned recon -> KB 시드 ->
     CampaignResult -> JSONL. 주입 tool 미노출(scope RECON) 확인.
  F. recon-only ReAct 루프(replay LLM · llm.completion 오프라인 강제): step 기록 검증.

통과 시 exit 0.
"""

from __future__ import annotations
_import_sys=__import__('sys'); _import_os=__import__('os')
from pathlib import Path as _Path
_REPO=_Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path: _import_sys.path.insert(0,str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root -> cwd-relative paths resolve

import asyncio
import json
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_fail = 0


def check(label: str, cond: bool) -> None:
    global _fail
    if not cond:
        _fail += 1
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


# ═══════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("A · import 스모크")
print("=" * 70)

from pydantic import ValidationError

from core.common.config import (
    GoalSpec,
    InputSpec,
    load_config,
    load_goal,
    load_goal_spec,
    load_input,
    parse_goal_expr,
)
from core.common.results import CampaignResult
from core.modules.backends import ExecOutput, LocalBackend, MockBackend
from core.modules.resolve import TargetResolver
from core.modules.safeexec import LABEL_KEY, LABEL_VALUE
from core.modules.sidecar import SidecarManager, SidecarSpec
from core import driver as D

check("import core.driver / sidecar / backends OK", True)

_CFG = "configs/config.example.yaml"
_GOAL = "goals/goal.example.yaml"
cfg = load_config(_CFG)
goal = load_goal(_GOAL)
check("load_config/load_goal OK", cfg is not None and goal is not None)


# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("B · SidecarManager 조립/커맨드/오프라인 no-op")
print("=" * 70)

specs = D.build_sidecar_specs(cfg)
mgr = SidecarManager(specs=specs)
kinds = mgr.kinds
check("specs 포함 ue/sgi (core=vantage.core 지정 시)", "ue" in kinds and "sgi" in kinds)

# container_of 순수 해석(우리 접두 · 벤티지 대상 아님)
check("container_of(ue) == dah_tools_ue", mgr.container_of("ue") == "dah_tools_ue")
check("container_of(sgi) == dah_tools_sgi", mgr.container_of("sgi") == "dah_tools_sgi")
try:
    mgr.container_of("host")
    check("container_of(host) rejected", False)
except Exception:
    check("container_of(host) rejected (CRSError)", True)

# run_argv: 라벨·netns·이미지·sleep infinity · 금지패턴(--rm) 부재
ue_argv = mgr.run_argv("ue")
check("run_argv(ue) 우리 라벨 부여", f"{LABEL_KEY}={LABEL_VALUE}" in ue_argv)
check(
    "run_argv(ue) netns 공유(container:<vantage.ue>)",
    "container:" + cfg.exec_.vantage.ue in ue_argv,
)
check("run_argv(ue) 이미지=tools.image.air", cfg.tools.image.air in ue_argv)
check("run_argv(ue) CMD=sleep infinity(장수)", ue_argv[-2:] == ("sleep", "infinity"))
check("run_argv(ue) '--rm' 부재(금지)", "--rm" not in ue_argv)
check("run_argv(ue) '-d' detached", "-d" in ue_argv)

sgi_argv = mgr.run_argv("sgi")
check(
    "run_argv(sgi) net 연결(--network <vantage.sgi> · netns 아님)",
    cfg.exec_.vantage.sgi in sgi_argv and ("container:" + cfg.exec_.vantage.sgi) not in sgi_argv,
)

ex_argv = mgr.exists_argv("ue")
check("exists_argv 우리 라벨 필터", f"label={LABEL_KEY}={LABEL_VALUE}" in ex_argv)
check("exists_argv 이름 완전일치 필터", "name=^dah_tools_ue$" in ex_argv)

reap_argv = mgr.reap_ls_argv()
check("reap_ls_argv 우리 라벨만 조회(넓은 회수 아님)", f"label={LABEL_KEY}={LABEL_VALUE}" in reap_argv)


async def _sidecar_offline() -> tuple:
    # 미바인딩: ensure 는 Err(오프라인)
    r_unbound = await mgr.ensure("ue")
    # mock backend 바인딩: docker 미접속(mock)라 ensure/teardown 무해 Ok
    mb = MockBackend(workdir=Path(_ROOT / ".cache_verify"))
    mgr.bind_backend(mb)
    r_ensure = await mgr.ensure("ue")
    r_teardown = await mgr.teardown()
    return r_unbound, r_ensure, r_teardown


_ru, _re, _rt = asyncio.run(_sidecar_offline())
check("ensure(미바인딩) → Err(오프라인 무실행)", type(_ru).__name__ == "Err")
check("ensure(mock backend) → Ok(name)", type(_re).__name__ == "Ok" and _re.value == "dah_tools_ue")
check("teardown(mock, ids 없음) → Ok(None)", type(_rt).__name__ == "Ok")


# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("C · build_backend(local) — container_of=SidecarManager 주입 배선")
print("=" * 70)

mgr2 = D.build_sidecar_manager(cfg)
be_local = D.build_backend(
    cfg, kind="local", workdir=Path(_ROOT / ".cache_verify"), mgr=mgr2
)
check("LocalBackend 조립 OK(container_of 주입)", isinstance(be_local, LocalBackend))
# on_host 가 아닌 사이드카 argv 조립 시 container_of 로 사이드카 해석되는지(순수 확인)
_argv = be_local._container_argv(  # noqa: SLF001 — 배선 검증용
    __import__("core.modules.backends", fromlist=["ExecRequest"]).ExecRequest(
        sidecar="ue", argv=("recon.sh",), tool_id="t"
    ),
    30.0,
    "deadbeef",
)
check(
    "local exec argv 가 사이드카 이름(dah_tools_ue) 경유",
    "dah_tools_ue" in _argv and _argv[0:3] == ["docker", "exec", "-i"],
)


# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("D · TargetResolver 연결 (role→컨테이너 + backend 경유)")
print("=" * 70)

res = D.build_resolver(cfg, be_local)
check("TargetResolver 조립 OK", isinstance(res, TargetResolver))
check("resolver.container_of(oracle) == config.tgt.oracle", res.container_of("oracle") == cfg.tgt.oracle)
check("resolver.container_of(mongo) == config.tgt.mongo", res.container_of("mongo") == cfg.tgt.mongo)


# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("E · recon-only 폐루프 dry-run (no_llm seed-only · MockBackend canned)")
print("=" * 70)

# canned recon 출력(tool_id 키). reach 에 net_core 포함 -> recon_session 도 시드.
_reach = [
    f"{t}@10.50.0.1:0"
    for t in ("net_core", "mongo", "sgi", "gcs14556", "gcs14555", "web8080", "uav5762", "s1u", "pivot")
]
mock_table = {
    "recon_reach": ExecOutput(
        returncode=0, stdout=json.dumps({"reach": _reach, "signing": "on"})
    ),
    "recon_session": ExecOutput(
        returncode=0, stdout=json.dumps({"seid": "0xABCD", "sessions": 2})
    ),
}

drv = D.build_driver(
    cfg, goal, backend_kind="mock", recon_only=True, no_llm=True, mock_table=mock_table,
    workdir=Path(_ROOT / ".cache_verify"),
)
# recon-only scope -> 노출 tool 이 RECON 계층뿐(주입 tool 미노출)
_ids = drv.orch._ids  # noqa: SLF001
from core.modules.registry import get_spec  # noqa: E402
from core.common.types import Layer  # noqa: E402

check("recon-only: 노출 tool 전부 RECON 계층", all(get_spec(i).layer == Layer.RECON for i in _ids))
check("recon-only: 주입 tool(oracle/forge_sign) 미노출", "oracle" not in _ids and "forge_sign" not in _ids)

result = asyncio.run(drv.run())
check("run() → CampaignResult", isinstance(result, CampaignResult))
kbf = result.kb_final
check("seed: reach(net_core) KB 반영", "reach(net_core)" in kbf.get("facts", []))
check("seed: reach(sgi) KB 반영", "reach(sgi)" in kbf.get("facts", []))
check("seed: signing=on 반영", kbf.get("scalars", {}).get("signing") == "on")
check("seed: seid 아티팩트 반영", "seid" in kbf.get("artifacts", []))
check("no_llm: LLM 스텝 0(seed-only, chain 비어있음)", len(result.chain) == 0)

# JSONL 산출
jsonl = D.campaign_to_jsonl(result)
lines = [ln for ln in jsonl.splitlines() if ln.strip()]
last = json.loads(lines[-1])
check("JSONL 마지막 줄 = campaign_result", last.get("type") == "campaign_result")
check("JSONL kb_final 포함", "kb_final" in last)
_out = D.write_jsonl(result, Path(_ROOT / ".cache_verify" / "run_verify.jsonl"))
check("write_jsonl 파일 기록", _out.exists())


# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("F · recon-only ReAct 루프 (replay LLM · llm.completion 오프라인 강제)")
print("=" * 70)

# llm.completion 을 오프라인 결정론으로 강제(스크립트 소진 후 live 호출 차단).
import core.common.llm as _llm  # noqa: E402
from core.modules.tool_wrap import Err as _Err, CRSError as _CRSError  # noqa: E402

_orig_completion = _llm.completion


def _offline_completion(**kw):
    mock = kw.get("mock_response")
    if mock is not None:
        return _orig_completion(**kw)  # replay 경로만 통과
    return _Err(_CRSError("offline: live LLM 차단(verify)"))


# orchestrator 는 `from core.common import llm; llm.completion(...)` 로 호출 -> 모듈속성 치환.
_llm.completion = _offline_completion  # type: ignore[assignment]
try:
    replay = D.recon_replay([("recon_reach", "{}"), ("recon_defense", "{}")])
    drv2 = D.build_driver(
        cfg, goal, backend_kind="mock", recon_only=True, no_llm=False,
        mock_table=mock_table, replay=replay, workdir=Path(_ROOT / ".cache_verify"),
    )
    # recon_defense precond=reach(sgi) -> seed_recon(recon_reach) 로 먼저 열림.
    result2 = asyncio.run(drv2.run())
    check("run() → CampaignResult (ReAct)", isinstance(result2, CampaignResult))
    tool_ids = [s.tool_id for s in result2.chain]
    check("ReAct: replay 로 recon 스텝 실행됨(chain 비어있지 않음)", len(tool_ids) >= 1)
    check("ReAct: 실행 tool 전부 RECON 계층(주입 미실행)",
          all(get_spec(t).layer == Layer.RECON for t in tool_ids))
finally:
    _llm.completion = _orig_completion  # 원복


# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("G · 소규모 결정 확정 (goal.defense/success · CLI goal expr · TgtSpec 닫힘)")
print("=" * 70)

gs = load_goal_spec(_GOAL)
check("goal.example defense=auto 로드", gs.defense == "auto")
check("goal.example success=ack 로드", gs.success == "ack")
check("GoalSpec.to_goal 은 type/target/scope 만 전달(하위호환)", gs.to_goal().type == gs.type)

node = parse_goal_expr("signing_bypass mode=5 defense=on success=ground_truth scope=A,C")
gs2 = GoalSpec.model_validate(node)
check("CLI goal expr: type 파싱", gs2.type == "signing_bypass")
check("CLI goal expr: target.mode 파싱", str(gs2.target.get("mode")) == "5")
check("CLI goal expr: defense 파싱", gs2.defense == "on")
check("CLI goal expr: success 파싱", gs2.success == "ground_truth")
check("CLI goal expr: scope 파싱", gs2.scope == ["A", "C"])

_cfg2, _goal2 = load_input(_CFG, cli_goal="mode_set mode=4 defense=off success=ack scope=A,D")
check("load_input(cli_goal) goal 생성", _goal2 is not None and _goal2.type == "mode_set")
check("load_input(cli_goal) target.mode=4", str((_goal2.target or {}).get("mode")) == "4")

# TgtSpec(extra=forbid) 닫힘 정책: 미등록 role 키는 ValidationError
try:
    _ = InputSpec.model_validate(
        {
            "testbed": {"host": "h", "user": "u", "ssh_key": "k"},
            "exec": {"vantage": {"ue": "attacker_ue", "sgi": "net_sgi"}},
            "tools": {"image": {"air": "dahv2/air"}},
            "llm": {"mode": "replay", "model": "m", "api_key_env": "K"},
            "tgt": {"unknown_role": "x"},
        }
    )
    check("TgtSpec extra=forbid (unknown_role 거부)", False)
except ValidationError:
    check("TgtSpec extra=forbid (unknown_role 거부)", True)


# ═══════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
if _fail == 0:
    print("ALL CHECKS PASSED (0 failures)")
    sys.exit(0)
else:
    print(f"{_fail} CHECK(S) FAILED")
    sys.exit(1)
