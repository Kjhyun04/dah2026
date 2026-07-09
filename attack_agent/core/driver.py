"""core.driver — recon-only run-driver (P2/P3 실행 글루).

부트스트랩 폐루프(13 §6 · 10 §1):
  load_config/load_goal -> premise_facts -> WorldState.initial
    -> SidecarManager(config) -> Backend(container_of=SidecarManager)
    -> make_runner_factory(safeexec) -> AttackOrchestrator -> run() -> CampaignResult(JSONL).

완전 오프라인: 기본 백엔드는 **MockBackend**(docker/테스트베드 무접속). LocalBackend/
  SshBackend 배선은 정본 코드로 조립만 하며 실행은 사람 런북(gate-1)이 수행한다.
recon-only 프로파일(명시 옵션): goal.scope 를 RECON 으로 강제 -> 노출/실행 tool 이
  RECON 계층(PROBE/COLLECT-recon)뿐 -> **주입(INJECT) tool 은 구조적으로 미실행**.
  offline dry-run(no_llm)은 auto_seed_recon 만으로 KB 를 시드하고 LLM 루프를 건너뛴다.
TargetResolver 연결: 동일 backend(container_of=SidecarManager)를 주입 -> role->IP 해석의
  사이드카 exec 가 SidecarManager 를 경유(13 §5). 오프라인 무실행(런북).

불변식: 하드코딩0(전부 config) · grep0 · 레시피 금지 · 종료계약(teardown=우리 라벨 rm -f).
작성 2026-07-06.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

from core.common.config import InputSpec
from core.common.llm import ReplayLLM
from core.common.results import CampaignResult
from core.modules.backends import (
    Backend,
    Err,
    ExecOutput,
    LocalBackend,
    MockBackend,
    SshBackend,
    resolve_backend_kind,
)
from core.modules.kb import Goal, WorldState
from core.modules.resolve import Net, TargetResolver
from core.modules.safeexec import Vault, make_runner_factory
from core.modules.sidecar import SidecarManager, SidecarSpec
from core.agents import EvidenceAgent
from core.obs import C2Observer
from core.orchestrator import AttackOrchestrator, ReplayHook

try:  # Windows 콘솔(cp949) 유니코드 출력 보호(과제 지침).
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass


# ═══════════════════════════════════════════════════════════════════════════
# 1. 사이드카 규격 조립 (config -> SidecarSpec). 하드코딩0: 전부 config 파생.
# ═══════════════════════════════════════════════════════════════════════════

# 벤티지 netns 공유 정책(13 §3 구조 사실 · IP/이름 아님):
# ue = attacker_ue netns 공유(--network container:) -> rogue UE 시야.
# core= pivot netns 공유(--network container:) -> pivot 후 net_core 시야.
#   sgi = net_sgi 네트워크 연결(--network <net>).
_NETNS_SHARE: dict[str, bool] = {"ue": True, "core": True, "sgi": False}


def build_sidecar_specs(cfg: InputSpec) -> list[SidecarSpec]:
    """config.exec.vantage + tools.image -> SidecarSpec 목록(ue/sgi/(core)).

    core 는 vantage.core 지정 시에만(옵션). 이미지: pfcp 툴링 있으면 core=pfcp, 없으면 air.
    """
    v = cfg.exec_.vantage
    img = cfg.tools.image
    specs: list[SidecarSpec] = [
        SidecarSpec("ue", img.air, v.ue, netns_share=_NETNS_SHARE["ue"]),
        SidecarSpec("sgi", img.air, v.sgi, netns_share=_NETNS_SHARE["sgi"]),
    ]
    if v.core:
        core_image = img.pfcp or img.air
        specs.append(
            SidecarSpec("core", core_image, v.core, netns_share=_NETNS_SHARE["core"])
        )
    return specs


def build_sidecar_manager(
    cfg: InputSpec, *, docker_bin: str = "docker", backend: Optional[Backend] = None
) -> SidecarManager:
    """config -> SidecarManager(container_of 리졸버 제공). backend 는 이후 bind 가능."""
    return SidecarManager(
        specs=build_sidecar_specs(cfg), docker_bin=docker_bin, backend=backend
    )


# ═══════════════════════════════════════════════════════════════════════════
# 2. WorldState 초기화 (premise footholds -> 초기 사실)
# ═══════════════════════════════════════════════════════════════════════════


def build_worldstate(cfg: InputSpec, *, signing: Optional[str] = None) -> WorldState:
    """premise.footholds/weakcred_pivot -> WorldState.initial.

    signing: goal.defense∈{on,off} 이면 config 선언으로 시드(prov=config, D18·19 PART1-1).
      'auto'/None 이면 미시드 -> recon_defense/lazy 학습 소유(정직: 미충족은 계층 보수 봉쇄).
    """
    from core.modules.kb import Signing

    sig: Optional[Signing] = None
    if signing == "on":
        sig = Signing.ON
    elif signing == "off":
        sig = Signing.OFF
    return WorldState.initial(footholds=cfg.premise_facts(), signing=sig)


# ═══════════════════════════════════════════════════════════════════════════
# 3. 백엔드 조립 (mock=오프라인 기본 · local/ssh=런북 정본)
# ═══════════════════════════════════════════════════════════════════════════


def build_backend(
    cfg: InputSpec,
    *,
    kind: str,
    workdir: Path,
    mgr: SidecarManager,
    docker_bin: str = "docker",
    mock_table: Optional[Mapping[str, ExecOutput]] = None,
    mock_live_local: bool = False,
) -> Backend:
    """exec.mode/명시 kind -> Backend. container_of=SidecarManager 주입(local/ssh).

    kind ∈ {'mock','local','ssh'}. 'mock' 은 오프라인 폐루프 기본(docker 무접속).
    local/ssh 는 정본 배선(실행은 런북) — SidecarManager.container_of 로 사이드카 해석.
    """
    if kind == "mock":
        return MockBackend(
            table=dict(mock_table or {}),
            live_local=mock_live_local,
            workdir=workdir,
        )
    if kind == "local":
        return LocalBackend(
            workdir=workdir,
            container_of=mgr.container_of,
            docker_bin=docker_bin,
            default_timeout_s=float(cfg.run.termination_timeout),
        )
    if kind == "ssh":
        tb = cfg.testbed
        return SshBackend(
            host=tb.host,
            user=tb.user,
            ssh_key=tb.ssh_key,
            workdir=workdir,
            container_of=mgr.container_of,
            docker_bin=docker_bin,
            default_timeout_s=float(cfg.run.termination_timeout),
        )
    raise ValueError(f"unknown backend kind: {kind!r} (mock|local|ssh)")


def resolve_backend_from_config(cfg: InputSpec) -> str:
    """config.exec.mode -> 백엔드 종류('local'|'ssh'|'mock'). (docker_exec/host->local)."""
    return resolve_backend_kind(cfg.exec_.mode)


# ═══════════════════════════════════════════════════════════════════════════
# 4. TargetResolver 연결 (role->IP 해석이 backend(=SidecarManager) 경유)
# ═══════════════════════════════════════════════════════════════════════════


def build_resolver(
    cfg: InputSpec, backend: Backend, *, docker_bin: str = "docker"
) -> TargetResolver:
    """config.tgt(role->컨테이너명) + backend -> TargetResolver. 사이드카 exec 는 backend 경유.

    backend.container_of=SidecarManager 이므로 identify 프로브(sidecar='ue')가 사이드카를
    SidecarManager 로 해석한다(13 §5 연결). net_names 재매핑: config 는 이름만이라 기본 enum.
    """
    tgt = {k: v for k, v in cfg.tgt.model_dump().items() if v}
    net_names: dict[Net, str] = {}
    sgi = cfg.exec_.vantage.sgi
    if sgi:
        # sgi 벤티지 값이 net_sgi 논리이름 재매핑(인스턴스 흡수). 하드코딩 0.
        net_names[Net.SGI] = sgi
    return TargetResolver(
        backend=backend, tgt=tgt, net_names=net_names, docker_bin=docker_bin
    )


# ═══════════════════════════════════════════════════════════════════════════
# 5. 오케스트레이터 조립 (recon-only 프로파일)
# ═══════════════════════════════════════════════════════════════════════════

# recon-only scope 센티넬: A/B/C/D 미포함 -> scoped_tool_ids 가 RECON 계층만 노출.
_RECON_SCOPE: list[str] = ["RECON"]


def recon_only_goal(goal: Goal) -> Goal:
    """원 목표를 보존하되 scope 를 RECON 으로 강제(주입 tool 구조적 배제)."""
    return Goal(type=goal.type, target=dict(goal.target), scope=list(_RECON_SCOPE))


def build_orchestrator(
    cfg: InputSpec,
    goal: Goal,
    kb: WorldState,
    backend: Backend,
    *,
    recon_only: bool = True,
    no_llm: bool = False,
    vault: Optional[Vault] = None,
    replay: Optional[ReplayHook] = None,
    preflight: bool = True,
    resolver: Optional[TargetResolver] = None,
) -> AttackOrchestrator:
    """AttackOrchestrator 조립. recon_only -> RECON scope. no_llm -> seed-only(LLM 루프 생략).

    no_llm=True: auto_seed_recon 으로 recon 러너만 태워 KB 시드 후 즉시 종료(max_steps=0).
      완전 오프라인·결정론(LLM 미호출). recon-only dry-run 의 기본.
    no_llm=False: 정상 ReAct 루프(replay 또는 live LLM). recon_only 면 노출 tool=RECON.

    resolver: INJECT tool 의 args_template IP placeholder({oracle_ip}/{cipher_ip}) 를 실행
      시점에 role->IP 로 해석해 주입(safeexec make_runner (0)단계). 미전달 시 IP placeholder
      tool 은 fail-closed(Err) — 실 캠페인은 build_driver 가 build_resolver 결과를 넘긴다.
    """
    g = recon_only_goal(goal) if recon_only else goal
    # 모델 해석(A5·07 §4): llm.models_path 지정 시 configs/models.yaml 로 role->routable 해석.
    #   미지정이면 cfg.llm.model 그대로(하위호환·회귀 0). override=cfg.llm.model(운영자 명시 존중).
    model = cfg.llm.model
    mm = None
    if cfg.llm.models_path:
        from core.common.models import load_model_map, resolve_model

        mm = load_model_map(cfg.llm.models_path)
        model = resolve_model("AttackOrchestrator", mm, override=cfg.llm.model)
    # runner_factory 는 backend 주입 시 orchestrator 내부에서 make_runner_factory 로 배선.
    # (동일 팩토리를 seed_recon 이 재사용 -> 정찰 러너도 실행엔진에 연결.)
    _rf = make_runner_factory(
        backend=backend,
        vault=vault or Vault(),
        timeout_s=cfg.run.termination_timeout,
        preflight=preflight,
        resolver=resolver,
    )
    observer = None
    if cfg.observer.enabled:
        observer = C2Observer(
            port=cfg.observer.port,
            iface=cfg.observer.iface,
            sample_s=cfg.observer.sample_s,
            gap_s=cfg.observer.gap_s,
            quiet_pps=cfg.observer.quiet_pps,
            tcpdump_bin=cfg.observer.tcpdump_bin,
            max_packets=cfg.observer.max_packets,
        )
    evidence = None
    if cfg.evidence.enabled:
        evidence_model = model
        if mm is not None:
            from core.common.models import resolve_model

            evidence_model = resolve_model("Evidence", mm)
        use_evidence_llm = (
            (not no_llm)
            and replay is None
            and cfg.llm.mode == "live"
            and bool(os.environ.get(cfg.llm.api_key_env))
        )
        evidence = EvidenceAgent(
            model=evidence_model,
            temperature=cfg.evidence.temperature,
            max_chars=cfg.evidence.max_chars,
            use_llm=use_evidence_llm,
        )
    max_steps = 0 if no_llm else cfg.run.max_iters
    return AttackOrchestrator(
        goal=g,
        kb=kb,
        model=model,
        runner_factory=_rf,
        backend=backend,  # teardown 훅(자원회수) 용
        replay=replay,
        max_steps=max_steps,
        max_pivots=cfg.run.max_pivots,
        timeout_s=cfg.run.termination_timeout,
        observer=observer,
        evidence=evidence,
        auto_seed_recon=True,  # init baseline: recon 러너로 KB 시드(12 §5)
    )


# ═══════════════════════════════════════════════════════════════════════════
# 6. Driver — 조립 + 실행 + JSONL 산출
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class Driver:
    """부트스트랩 조립 결과 묶음(재사용/검사 가능). run() 이 폐루프를 돈다."""

    cfg: InputSpec
    goal: Goal
    kb: WorldState
    mgr: SidecarManager
    backend: Backend
    orch: AttackOrchestrator
    resolver: TargetResolver
    recon_only: bool = True
    no_llm: bool = False

    async def run(self) -> CampaignResult:
        """캠페인 실행 -> CampaignResult. 종료 후 사이드카 우리-라벨 rm -f(원자 회수).

        orch.run() 이 backend.teardown()(per-job PGID reap)을 finally 로 보장하고,
        여기서 SidecarManager.teardown()(라벨 컨테이너 원자 회수·정본)을 추가 수행한다.
        오프라인(mock/미바인딩)에선 teardown 이 no-op.
        """
        # live/local/ssh 경로는 실행 전에 장수 사이드카를 보장해야 한다.
        # (ensure 미실행 시 docker exec 대상 부재 -> preflight rc=1 연쇄 오류)
        if not isinstance(self.backend, MockBackend):
            self.mgr.bind_backend(self.backend)
            # 필수 벤티지: ue/sgi. core 는 환경에 따라 pivot 컨테이너가 없을 수 있어 optional.
            for kind in ("ue", "sgi"):
                if kind not in self.mgr.kinds:
                    continue
                ensured = await self.mgr.ensure(kind)
                if isinstance(ensured, Err):
                    raise RuntimeError(f"sidecar ensure failed ({kind}): {ensured.error}")
            if "core" in self.mgr.kinds:
                _core = await self.mgr.ensure("core")
                # core 미가용은 B계층 실험에서만 필요하므로 런 전체를 중단하지 않는다.
                # (해당 tool 실행 시 legality/실행 단계에서 정직하게 ERROR 처리)
        try:
            return await self.orch.run()
        finally:
            self.mgr.bind_backend(self.backend)
            await self.mgr.teardown()


def build_driver(
    cfg: InputSpec,
    goal: Goal,
    *,
    backend_kind: Optional[str] = None,
    workdir: Optional[Path] = None,
    docker_bin: str = "docker",
    recon_only: bool = True,
    no_llm: bool = True,
    mock_table: Optional[Mapping[str, ExecOutput]] = None,
    mock_live_local: bool = False,
    replay: Optional[ReplayHook] = None,
    defense: Optional[str] = None,
) -> Driver:
    """config+goal -> 완전 조립된 Driver.

    backend_kind 미지정 시: no_llm(오프라인 dry-run)=mock, 아니면 config.exec.mode 파생.
    workdir 미지정 시: config.out.log 디렉터리(파일 캡처 임시경로).
    defense∈{on,off}: signing 을 config 선언으로 시드(signing_bypass 목표 판정용).
    """
    wd = Path(workdir) if workdir else Path(cfg.out.log).resolve().parent
    wd.mkdir(parents=True, exist_ok=True)

    kind = backend_kind or ("mock" if no_llm else resolve_backend_from_config(cfg))
    # mock 이 아니면 preflight 실측(local R3). mock/no_llm 은 preflight 통과(무접속).
    preflight = kind not in ("mock",)

    mgr = build_sidecar_manager(cfg, docker_bin=docker_bin)
    backend = build_backend(
        cfg,
        kind=kind,
        workdir=wd,
        mgr=mgr,
        docker_bin=docker_bin,
        mock_table=mock_table,
        mock_live_local=mock_live_local,
    )
    mgr.bind_backend(backend)  # ensure/teardown docker 발화 백엔드 주입
    resolver = build_resolver(cfg, backend, docker_bin=docker_bin)

    kb = build_worldstate(cfg, signing=defense)
    orch = build_orchestrator(
        cfg,
        goal,
        kb,
        backend,
        recon_only=recon_only,
        no_llm=no_llm,
        replay=replay,
        preflight=preflight,
        resolver=resolver,  # INJECT args_template IP placeholder 런타임 해석·주입
    )
    return Driver(
        cfg=cfg,
        goal=goal,
        kb=kb,
        mgr=mgr,
        backend=backend,
        orch=orch,
        resolver=resolver,
        recon_only=recon_only,
        no_llm=no_llm,
    )


# ═══════════════════════════════════════════════════════════════════════════
# 7. JSONL 산출 (viewer/심사 근거) — steps 스트림 + 최종 CampaignResult
# ═══════════════════════════════════════════════════════════════════════════


def campaign_to_jsonl(result: CampaignResult) -> str:
    """CampaignResult -> JSONL 문자열. 각 step 1줄 + 마지막 요약 1줄(type 태그).

    grep0/완전분리: 공격자-가시 payload 만(감독 truth 없음). kb_final 은 마스킹 스냅샷.
    """
    lines: list[str] = []
    for st in result.chain:
        rec = {"type": "step", **st.model_dump()}
        lines.append(json.dumps(rec, ensure_ascii=False, default=str))
    summary = {
        "type": "campaign_result",
        "goal_reached": result.goal_reached,
        "steps": len(result.chain),
        "defenses_bypassed": result.defenses_bypassed,
        "win_causes": result.win_causes,
        "kb_final": result.kb_final,
        "evidence_notes": result.evidence_notes,
    }
    lines.append(json.dumps(summary, ensure_ascii=False, default=str))
    return "\n".join(lines) + "\n"


def write_jsonl(result: CampaignResult, path: str | Path) -> Path:
    """CampaignResult JSONL 을 out.log 경로에 기록. 반환=기록 경로."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(campaign_to_jsonl(result), encoding="utf-8")
    return p


# ═══════════════════════════════════════════════════════════════════════════
# 8. 오프라인 결정론 replay 헬퍼(검증·심사 재현) — recon 스텝 스크립트
# ═══════════════════════════════════════════════════════════════════════════


def recon_replay(steps: list[tuple[str, str]]) -> ReplayLLM:
    """(tool, args-json) 시퀀스 -> ReplayLLM(litellm 미호출 결정론 재생).

    recon-only 폐루프를 LLM 없이 재현(예: [('recon_reach','{}'),('recon_defense','{}')]).
    """
    return ReplayLLM(steps)


__all__ = [
    "build_sidecar_specs",
    "build_sidecar_manager",
    "build_worldstate",
    "build_backend",
    "resolve_backend_from_config",
    "build_resolver",
    "recon_only_goal",
    "build_orchestrator",
    "Driver",
    "build_driver",
    "campaign_to_jsonl",
    "write_jsonl",
    "recon_replay",
]
