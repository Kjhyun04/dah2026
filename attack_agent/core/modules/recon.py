"""core.modules.recon — 정찰 러너 실내용: PROBE 파서·조립 + init baseline 시드 (12).

정찰 tool 3종(recon_reach·recon_defense·recon_session)의 **결정론 파서/조립**을
한 곳에 모은다. 실행 배선(ExecBinding->backend.run)은 safeexec.make_runner 가,
KB 반영은 kb.kb_update 가 담당하며, 이 모듈은 그 사이의 **PROBE->ReconResult 조립**과
**init 자동 baseline 시드 드라이버**(12 §5)를 제공한다.

baked 스크립트 stdout 규약(결정론 파싱, 12 §7):
  recon_reach   -> {"reach": [...], "unauth": [...], "identified": [...]}
  recon_defense -> {"signing": "on"|"off"|"unknown"}
  recon_session -> {"seid": "...", "sessions": N}
  (필드는 tool 별 부분집합. 없으면 보수 기본 — 애매하면 fact 미설정.)

정합(12 §9):
  - 공격자-관측만(감독 특권/평문 텔레메트리 배제). grep0: truth 미참조.
  - RO·종료계약: 파서는 순수 함수. baseline 드라이버는 러너(종료계약 내장) 호출만.
  - signing 은 recon_defense 가 config 선언을 반영하거나 unknown(-> 첫 공격 lazy 학습).
작성 2026-07-06.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Mapping, Optional

from core.common.results import ReconResult
from core.common.types import ReachTarget, reach
from core.modules.kb import WorldState, kb_update
from core.modules.tool_wrap import Ok, Result

# 러너 시그니처(safeexec.make_runner 산출물): params -> Result[ReconResult].
type Runner = Callable[..., Awaitable[Result[Any]]]

# 정찰 tool id(레지스트리 RECON 계층). 하드코딩 아님 — 레지스트리 어휘 참조.
RECON_REACH = "recon_reach"
RECON_DEFENSE = "recon_defense"
RECON_SESSION = "recon_session"

# signing 닫힌 어휘(results.ReconResult.signing 정합).
_SIGNING_VALS = frozenset({"on", "off", "unknown"})


# ═══════════════════════════════════════════════════════════════════════════
# 1. 필드 파서 (결정론 · 명확 신호만 · 12 §7 보수원칙)
# ═══════════════════════════════════════════════════════════════════════════


def _as_str_list(v: Any) -> list[str]:
    """JSON list -> str list. list 아니면 [](보수: 애매하면 미설정)."""
    if isinstance(v, list):
        return [str(x) for x in v]
    return []


def parse_signing(v: Any) -> str:
    """signing 원시값 -> 닫힌 어휘("on"/"off"/"unknown"). 밖이면 unknown(보수)."""
    s = str(v).strip().lower() if v is not None else "unknown"
    return s if s in _SIGNING_VALS else "unknown"


def parse_seid(v: Any) -> Optional[str]:
    """seid 원시값 -> str|None. None/빈값이면 None(미획득)."""
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def parse_sessions(v: Any) -> int:
    """활성 세션 수 -> int(실패/음수 방어 0)."""
    try:
        n = int(v)
    except (ValueError, TypeError):
        return 0
    return n if n >= 0 else 0


def parse_observed_mode(v: Any) -> Optional[int]:
    """observe_mode 실측 custom_mode -> int|None. None/bool/파싱실패 -> None(미관측·보수)."""
    if v is None or isinstance(v, bool):  # bool 은 int 하위형 — 오매칭 방지
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def parse_probe_json(stdout: str) -> dict[str, Any]:
    """PROBE stdout(JSON object) -> dict. 비-object/파싱실패 -> {}(보수)."""
    s = (stdout or "").strip()
    if not s:
        return {}
    try:
        d = json.loads(s)
    except (ValueError, TypeError):
        return {}
    return d if isinstance(d, dict) else {}


# ═══════════════════════════════════════════════════════════════════════════
# 2. 조립 — PROBE data -> ReconResult (safeexec.parse_output PROBE 정본)
# ═══════════════════════════════════════════════════════════════════════════


def build_recon_result(
    data: Mapping[str, Any], *, latency_ms: int = 0, killed: bool = False
) -> ReconResult:
    """PROBE 파싱 데이터 -> ReconResult (recon_reach/defense/session 공통 조립).

    reach/unauth/identified = str list. signing = 닫힌 어휘. seid/sessions = 세션.
    killed(하드타임아웃) 는 exec_meta 로 전사(보수판정 신호). grep0: truth 필드 없음.
    이 함수가 kind==PROBE 파서의 **단일 진실** — safeexec.parse_output 이 위임한다.
    """
    signing = parse_signing(data.get("signing", "unknown"))
    return ReconResult(
        reach=_as_str_list(data.get("reach")),
        unauth=_as_str_list(data.get("unauth")),
        signing=signing,
        seid=parse_seid(data.get("seid")),
        sessions=parse_sessions(data.get("sessions", 0)),
        identified=_as_str_list(data.get("identified")),
        observed_mode=parse_observed_mode(data.get("observed_mode")),
        latency_ms=int(latency_ms),
        killed=bool(killed),
    )


# ═══════════════════════════════════════════════════════════════════════════
# 3. runner_factory 배선 — recon 러너만 뽑아 KB 시드에 사용 (배선 최소 정리)
# ═══════════════════════════════════════════════════════════════════════════


def build_recon_runners(
    runner_factory: Callable[[Any], Runner],
    *,
    ids: tuple[str, ...] = (RECON_REACH, RECON_DEFENSE, RECON_SESSION),
) -> dict[str, Runner]:
    """orchestrator 와 동일한 runner_factory 로 recon 러너 집합 조립(정찰=상시).

    factory(spec)=make_runner 클로저 -> recon 러너. get_spec 로 스펙 해석(닫힌 어휘).
    orchestrator._tools 배선과 동일 팩토리를 태워 recon 러너가 실행엔진에 연결됨을 보장.
    """
    from core.modules.registry import get_spec

    out: dict[str, Runner] = {}
    for tid in ids:
        out[tid] = runner_factory(get_spec(tid))
    return out


# ═══════════════════════════════════════════════════════════════════════════
# 4. init 자동 baseline (12 §5) — KB 시드. 레시피 아님(표준 정찰 시드).
# ═══════════════════════════════════════════════════════════════════════════


async def run_baseline_recon(
    runners: Mapping[str, Runner],
    kb: WorldState,
    *,
    params: Optional[Mapping[str, Any]] = None,
) -> list[ReconResult]:
    """init baseline: recon_reach -> (net_core 도달 시) recon_session 으로 KB 시드(12 §5).

    레시피 금지 준수: 이것은 **공격 조합 처방이 아니라** '아는 사실을 세우는' 표준
      정찰 시드다(12 §1·§5). recon_reach 로 reach/unauth 확보, net_core 가 열렸으면
      recon_session 으로 seid 확보. 순서는 데이터 의존(session 은 reach(net_core) 전제).
    결과는 kb_update 로만 반영(정합) — 여기서 KB 를 직접 조작하지 않는다.
    Err/미배선 러너는 조용히 skip(정직: 못 얻은 사실은 미설정 -> 해당 계층 보수 봉쇄).
    반환: 적용된 ReconResult 목록(감사/로그용).
    """
    applied: list[ReconResult] = []
    p: dict[str, Any] = dict(params or {})

    r = await _run_recon(runners.get(RECON_REACH), p)
    if r is not None:
        kb_update(kb, r)
        applied.append(r)

    # net_core 가 도달 가능해졌으면 세션 학습(recon_session precond=reach(net_core)).
    if reach(ReachTarget.NET_CORE) in kb.facts:
        s = await _run_recon(runners.get(RECON_SESSION), p)
        if s is not None:
            kb_update(kb, s)
            applied.append(s)

    return applied


async def _run_recon(runner: Optional[Runner], params: Mapping[str, Any]) -> Optional[ReconResult]:
    """단일 recon 러너 실행 -> ReconResult|None. 미배선/Err/비-Recon 은 None(보수 skip)."""
    if runner is None:
        return None
    match await runner(**params):
        case Ok(res) if isinstance(res, ReconResult):
            return res
        case _:
            return None


__all__ = [
    "build_recon_result",
    "build_recon_runners",
    "run_baseline_recon",
    "parse_probe_json",
    "parse_signing",
    "parse_seid",
    "parse_sessions",
    "parse_observed_mode",
    "RECON_REACH",
    "RECON_DEFENSE",
    "RECON_SESSION",
]
