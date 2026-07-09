"""artifacts.py (P6) — 캠페인 산출물 + CampaignResult -> 6장 보고서 매핑.

기록된 ``run.jsonl``(이식성 기둥, H-J)과 독립 Verifier 진실을 소비해 공격마다 리뷰어 대상
산출물 3종을 만든다:

  * timeline       — 틱별 노드 경로 + 근거 + impact band + decision (replay.play)
  * decisions      — agent 결정 채널 (무엇을 선택했는지, tier, DRY/operator-go)
  * verifier_truth — OUT-OF-GRAPH Verifier의 틱별 판정 + agent≠truth (verifier.py)

그리고 모든 공격의 결과를 ``CampaignResult``로 접어 보고서의 6개 장(``to_report``)에
매핑한다:

  1. 개요·범위      범위·2대 불변식·운영제약·DRY posture
  2. 공격 재생      재생된 6개 공격 (시나리오 + 근거 스크립트)
  3. 탐지           incidents / 근거 타임라인 (탐지 관측)
  4. 대응           decisions / tier / inert-DRY dispatch + blast-radius 공개
  5. 독립 검증      Verifier 진실 + agent≠truth 발산 (H-K)
  6. 정직성·한계    정직한 한계 (V4/5762/mission-weight/unverified/blast-radius)

의존 방향: e2e.py -> artifacts.py -> {honest, verifier, replay.play}. 이 모듈은 mdg.core를
전혀 import하지 않고(보고서 측, JSONL 소비) langgraph도 import하지 않는다. 결과 dataclass가
여기 있으므로 (무거운 노드 그래프를 import하는) e2e가 이 가벼운 모듈에 의존하며,
그 반대가 아니다.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

from . import honest as H
from ..replay import play
from ..verifier import verifier as V

__all__ = [
    "AttackOutcome", "CampaignResult",
    "build_timeline", "build_decisions", "build_verifier_truth",
    "to_report", "write_report_json",
]


# --------------------------------------------------------------------------- #
# 결과 dataclass (e2e.run_campaign이 생성, to_report가 소비)
# --------------------------------------------------------------------------- #
@dataclass
class AttackOutcome:
    """재생된 공격 하나의 전체 결과 (탐지 + 대응 + 검증)."""
    attack_id: str
    title: str
    description: str
    run_path: str = ""
    # 탐지
    detected: bool = False
    verified_detection: bool = False        # 라이브 지상근거 관측 (D-1 telemetry / B-1 PFCP)
    incidents: list[dict] = field(default_factory=list)   # {id, kind, score, target, ...}
    top_impact_band: str = "Green"
    domains_hit: list[str] = field(default_factory=list)
    # 대응
    responded: bool = False
    response_rule: str = ""                 # 선택된 recovery_type (없으면 "")
    response_tool: str = ""                 # 레지스트리 tool_id
    response_tier: str = ""                 # AUTO | OPER | NONE
    response_dispatch: str = "none"         # inert_dry | dry_argv | operator_gate | escalated | none
    revert_cmd: str = ""                    # 부작용 전 기록된 G3 revert
    live_execution: bool = False            # 항상 False (operator-go 유보)
    # 검증 (독립 Verifier)
    truth_summary: dict = field(default_factory=dict)
    agent_truth_divergences: int = 0
    # 정직성
    honest_keys: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CampaignResult:
    """6개 공격 캠페인 전체 결과 (보고서가 만들어지는 루트 객체)."""
    outcomes: list[AttackOutcome] = field(default_factory=list)
    out_dir: str = ""
    banner: dict = field(default_factory=H.banner)
    invariants: list[str] = field(default_factory=lambda: [
        "불변식① 결정론 제어흐름 — 조건부 엣지는 impact.band·chosen_action_risk/reversible/"
        "chosen_action is None 수치·불린만 read (LLM 미참여).",
        "불변식② 누수-0 실행 — 도구 부작용은 Backend.run(ExecRequest) 단일 safe-exec 경유, "
        "노드 subprocess 0, Verifier 별 프로세스(core 미import).",
    ])
    operating_constraints: list[str] = field(default_factory=lambda: [
        f"testbed({os.environ.get('MDG_TESTBED_LABEL', '<testbed>')}) 상태변경 자동실행 금지 "
        "— DROP·docker pause·서명명령·stop·설정수정 금지.",
        "라이브 검증은 read-only SSH 관측만; 실집행(GATE1 누수0 실측·GATE2 효력·E2E 실집행)은 operator-go 유보.",
        "Backend.allow_live=False 기본 → 모든 actuation DRY-RUN.",
    ])

    # -- 롤업 --------------------------------------------------------- #
    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def detected_count(self) -> int:
        return sum(1 for o in self.outcomes if o.detected)

    @property
    def verified_count(self) -> int:
        return sum(1 for o in self.outcomes if o.verified_detection)

    @property
    def responded_count(self) -> int:
        return sum(1 for o in self.outcomes if o.responded)

    @property
    def divergence_count(self) -> int:
        return sum(o.agent_truth_divergences for o in self.outcomes)

    @property
    def live_execution_count(self) -> int:
        return sum(1 for o in self.outcomes if o.live_execution)   # 반드시 0

    def to_dict(self) -> dict:
        return {
            "out_dir": self.out_dir,
            "banner": self.banner,
            "invariants": self.invariants,
            "operating_constraints": self.operating_constraints,
            "rollup": {
                "total": self.total, "detected": self.detected_count,
                "verified_detection": self.verified_count, "responded": self.responded_count,
                "agent_truth_divergences": self.divergence_count,
                "live_executions": self.live_execution_count,
            },
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


# --------------------------------------------------------------------------- #
# 공격별 산출물 (run.jsonl + 독립 Verifier)
# --------------------------------------------------------------------------- #
def build_timeline(run_path: str) -> list[dict]:
    """틱별 타임라인: 노드 경로, 근거 수, impact band, incidents, decision.

    replay.play를 통한 run.jsonl 순수 읽기 (재실행 없음, testbed 없음, 결정론적)."""
    ticks = play.load_timeline(run_path)
    out: list[dict] = []
    for t in ticks:
        dec = t.last_decision()
        out.append({
            "tick": t.index,
            "tick_i": t.tick_i,
            "nodes": list(t.nodes),
            "evidence": len(t.evidence),
            "evidence_metrics": [e.get("metric") for e in t.evidence if isinstance(e, dict)],
            "impact_band": (t.impact or {}).get("band"),
            "impact_score": (t.impact or {}).get("score"),
            "incidents": [i.get("kind") for i in t.incidents if isinstance(i, dict)],
            "decision": dec.get("decision") if dec else None,
            "ledger_intents": len(t.ledger),
        })
    return out


def build_decisions(run_path: str) -> list[dict]:
    """런 전체에 걸친 agent 결정 채널 (무엇을 선택했는지 + enforcement tier)."""
    ticks = play.load_timeline(run_path)
    out: list[dict] = []
    for t in ticks:
        for dec in t.decisions:
            if not isinstance(dec, dict):
                continue
            out.append({
                "tick": t.index,
                "decision": dec.get("decision"),
                "enforcement": dec.get("enforcement"),
                "mission_impact": dec.get("mission_impact"),
                "config_version": dec.get("config_version"),
            })
    return out


def build_verifier_truth(run_path: str) -> dict:
    """독립 Verifier의 틱별 진실 + 런 요약 (H-K agent≠truth).

    독립형 Verifier(verifier.py: replay 전용, mdg.core 미import)를 호출하므로 진실
    컬럼이 agent의 결정과 진정으로 독립이다."""
    verdicts = V.verify_run(run_path)
    return {
        "summary": V.summarize(verdicts),
        "per_tick": [
            {
                "tick": v.tick,
                "verdict": v.verdict,
                "telemetry_alive": v.telemetry_alive,
                "gcs_proxy_alive": v.gcs_proxy_alive,
                "cross_root_consistent": v.cross_root_consistent,
                "silence_streak": v.silence_streak,
                "agent_decision": v.agent_decision,
                "agent_truth_divergence": v.agent_truth_divergence,
                "reason": v.reason,
            }
            for v in verdicts
        ],
    }


# --------------------------------------------------------------------------- #
# CampaignResult -> 6장 보고서
# --------------------------------------------------------------------------- #
_CHAPTER_TITLES = {
    1: "개요·범위 (Scope & Invariants)",
    2: "공격 재생 (Attack Replay)",
    3: "탐지 (Detection)",
    4: "대응 (Response)",
    5: "독립 검증 (Independent Verification)",
    6: "정직성·한계 (Honesty & Limitations)",
}

# report-role 크로스워크 (P6-Q 보고서 구조 락): 아래 6개 章은 자체 완결형 E2E 캠페인
# 증거 보고서다 — 공동 경쟁 보고서의 "6장"이 아니다. 이름 충돌(이 산출물의 6개 章 vs
# 공동 보고서의 章 분류)은 章을 재구조화하지 않고 여기서 해소한다(재구조화하면
# test_p6_campaign, RUNBOOK DRY 체크, honest.py의 章 매핑이 깨진다). report-generator는 이
# 산출물을 report_role.folds_into로 소비하고 정직성 배너(verified=2,
# live_state_changes=0, operator-go)를 그대로 유지해야 하며 이 6개 章을 top level로 승격하지 말 것.
_REPORT_ROLE = {
    "artifact": "e2e_campaign_evidence_report",
    "standalone": True,
    "chapters": 6,
    "folds_into": "공동 경쟁 보고서의 '독립 검증 / E2E 증거' 절 (report-generator §7)",
    "chapter_collision_note": (
        "이 산출물의 6개 章은 자체 완결형 E2E 캠페인 증거 보고서이며, 공동 보고서의 '6장'이 "
        "아니다. report-generator는 이 문서를 folds_into 절로 접어 넣고 章 번호를 top-level로 "
        "승격하지 말 것. 정직성 배너(verified=2·live_state_changes=0·operator-go)는 보존한다."
    ),
    "chapter_titles": {str(k): v for k, v in _CHAPTER_TITLES.items()},
}


def to_report(campaign: CampaignResult) -> dict:
    """CampaignResult를 6장 보고서 구조에 매핑한다.

    각 章은 report-generator(또는 뷰어)가 렌더하는 자체 완결형 dict다. 공격별 산출물은
    모두 기록된 run.jsonl에서 재구성되므로 보고서는 캠페인의 온디스크 기록에 대한 순수·
    재현 가능한 함수다(이식성 기둥)."""
    outcomes = campaign.outcomes

    # 공격별 산출물을 (run.jsonl에서) 재구성해 보고서가 JSONL로 재현 가능하게 한다
    per_attack_artifacts: dict[str, dict] = {}
    for o in outcomes:
        if o.run_path:
            try:
                per_attack_artifacts[o.attack_id] = {
                    "timeline": build_timeline(o.run_path),
                    "decisions": build_decisions(o.run_path),
                    "verifier_truth": build_verifier_truth(o.run_path),
                }
            except Exception as exc:            # 누락/손상된 run.jsonl이 보고서를 crash시키면 안 된다
                per_attack_artifacts[o.attack_id] = {"error": f"{type(exc).__name__}: {exc}"}

    ch1 = {
        "title": _CHAPTER_TITLES[1],
        "banner": campaign.banner,
        "invariants": campaign.invariants,
        "operating_constraints": campaign.operating_constraints,
        "execution_mode": "DRY (operator-go 유보)",
        "live_state_changes": campaign.live_execution_count,      # 0으로 단언
        "rollup": campaign.to_dict()["rollup"],
    }

    ch2 = {
        "title": _CHAPTER_TITLES[2],
        "attacks": [
            {
                "attack_id": o.attack_id, "title": o.title, "description": o.description,
                "domains": o.domains_hit, "run_path": o.run_path,
                "verified_detection": o.verified_detection,
            }
            for o in outcomes
        ],
    }

    ch3 = {
        "title": _CHAPTER_TITLES[3],
        "detection": [
            {
                "attack_id": o.attack_id, "detected": o.detected,
                "verified_detection": o.verified_detection,
                "top_impact_band": o.top_impact_band, "domains_hit": o.domains_hit,
                "incidents": o.incidents,
                "timeline": per_attack_artifacts.get(o.attack_id, {}).get("timeline", []),
            }
            for o in outcomes
        ],
        "verified_note": (
            "라이브 관측-검증된 탐지 근거는 2개: telemetry 교차탭 uav_ue lo:14550(D-1) · "
            "PFCP s5c_rx_deletesession 카운터 diff(B-1). 나머지는 관측점 실재하나 지상진실 미확보."
        ),
    }

    ch4 = {
        "title": _CHAPTER_TITLES[4],
        "response": [
            {
                "attack_id": o.attack_id, "responded": o.responded,
                "rule": o.response_rule, "tool": o.response_tool, "tier": o.response_tier,
                "dispatch": o.response_dispatch, "revert_cmd": o.revert_cmd,
                "live_execution": o.live_execution,             # 항상 False
                "decisions": per_attack_artifacts.get(o.attack_id, {}).get("decisions", []),
            }
            for o in outcomes
        ],
        "blast_radius": H.for_chapter(4),
        "response_note": (
            "모든 대응은 Backend.allow_live=False → DRY. 미검증 셀렉터는 fail-closed inert-DRY "
            "(PS-7 self-DoS 봉쇄). 실 DROP/pause/서명발행은 GATE2 가역 실측·operator-go 유보."
        ),
    }

    ch5 = {
        "title": _CHAPTER_TITLES[5],
        "trust_root": campaign.banner.get("trust_root"),
        "verification": [
            {
                "attack_id": o.attack_id,
                "truth_summary": o.truth_summary,
                "agent_truth_divergences": o.agent_truth_divergences,
                "verifier_truth": per_attack_artifacts.get(o.attack_id, {}).get("verifier_truth", {}),
            }
            for o in outcomes
        ],
        "total_agent_truth_divergences": campaign.divergence_count,
        "hk_note": (
            "Verifier는 core를 import하지 않는 별 프로세스(grep0)로 replay JSONL만 접는다. "
            "agent가 nominal(Continue/Continue+Monitoring)인데 truth가 SILENCE/CROSS_ROOT_"
            "INCONSISTENT면 agent≠truth 발산으로 표기한다(H-K)."
        ),
    }

    ch6 = {
        "title": _CHAPTER_TITLES[6],
        "limitations": [h.to_dict() for h in H.HONEST_LIMITATIONS],
        "per_attack_honest_keys": {o.attack_id: o.honest_keys for o in outcomes},
        "disclaimer": H.campaign_disclaimer(),
    }

    return {
        "report": "MDG 방어 에이전트 — E2E 캠페인 증거 보고서 (자체 완결형 6장)",
        "report_role": _REPORT_ROLE,      # 크로스워크: 독립 산출물, 공동 §7로 접힘
        "chapters": {"1": ch1, "2": ch2, "3": ch3, "4": ch4, "5": ch5, "6": ch6},
    }


def write_report_json(campaign: CampaignResult, path: str) -> str:
    """6장 보고서를 ``path``에 직렬화한다 (결정론적, 구조상 비밀 없음).

    보고서는 CampaignResult + run.jsonl 산출물만으로 만들어지며 둘 다 이미 기록 시점에
    편집(redact)되어 있어(PS-3) 직렬화할 비밀 필드가 존재하지 않는다."""
    report = to_report(campaign)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, sort_keys=True, indent=2)
    return path
