"""artifacts.py (P6) — campaign artifacts + CampaignResult -> 6-chapter report mapping.

Consumes the recorded ``run.jsonl`` (the portability pillar, H-J) and the independent
Verifier truth to build three reviewer-facing artifacts per attack:

  * timeline       — per-tick node path + evidence + impact band + decision (replay.play)
  * decisions      — the agent's decision channel (what it chose, tier, DRY/operator-go)
  * verifier_truth — the OUT-OF-GRAPH Verifier's per-tick verdict + agent≠truth (verifier.py)

and folds every attack's outcome into a ``CampaignResult`` mapped onto the report's SIX
chapters (``to_report``):

  1. 개요·범위      scope, 2대 불변식, 운영제약, DRY posture
  2. 공격 재생      the 6 replayed attacks (scenario + evidence script)
  3. 탐지           incidents / evidence timeline (detection observation)
  4. 대응           decisions / tier / inert-DRY dispatch + blast-radius disclosures
  5. 독립 검증      Verifier truth + agent≠truth divergences (H-K)
  6. 정직성·한계    honest limitations (V4/5762/mission-weight/unverified/blast-radius)

Dependency direction: e2e.py -> artifacts.py -> {honest, verifier, replay.play}. This module
imports NO mdg.core (it is reporting-side, consuming JSONL) and NO langgraph. The result
dataclasses live HERE so e2e (which imports the heavy node graph) depends on this light module,
not the reverse.
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
# Result dataclasses (produced by e2e.run_campaign, consumed by to_report)
# --------------------------------------------------------------------------- #
@dataclass
class AttackOutcome:
    """One replayed attack's full outcome (detection + response + verification)."""
    attack_id: str
    title: str
    description: str
    run_path: str = ""
    # detection
    detected: bool = False
    verified_detection: bool = False        # live-grounded observation (D-1 telemetry / B-1 PFCP)
    incidents: list[dict] = field(default_factory=list)   # {id, kind, score, target, ...}
    top_impact_band: str = "Green"
    domains_hit: list[str] = field(default_factory=list)
    # response
    responded: bool = False
    response_rule: str = ""                 # recovery_type chosen (or "")
    response_tool: str = ""                 # registry tool_id
    response_tier: str = ""                 # AUTO | OPER | NONE
    response_dispatch: str = "none"         # inert_dry | dry_argv | operator_gate | escalated | none
    revert_cmd: str = ""                    # G3 revert recorded before any side effect
    live_execution: bool = False            # ALWAYS False (operator-go 유보)
    # verification (independent Verifier)
    truth_summary: dict = field(default_factory=dict)
    agent_truth_divergences: int = 0
    # honesty
    honest_keys: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CampaignResult:
    """The whole 6-attack campaign result (root object the report is built from)."""
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

    # -- rollups --------------------------------------------------------- #
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
        return sum(1 for o in self.outcomes if o.live_execution)   # must be 0

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
# Per-attack artifacts (from run.jsonl + independent Verifier)
# --------------------------------------------------------------------------- #
def build_timeline(run_path: str) -> list[dict]:
    """Per-tick timeline: node path, evidence count, impact band, incidents, decision.

    Pure read of run.jsonl via replay.play (no re-execution, no testbed, deterministic)."""
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
    """The agent decision channel across the run (what it chose + enforcement tier)."""
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
    """The INDEPENDENT Verifier's per-tick truth + run summary (H-K agent≠truth).

    Calls the standalone Verifier (verifier.py: replay-only, imports NO mdg.core) so the
    truth column is genuinely independent of the agent's decisions."""
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
# CampaignResult -> 6-chapter report
# --------------------------------------------------------------------------- #
_CHAPTER_TITLES = {
    1: "개요·범위 (Scope & Invariants)",
    2: "공격 재생 (Attack Replay)",
    3: "탐지 (Detection)",
    4: "대응 (Response)",
    5: "독립 검증 (Independent Verification)",
    6: "정직성·한계 (Honesty & Limitations)",
}

# report-role crosswalk (P6-Q report-structure lock): the SIX chapters below are a STANDALONE
# E2E campaign evidence report — they are NOT "Chapter 6" of the shared competition report.
# The naming collision (this artifact's 6 chapters vs the shared report's 章 taxonomy) is
# resolved here, not by restructuring the chapters (which would break test_p6_campaign, the
# RUNBOOK DRY check, and honest.py's chapter mapping). report-generator MUST consume this
# artifact via report_role.folds_into and keep the honesty banner intact (verified=2,
# live_state_changes=0, operator-go) rather than promoting these 6 chapters to top level.
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
    """Map a CampaignResult onto the 6-chapter report structure.

    Each chapter is a self-contained dict the report-generator (or a viewer) renders. All
    per-attack artifacts are rebuilt from the recorded run.jsonl so the report is a pure,
    reproducible function of the campaign's on-disk records (portability pillar)."""
    outcomes = campaign.outcomes

    # rebuild artifacts per attack (from run.jsonl) so the report is JSONL-reproducible
    per_attack_artifacts: dict[str, dict] = {}
    for o in outcomes:
        if o.run_path:
            try:
                per_attack_artifacts[o.attack_id] = {
                    "timeline": build_timeline(o.run_path),
                    "decisions": build_decisions(o.run_path),
                    "verifier_truth": build_verifier_truth(o.run_path),
                }
            except Exception as exc:            # a missing/corrupt run.jsonl must not crash the report
                per_attack_artifacts[o.attack_id] = {"error": f"{type(exc).__name__}: {exc}"}

    ch1 = {
        "title": _CHAPTER_TITLES[1],
        "banner": campaign.banner,
        "invariants": campaign.invariants,
        "operating_constraints": campaign.operating_constraints,
        "execution_mode": "DRY (operator-go 유보)",
        "live_state_changes": campaign.live_execution_count,      # asserted 0
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
                "live_execution": o.live_execution,             # ALWAYS False
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
        "report_role": _REPORT_ROLE,      # crosswalk: standalone artifact, folds into shared §7
        "chapters": {"1": ch1, "2": ch2, "3": ch3, "4": ch4, "5": ch5, "6": ch6},
    }


def write_report_json(campaign: CampaignResult, path: str) -> str:
    """Serialize the 6-chapter report to ``path`` (deterministic, secret-free by construction).

    The report is built only from CampaignResult + run.jsonl artifacts, both of which are
    already record-time redacted (PS-3); no secret field exists to serialize."""
    report = to_report(campaign)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, sort_keys=True, indent=2)
    return path
