"""honest.py (P6 · H-K honesty · V3 §8) — the campaign's honesty layer.

The defense agent must NEVER present its posture as ground truth. This module is the
single source of the honest disclosures the E2E campaign and the report surface:

  * V4 (ARIA key-forgery) is UNDETECTABLE — a valid-signature forged command has no
    per-packet success log (A-2), so it can only be CONTAINED, never detected.
  * The 5762 backdoor command ACTUATION is BLIND — WebProbe is ss-only/pool=1 and the
    5762 vantage is D-2 un-wired, so only the ESTAB socket state is observed, never the
    unauthenticated command that rides it.
  * Impact is MISSION-WEIGHTED — a compensatory weighted mean can dilute a single
    safety-critical domain; the criticality floor (71/45, band-cut-derived, P3-Q4)
    corrects that, but the weights are config and are operator-tunable.
  * RESPONSE EFFICACY is UNVERIFIED for 4 of the 6 attacks — only the telemetry
    cross-tap (D-1) and the PFCP counter diff (B-1) are live-grounded observations; the
    inter-container nsenter DROP / docker pause efficacy is unmeasured (C-1) and stays
    GATE2 / operator-go. Detection observation != response efficacy.
  * Every response carries a BLAST RADIUS — a mis-targeted DROP would self-DoS an ally
    (PS-7). The dispatch is fail-closed inert-DRY when the target is not a VERIFIED
    binding, so live actuation never fires from an unverified selector.

These are DISCLOSURES, not bugs: the architecture is deliberately conservative
(inert-DRY, tri-state signing, agent≠truth Verifier). ``banner`` / ``honest_note`` /
``for_chapter`` feed them into the campaign result and the 6-chapter report (artifacts.py).

Pure module: no I/O, no testbed, no core import — safe to import anywhere.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

__all__ = [
    "HonestLimitation", "HONEST_LIMITATIONS", "LIMITATION_INDEX",
    "banner", "honest_note", "for_chapter", "campaign_disclaimer",
    "attack_honest_keys",
]


@dataclass(frozen=True)
class HonestLimitation:
    """One disclosed limitation of the defense agent (evidence-cited, chapter-mapped)."""
    key: str
    title: str
    severity: str                       # "blind" | "unverified" | "structural" | "advisory"
    summary: str
    evidence: list[str] = field(default_factory=list)   # doc/live refs (A-2 / B-1 / C-1 / D-1 …)
    report_chapter: int = 6             # which of the 6 report chapters surfaces it
    blast_radius: str = ""              # who/what a mis-fire would affect (self-DoS scope)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# The disclosed-limitations registry (single source of truth for the report).
# --------------------------------------------------------------------------- #
HONEST_LIMITATIONS: list[HonestLimitation] = [
    HonestLimitation(
        key="V4_KEY_FORGERY_UNDETECTABLE",
        title="V4 (ARIA/서명키 위조) 명령은 탐지 불가 — 봉쇄(containment)만 가능",
        severity="blind",
        summary=(
            "유효 서명을 위조한 명령은 uav_proxy에서 서명검증을 통과하므로 드롭로그가 "
            "찍히지 않고, 서명 '성공'은 per-packet 로그가 없다(A-2). 따라서 방어는 위조 "
            "명령을 개별 탐지할 수 없고, 채널·세션 수준 봉쇄(Incident.containment_only_flag)"
            "로만 대응한다. 서명 ON은 5762 직결경로도 커버하지 못한다(P3-Q3)."
        ),
        evidence=["A-2 (서명 성공 per-packet 로그 부재)", "P3-Q3 (5762 우회 독립 latch)"],
        report_chapter=6,
        blast_radius="탐지 공백 — 위조 명령은 telemetry가 정상으로 보여 agent가 nominal을 유지",
    ),
    HonestLimitation(
        key="PORT_5762_BLIND",
        title="5762 백도어 명령 actuation은 blind — ESTAB 상태만 관측",
        severity="blind",
        summary=(
            "WebProbe collector는 ss-only·pool=1이며 5762 vantage는 D-2 미배선이라, 관측 "
            "가능한 것은 소켓 ESTAB 상태(Port_5762_State)뿐이다. 그 소켓으로 흐르는 무인증 "
            "명령 자체는 관측되지 않는다. command distrust≥71(Red floor) 매핑은 ESTAB+무인증 "
            "명령 상관에서 추론될 뿐, 실 actuation은 GATE2 이전 미검증(P3-Q4)."
        ),
        evidence=["B-2 (air 이미지 curl/nc 부재)", "C-1 (효력 미측정)", "P3-Q4"],
        report_chapter=6,
        blast_radius="추론 기반 — 무인증 명령이 SITL에 도달했는지는 라이브 read-only로만 확정",
    ),
    HonestLimitation(
        key="MISSION_WEIGHTED_DILUTION",
        title="Impact는 mission-weighted — 보상적 평균의 희석 위험(criticality_floor로 교정)",
        severity="structural",
        summary=(
            "overall_impact = max(weighted_mean, criticality_floor). weighted_mean 단독은 "
            "단일 안전-핵심 도메인 전면침해를 희석한다(command trust=0인데 20=Green). floor "
            "71/45(밴드컷 파생·weight 독립, P3-Q4)가 이를 Red/Yellow로 고정해 교정하나, "
            "mission_weight 자체는 config이며 operator가 튜닝 가능하다(회귀 시 재검증 필요)."
        ),
        evidence=["PP-3 / P3-Q4 (crit_floor 71/45 락)", "M5/E8"],
        report_chapter=5,
        blast_radius="config 변조 시 안전도메인 무력화 시도 — floor는 weight 독립이라 방어됨",
    ),
    HonestLimitation(
        key="UNVERIFIED_RESPONSE_EFFICACY",
        title="6공격 중 4공격의 대응 효력은 미검증 (관측 근거 ≠ 대응 효력)",
        severity="unverified",
        summary=(
            "라이브 read-only로 지상진실이 확보된 관측은 2개뿐이다: (1) telemetry 교차탭 "
            "uav_ue lo:14550 평문 HEARTBEAT(D-1, 3패킷 실캡처), (2) PFCP s5c_rx_deletesession "
            "단조 카운터 diff(B-1). 나머지 4공격(무인증 명령/14556·5762 backdoor·mongo 접속·"
            "NAS/서명 위조)은 관측점은 실재하나 대응(nsenter DROP·docker pause)의 실효력은 "
            "코드 전 미측정(C-1). br_netfilter 미로드·DOCKER-USER 빈 체인으로 netns-INPUT 집행만 "
            "유효하며 그 차단 확정은 GATE2 가역 실측 이전 operator-go."
        ),
        evidence=["C-1 (DROP 효력 미측정·GATE2 블로커)", "D-1/B-1 (2 verified)", "부록B"],
        report_chapter=4,
        blast_radius="대응 '차단됨' 주장은 미검증 — 라이브 효력 실측 전까지 DRY로만 표기",
    ),
    HonestLimitation(
        key="BLAST_RADIUS_SELF_DOS",
        title="모든 대응의 blast radius·self-DoS — 미검증 타깃은 fail-closed inert-DRY",
        severity="advisory",
        summary=(
            "incident.target은 telemetry/상관 유래 신뢰불가 입력이라 iptables -s에 직접 실으면 "
            "공격자가 operator/정상 UE IP를 주입해 아군을 자기격리(self-DoS)할 수 있다(PS-7). "
            "dispatch는 셀렉터를 VERIFIED WorldState 바인딩의 KEY로만 해석하고, enforce_at·source "
            "가 서로 다른 검증된 엔드포인트로 풀리지 않으면 exec_request=None → inert-DRY로 봉쇄한다. "
            "따라서 미검증 셀렉터에서 라이브 DROP은 구조적으로 발화하지 않는다."
        ),
        evidence=["PS-7 (인젝션·과잉대응 게이트)", "P4-Q1/P4-2 (2-endpoint 검증)", "불변식②"],
        report_chapter=4,
        blast_radius="mis-DROP 시 아군 UE/operator 격리 — 검증 게이트로 발화 차단(inert-DRY)",
    ),
]

LIMITATION_INDEX: dict[str, HonestLimitation] = {h.key: h for h in HONEST_LIMITATIONS}


# per-attack honest-key hints: which disclosures a given attack surfaces. The
# campaign runner attaches these to each AttackOutcome so the report cross-links.
_ATTACK_HONEST: dict[str, list[str]] = {
    "A1_command_hijack_cr01": ["UNVERIFIED_RESPONSE_EFFICACY", "PORT_5762_BLIND",
                               "BLAST_RADIUS_SELF_DOS", "MISSION_WEIGHTED_DILUTION"],
    "A2_pfcp_teardown": ["BLAST_RADIUS_SELF_DOS"],           # PFCP diff is verified detection
    "A3_unauth_command": ["UNVERIFIED_RESPONSE_EFFICACY", "V4_KEY_FORGERY_UNDETECTABLE",
                          "BLAST_RADIUS_SELF_DOS"],
    "A4_5762_backdoor": ["PORT_5762_BLIND", "UNVERIFIED_RESPONSE_EFFICACY",
                         "BLAST_RADIUS_SELF_DOS"],
    "A5_mongo_dbaccess": ["UNVERIFIED_RESPONSE_EFFICACY", "BLAST_RADIUS_SELF_DOS"],
    "A6_telemetry_silence": ["V4_KEY_FORGERY_UNDETECTABLE", "MISSION_WEIGHTED_DILUTION"],
}


def attack_honest_keys(attack_id: str) -> list[str]:
    """Honest-limitation keys an attack surfaces (empty if none registered)."""
    return list(_ATTACK_HONEST.get(attack_id, []))


# --------------------------------------------------------------------------- #
# Banners / notes
# --------------------------------------------------------------------------- #
def campaign_disclaimer() -> str:
    """The single-line campaign honesty banner pinned at the top of the report."""
    return (
        "이 캠페인은 DRY(operator-go 유보) — 라이브 상태변경 0. 탐지는 관측근거 위에서, "
        "대응은 fail-closed inert-DRY로 계획까지만 실행된다. 독립 Verifier(별 프로세스, "
        "replay 전용)가 링크 지상진실이며 agent의 posture는 진실이 아니다(agent≠truth). "
        "대응 효력은 6공격 중 2공격만 관측-검증(telemetry D-1·PFCP B-1), 나머지는 미검증."
    )


def banner() -> dict:
    """Structured honesty banner for the campaign result / report header (H-K)."""
    return {
        "text": campaign_disclaimer(),
        "trust_root": "mdg.verifier (out-of-graph, replay-only, deterministic)",
        "live_state_changes": 0,
        "execution_mode": "DRY (operator-go 유보)",
        "verified_detections": 2,           # telemetry cross-tap (D-1) + PFCP counter diff (B-1)
        "total_attacks": 6,
        "limitations": [h.key for h in HONEST_LIMITATIONS],
    }


def honest_note(key: str) -> dict:
    """One disclosed limitation as a dict (for embedding in a result/note). KeyError-safe."""
    lim = LIMITATION_INDEX.get(key)
    if lim is None:
        return {"key": key, "title": "(unknown limitation)", "severity": "unknown",
                "summary": "", "evidence": [], "report_chapter": 6, "blast_radius": ""}
    return lim.to_dict()


def for_chapter(chapter: int) -> list[dict]:
    """All disclosed limitations whose report_chapter == ``chapter`` (report mapping)."""
    return [h.to_dict() for h in HONEST_LIMITATIONS if h.report_chapter == chapter]
