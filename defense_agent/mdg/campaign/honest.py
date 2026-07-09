"""honest.py (P6 · H-K 정직성 · V3 §8) — 캠페인의 정직성 레이어.

방어 에이전트는 자신의 posture를 지상진실로 결코 제시해선 안 된다. 이 모듈은 E2E 캠페인과
보고서가 드러내는 정직한 공개의 단일 원천이다:

  * V4 (ARIA 키위조)는 탐지 불가 — 유효 서명 위조 명령은 per-packet 성공 로그가 없으므로
    (A-2) 봉쇄(CONTAIN)만 가능하고 탐지는 결코 불가하다.
  * Impact는 MISSION-WEIGHTED — 보상적 가중평균은 단일 안전-핵심 도메인을 희석할 수 있다;
    criticality floor(71/45, 밴드컷 파생, P3-Q4)가 이를 교정하나, weight는 config이며
    operator가 튜닝 가능하다.
  * 대응 효력은 6공격 중 4공격에서 미검증 — telemetry cross-tap(D-1)과 PFCP counter
    diff(B-1)만 라이브 지상근거 관측이다; 컨테이너 간 nsenter DROP / docker pause 효력은
    미측정(C-1)이며 GATE2 / operator-go로 유지된다. 탐지 관측 != 대응 효력.
  * 모든 대응은 BLAST RADIUS를 수반한다 — 오조준 DROP은 아군을 self-DoS시킨다
    (PS-7). 타깃이 VERIFIED 바인딩이 아니면 dispatch는 fail-closed inert-DRY이므로, 라이브
    actuation은 미검증 셀렉터에서 결코 발화하지 않는다.

이들은 버그가 아니라 공개다: 아키텍처는 의도적으로 보수적이다
(inert-DRY, tri-state signing, agent≠truth Verifier). ``banner`` / ``honest_note`` /
``for_chapter``가 이를 캠페인 결과와 6장 보고서(artifacts.py)에 공급한다.

순수 모듈: I/O 없음, testbed 없음, core import 없음 — 어디서든 안전하게 import 가능.
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
    """방어 에이전트의 공개된 한계 하나 (근거 인용·章 매핑)."""
    key: str
    title: str
    severity: str                       # "blind" | "unverified" | "structural" | "advisory"
    summary: str
    evidence: list[str] = field(default_factory=list)   # doc/live 참조 (A-2 / B-1 / C-1 / D-1 …)
    report_chapter: int = 6             # 6개 보고서 章 중 어디에 드러나는지
    blast_radius: str = ""              # 오발화가 영향을 미칠 대상 (self-DoS 범위)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# 공개 한계 레지스트리 (보고서의 단일 진실원).
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
            "로만 대응한다(P3-Q3)."
        ),
        evidence=["A-2 (서명 성공 per-packet 로그 부재)", "P3-Q3 (서명 우회 독립 latch)"],
        report_chapter=6,
        blast_radius="탐지 공백 — 위조 명령은 telemetry가 정상으로 보여 agent가 nominal을 유지",
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
            "단조 카운터 diff(B-1). 나머지 3공격(무인증 명령/14556·mongo 접속·"
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


# 공격별 honest-key 힌트: 주어진 공격이 어떤 공개를 드러내는지. 캠페인 러너가 이를 각
# AttackOutcome에 붙여 보고서가 상호 링크하게 한다.
_ATTACK_HONEST: dict[str, list[str]] = {
    "A1_command_hijack_cr01": ["UNVERIFIED_RESPONSE_EFFICACY",
                               "BLAST_RADIUS_SELF_DOS", "MISSION_WEIGHTED_DILUTION"],
    "A2_pfcp_teardown": ["BLAST_RADIUS_SELF_DOS"],           # PFCP diff는 검증된 탐지
    "A3_unauth_command": ["UNVERIFIED_RESPONSE_EFFICACY", "V4_KEY_FORGERY_UNDETECTABLE",
                          "BLAST_RADIUS_SELF_DOS"],
    "A5_mongo_dbaccess": ["UNVERIFIED_RESPONSE_EFFICACY", "BLAST_RADIUS_SELF_DOS"],
    "A6_telemetry_silence": ["V4_KEY_FORGERY_UNDETECTABLE", "MISSION_WEIGHTED_DILUTION"],
}


def attack_honest_keys(attack_id: str) -> list[str]:
    """공격이 드러내는 정직-한계 키 (등록된 게 없으면 빈 리스트)."""
    return list(_ATTACK_HONEST.get(attack_id, []))


# --------------------------------------------------------------------------- #
# 배너 / 노트
# --------------------------------------------------------------------------- #
def campaign_disclaimer() -> str:
    """보고서 최상단에 고정되는 한 줄 캠페인 정직성 배너."""
    return (
        "이 캠페인은 DRY(operator-go 유보) — 라이브 상태변경 0. 탐지는 관측근거 위에서, "
        "대응은 fail-closed inert-DRY로 계획까지만 실행된다. 독립 Verifier(별 프로세스, "
        "replay 전용)가 링크 지상진실이며 agent의 posture는 진실이 아니다(agent≠truth). "
        "대응 효력은 5공격 중 2공격만 관측-검증(telemetry D-1·PFCP B-1), 나머지는 미검증."
    )


def banner() -> dict:
    """캠페인 결과 / 보고서 헤더용 구조화된 정직성 배너 (H-K)."""
    return {
        "text": campaign_disclaimer(),
        "trust_root": "mdg.verifier (out-of-graph, replay-only, deterministic)",
        "live_state_changes": 0,
        "execution_mode": "DRY (operator-go 유보)",
        "verified_detections": 2,           # telemetry cross-tap (D-1) + PFCP counter diff (B-1)
        "total_attacks": 5,
        "limitations": [h.key for h in HONEST_LIMITATIONS],
    }


def honest_note(key: str) -> dict:
    """공개된 한계 하나를 dict로 (결과/노트 임베딩용). KeyError-safe."""
    lim = LIMITATION_INDEX.get(key)
    if lim is None:
        return {"key": key, "title": "(unknown limitation)", "severity": "unknown",
                "summary": "", "evidence": [], "report_chapter": 6, "blast_radius": ""}
    return lim.to_dict()


def for_chapter(chapter: int) -> list[dict]:
    """report_chapter == ``chapter``인 모든 공개 한계 (보고서 매핑)."""
    return [h.to_dict() for h in HONEST_LIMITATIONS if h.report_chapter == chapter]
