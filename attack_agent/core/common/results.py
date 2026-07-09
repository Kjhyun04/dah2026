"""core.common.results — tool 반환 payload T + 캠페인 최종산출 (15).

이 3종(ReconResult/CollectResult/InjectResult) = ToolSuccess[T]의 T (06 §6).
**공격 payload 아님** — tool이 반환하는 '공격자-가시' 데이터(15 §1).

22 원시 커버(kind->result):
  PROBE  -> ReconResult   : recon_reach(reach) · recon_defense(signing) · recon_session(seid,sessions)
  COLLECT-> CollectResult : capture_downlink · s1u_capture(ciphertext,pcap) · subdb_dump(k_opc,imsi)
                           key_extract(aria_key) · signkey_leak(sign_key) · nonce_scan(nonce_collision)
  INJECT -> InjectResult  : serial5762 · oracle · webcmd · forge_sign · forge_aria · replay · naive
                           (mode via effect) · pfcp_delete/pfcp_flood/peer_flood(c2) ·
                           subdb_canary(subscriber_written flag) · forceland(mode=9) · pivot_exploit(reach)

@ToolVerifyClass 제약(15 §2·아카이브): **optional list 금지** -> 리스트는 필수+기본 [].
  pydantic v2에서 `= []` 는 인스턴스마다 deepcopy -> 공유 변이 없음(core.py 주석 규격).

완전분리(06 P2): InjectResult엔 **감독 ground-truth 필드 없음**. effect는 공격자-관측 추정치.
작성 2026-07-05.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel


class _ResultBase(BaseModel):
    """모든 결과 payload 공통 베이스 (15 §1)."""

    raw: str = ""                       # redacted (viewer·증거, 06 §2-3)
    latency_ms: int = 0                 # exec_meta (09 §1 누수 감시)
    killed: bool = False                # timeout kill 여부 (09 §1)


class ReconResult(_ResultBase):
    """정찰 PROBE 반환 (15 §1). 도달·방어·세션 관측."""

    reach: list[str] = []       # 도달 role@ip:port (또는 role) — 기본 []
    unauth: list[str] = []      # 무인증 서비스
    signing: Literal["on", "off", "unknown"] = "unknown"
    seid: Optional[str] = None  # recon_session
    sessions: int = 0           # 활성 세션 수
    identified: list[str] = []  # 확정된 role (verified, 14)
    observed_mode: Optional[int] = None  # observe_mode: 실측 custom_mode(평문 관측). None=미관측


class CollectResult(_ResultBase):
    """수집 COLLECT 반환 (15 §1). 아티팩트 획득 + 마스킹 값."""

    artifacts: list[str] = []       # 획득 아티팩트 키명 (k_opc/aria_key/sign_key/…)
    values: dict[str, str] = {}     # **마스킹** (예: aria_key: "59a5…")
    redacted: bool = True           # 비밀 마스킹 강제
    nonce_collision: Optional[bool] = None  # nonce_scan offline 분석 결과(있으면 crypto 잠재)


class InjectResult(_ResultBase):
    """주입 INJECT 반환 (15 §1). ACK 수용 + 공격자-관측 효과.

    주의 감독 ground-truth 필드 없음(완전분리·06 P2). effect는 자기판정 추정치.
    """

    accepted: bool = False                     # ACK 수용
    signed: Optional[bool] = None              # 서명 여부(응답)
    blocked_by: Optional[
        Literal["signing", "auth", "no_effect", "timestamp", "baseline"]
    ] = None                                    # ADAPT 피벗 키
    effect: dict[str, str] = {}                # 공격자-관측 효과 (mode?/c2?)


class StepRecord(BaseModel):
    """CampaignResult.chain 원소 = 실행 원시 1스텝 (15 §2)."""

    step: int
    tool_id: str
    params: dict[str, str] = {}
    verdict: str = ""                 # OK/BLOCKED/ERROR/TIMEOUT
    blocked_by: Optional[str] = None


class CampaignResult(BaseModel):
    """최종산출 = terminate 반환 (15 §2). viewer·심사 근거.

    감독 판정은 별도 산출(여기 미포함, 완전분리). 자기 ACK 판정만.
    @ToolVerifyClass: optional list 금지 -> 리스트 필수+기본 [].
    """

    goal_reached: bool = False
    chain: list[StepRecord] = []          # 도출된 조합 = 실행 원시 순서
    defenses_bypassed: list[str] = []     # 우회한 방어 (signing/auth…)
    win_causes: list[str] = []            # config-flaw/key-leak/crypto-break
    kb_final: dict = {}                   # 최종 KB 스냅샷 (마스킹)
    evidence_notes: list[str] = []        # 비적재 증거 서술(결정 비개입)
    honest_note: str = (
        "agent goal_reached=능력 달성(자기 ACK 판정). "
        "실제 mode 전이는 감독이 복호로 독립 판정, 둘은 분리·독립."
    )
