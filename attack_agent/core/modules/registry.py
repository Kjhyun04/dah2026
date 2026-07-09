"""core.modules.registry — 22 원시 ToolSpec 전량 (04 §3·§4·§5 · V2-D36).

이 목록 = 코드강제 화이트리스트(닫힌 행동공간, 04 §5). Planner 출력 id ∈ REGISTRY.
조합은 오케스트레이터가 precond/require_any/consumes/produces/produces_facts/effect 로
런타임 도출(레시피 없음, 03). goal.scope 로 옵션 필터(19 PART1-4).

22 = RECON(4) + A(2) + B(5) + C(3) + D(8).
  RECON: recon_reach · recon_defense · recon_session · capture_downlink
  A: serial5762 · s1u_capture
  B: subdb_dump · subdb_canary · pfcp_delete · pfcp_flood · pivot_exploit
  C: key_extract · signkey_leak · nonce_scan
  D: oracle · webcmd · forge_sign · forge_aria · replay · peer_flood · forceland · naive

비자명 체인 실증(19): signkey_leak(produces sign_key) -> forge_sign(consumes sign_key),
  signing=on 하에서 SetMode 미차단 경로(oracle/forge_aria/replay=Blocked, naive=baseline).

비밀 라우팅(R6·ADV-F5): forge_sign/forge_aria/replay 의 소비 비밀은 args_template 원문이
  아니라 exec_binding.secret_params(vault->stdin) 로 선언 — argv 누수 차단.
작성 2026-07-05. 확장(22 전량) 2026-07-05.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping, cast

from core.common.types import (
    ATTACHED,
    IN_FLIGHT,
    Artifact,
    BlockedBy,
    Cond,
    CondWhen,
    Disrupt,
    ExecBinding,
    Layer,
    ParamSpec,
    Risk,
    SetFlag,
    SetMode,
    ToolId,
    ToolKind,
    ToolSpec,
    container_access,
    host_access,
    reach,
    unauth,
    weakcred,
)
from core.common.types import ReachTarget as RT

# mode 파라미터 규약 (18-D4: DO_SET_MODE, custom_mode ∈ COPTER). 04: 0/4/5/9.
_MODE_PARAM = {
    "mode": ParamSpec(
        type="int",
        choices=[0, 4, 5, 9],  # 0=STAB 4=GUIDED 5=LOITER 9=LAND
        required=True,
        desc="ArduPilot COPTER custom_mode (0=STAB,4=GUIDED,5=LOITER,9=LAND)",
    )
}

# forceland 는 물리 LAND(9) 고정 (04 §3 D: physical mode:=LAND).
_LAND_PARAM = {
    "mode": ParamSpec(
        type="int",
        choices=[9],
        required=False,
        default=9,
        desc="physical LAND (9) — forceland 고정",
    )
}


_SPECS: list[ToolSpec] = [
    # ═══════════════════════════════════════════════════════════════════════
    # RECON (상태불변 · 각 계층 첫 단계, 04 §3 RECON)
    # ═══════════════════════════════════════════════════════════════════════
    ToolSpec(
        id="recon_reach",
        layer=Layer.RECON,
        kind=ToolKind.PROBE,
        precond=(ATTACHED,),
        # produces reach 사실(백워드체이닝 표시용; 실측은 ReconResult로 kb_update)
        produces_facts=(
            reach(RT.NET_CORE), reach(RT.MONGO), reach(RT.SGI),
            reach(RT.UAV5762), reach(RT.S1U), reach(RT.PIVOT),
            reach(RT.GCS14555), reach(RT.GCS14556), reach(RT.WEB8080),
        ),
        risk=Risk.LOW,
        reversible=True,
        exec_binding=ExecBinding(
            sidecar="ue",
            script="dah_exec/R4_UE_ENTRY/recon_ue_entry.sh",
        ),
    ),
    ToolSpec(
        id="recon_defense",
        layer=Layer.RECON,
        kind=ToolKind.PROBE,
        precond=(reach(RT.SGI),),
        # signing/ciphering_order 는 scalar -> ReconResult.signing 으로 kb_update
        risk=Risk.LOW,
        reversible=True,
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/R5_ROGUE_ATTACK/read_mode.py",
        ),
    ),
    ToolSpec(
        id="recon_session",
        layer=Layer.RECON,
        kind=ToolKind.PROBE,
        precond=(reach(RT.NET_CORE),),
        produces=(Artifact.SEID,),  # F-SEID -> pfcp_delete 소비
        risk=Risk.LOW,
        reversible=True,
        exec_binding=ExecBinding(
            sidecar="core",
            script="core_exec/D_TM2_PFCP/learn_seid.py",
        ),
    ),
    ToolSpec(
        id="capture_downlink",
        layer=Layer.RECON,
        kind=ToolKind.COLLECT,
        # precond = reach(gcs14555) ∨ reach(s1u)  (04 §3: OR)
        require_any=((reach(RT.GCS14555), reach(RT.S1U)),),
        produces=(Artifact.CIPHERTEXT, Artifact.PCAP),
        risk=Risk.LOW,
        reversible=True,
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/C_TM3_V1_V4_V5/extract_downlink.py",
        ),
    ),
    ToolSpec(
        id="observe_mode",
        layer=Layer.RECON,
        kind=ToolKind.PROBE,
        # 실측 mode 관측: 평문 다운링크(14550/14560) HEARTBEAT custom_mode 를 읽어
        #   성공판정을 자기보고(INJECT ACK)가 아닌 실제 상태에 근거시킨다(관측·RO·복호 무).
        precond=(reach(RT.GCS14555),),
        risk=Risk.LOW,
        reversible=True,
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/C_TM3_V1_V4_V5/observe_mode.py",
        ),
    ),
    # ═══════════════════════════════════════════════════════════════════════
    # 계층 A — 무선·단말 (04 §3 A)
    # ═══════════════════════════════════════════════════════════════════════
    ToolSpec(
        id="serial5762",
        layer=Layer.A,
        kind=ToolKind.INJECT,
        precond=(reach(RT.UAV5762),),
        effect=SetMode(),  # 서명·ARIA 관통(직접 시리얼) — signing 무관 성립
        params=dict(_MODE_PARAM),
        risk=Risk.LOW,
        reversible=True,
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="ue",
            script="dah_exec/R5_ROGUE_ATTACK/atk_direct5762.py",
            args_template="mode {mode}",
        ),
    ),
    ToolSpec(
        id="s1u_capture",
        layer=Layer.A,
        kind=ToolKind.COLLECT,
        precond=(reach(RT.S1U),),
        produces=(Artifact.CIPHERTEXT, Artifact.PCAP),  # + aria_proof(증거, 비-체인)
        risk=Risk.LOW,
        reversible=True,
        win_cause="defense-proof",
        exec_binding=ExecBinding(
            sidecar="core",
            script="core_exec/E_TM3_S1U/capture_s1u.sh",
        ),
    ),
    # ═══════════════════════════════════════════════════════════════════════
    # 계층 B — 코어망 (04 §3 B)
    # ═══════════════════════════════════════════════════════════════════════
    ToolSpec(
        id="subdb_dump",
        layer=Layer.B,
        kind=ToolKind.COLLECT,
        precond=(reach(RT.MONGO), unauth("mongo")),
        produces=(Artifact.K_OPC, Artifact.IMSI),  # RO exfil
        risk=Risk.LOW,
        reversible=True,
        win_cause="key-leak",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="ext_exec/N3_SUBDB/subdb_dump.sh",
        ),
    ),
    ToolSpec(
        id="subdb_canary",
        layer=Layer.B,
        kind=ToolKind.INJECT,
        precond=(reach(RT.MONGO), unauth("mongo")),
        effect=SetFlag(flag="subscriber_written"),  # 가역 write proof
        risk=Risk.LOW,
        reversible=True,
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="ext_exec/N3_SUBDB/subdb_canary.sh",
        ),
    ),
    ToolSpec(
        id="pfcp_delete",
        layer=Layer.B,
        kind=ToolKind.INJECT,
        # precond 통일: reach(NET_CORE) (recon_reach.produces_facts 가 NET_CORE 산출 -> 활성).
        #   과거 reach(UPF_PFCP) 는 어떤 tool 도 산출하지 않아 dead(도달불가)였음.
        precond=(reach(RT.NET_CORE),),
        consumes=(Artifact.SEID,),  # <- recon_session 산출 소비
        effect=Disrupt(),           # c2 := disrupted
        risk=Risk.MED,              # 가용성 (04 §4)
        reversible=True,            # 재attach
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="core",
            script="core_exec/D_TM2_PFCP/pfcp_delete.py",
        ),
    ),
    ToolSpec(
        id="pfcp_flood",
        layer=Layer.B,
        kind=ToolKind.INJECT,
        # precond 통일: reach(NET_CORE) (pfcp_delete 와 동일. UPF_PFCP dead 해소).
        precond=(reach(RT.NET_CORE),),
        effect=Disrupt(),  # c2 := disrupted (부분)
        risk=Risk.MED,
        reversible=True,
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="core",
            script="core_exec/D_TM2_PFCP/pfcp_flood.py",
        ),
    ),
    ToolSpec(
        id="pivot_exploit",
        layer=Layer.B,
        kind=ToolKind.INJECT,
        precond=(reach(RT.PIVOT), weakcred("pivot")),
        produces_facts=(reach(RT.NET_CORE),),  # 측면이동 -> 코어망 도달(창발 게이트)
        risk=Risk.MED,
        reversible=True,
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="core",
            script="core_exec/F_TM2_LATERAL/pivot_exploit.sh",
        ),
    ),
    # ═══════════════════════════════════════════════════════════════════════
    # 계층 C — 암호·키 (04 §3 C. RO. produces = 후속 D 소비 재료)
    # ═══════════════════════════════════════════════════════════════════════
    ToolSpec(
        id="key_extract",
        layer=Layer.C,
        kind=ToolKind.COLLECT,
        precond=(host_access("uav_proxy"),),
        produces=(Artifact.ARIA_KEY,),
        risk=Risk.LOW,
        reversible=True,
        win_cause="key-leak",
        exec_binding=ExecBinding(
            sidecar="host",
            script="dah_exec/C_TM3_V1_V4_V5/v4_forge.py",  # docker inspect --key-hex
        ),
    ),
    ToolSpec(
        id="signkey_leak",
        layer=Layer.C,
        kind=ToolKind.COLLECT,
        precond=(container_access("sgi"),),
        produces=(Artifact.SIGN_KEY,),
        risk=Risk.LOW,
        reversible=True,
        win_cause="key-leak",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="ext_exec/N6_SIGNKEY/signkey_exposure.sh",
        ),
    ),
    ToolSpec(
        id="nonce_scan",
        layer=Layer.C,
        kind=ToolKind.COLLECT,
        # precond = has(ciphertext) ∨ has(pcap)  (04 §3: OR over artifacts, offline 분석)
        require_any_artifact=((Artifact.CIPHERTEXT, Artifact.PCAP),),
        risk=Risk.LOW,
        reversible=True,
        win_cause="crypto-break",  # 잠재
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/C_TM3_V1_V4_V5/analyze_tm3_v5.py",
        ),
    ),
    # ═══════════════════════════════════════════════════════════════════════
    # 계층 D — C2 응용 (04 §3 D)
    # ═══════════════════════════════════════════════════════════════════════
    ToolSpec(
        id="oracle",
        layer=Layer.D,
        kind=ToolKind.INJECT,
        precond=(reach(RT.GCS14556),),
        # IF signing=off -> SetMode ELSE blocked(signing) (04 §3 · 06 §3 Cond)
        effect=Cond(
            when=CondWhen.SIGNING_OFF,
            then=SetMode(),
            else_blocked=BlockedBy.SIGNING,
        ),
        params=dict(_MODE_PARAM),
        risk=Risk.LOW,
        reversible=True,
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/A_TM1/tm1_inject_oracle.py",
            args_template="{oracle_ip}:14556 mode {mode}",  # IP 는 TargetResolver 런타임 주입
        ),
    ),
    ToolSpec(
        id="webcmd",
        layer=Layer.D,
        kind=ToolKind.INJECT,
        precond=(reach(RT.WEB8080), unauth("web")),
        effect=SetMode(),  # 웹이 서명 대행 -> 우회 (signing 무관 성립)
        params=dict(_MODE_PARAM),
        risk=Risk.LOW,
        reversible=True,
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="ext_exec/N4_WEBCMD/webcmd_inject.py",
            args_template="mode {mode}",
        ),
    ),
    ToolSpec(
        id="forge_sign",
        layer=Layer.D,
        kind=ToolKind.INJECT,
        precond=(reach(RT.GCS14556),),
        consumes=(Artifact.SIGN_KEY,),  # <- 계층C 산출 소비 (창발 엣지, 06 §5)
        effect=SetMode(),               # 서명 위조 -> 우회 (signing 무관 성립)
        params=dict(_MODE_PARAM),
        risk=Risk.LOW,
        reversible=True,
        win_cause="key-leak",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="ext_exec/N6_SIGNKEY/sign_forge.py",
            args_template="{oracle_ip}:14556 mode {mode}",  # IP 동적화·{sign_key} 원문 제거
            secret_params=("sign_key",),                    # vault->stdin (R6)
        ),
    ),
    ToolSpec(
        id="forge_aria",
        layer=Layer.D,
        kind=ToolKind.INJECT,
        precond=(reach(RT.GCS14555),),
        consumes=(Artifact.ARIA_KEY,),  # <- key_extract 산출 소비
        # IF signing=off -> SetMode ELSE blocked(signing) — ARIA 위조는 서명계층이 막음
        effect=Cond(
            when=CondWhen.SIGNING_OFF,
            then=SetMode(),
            else_blocked=BlockedBy.SIGNING,
        ),
        params=dict(_MODE_PARAM),
        risk=Risk.LOW,
        reversible=True,
        win_cause="key-leak",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/C_TM3_V1_V4_V5/v4_forge.py",
            args_template="{cipher_ip}:14555 mode {mode}",  # IP 동적화·{aria_key} 원문 제거
            secret_params=("aria_key",),                    # vault->stdin (R6)
        ),
    ),
    ToolSpec(
        id="replay",
        layer=Layer.D,
        kind=ToolKind.INJECT,
        precond=(),
        consumes=(Artifact.CIPHERTEXT,),  # 캡처 명령 재전송
        # IF signing=off -> SetMode ELSE blocked(timestamp) — 서명이 타임스탬프로 막음
        effect=Cond(
            when=CondWhen.SIGNING_OFF,
            then=SetMode(),
            else_blocked=BlockedBy.TIMESTAMP,
        ),
        params=dict(_MODE_PARAM),
        risk=Risk.LOW,
        reversible=True,
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/C_TM3_V1_V4_V5/v1_replay.py",
            args_template="{cipher_ip}:14555 mode {mode}",  # IP 동적화·{ciphertext} 원문 제거
            secret_params=("ciphertext",),                  # vault->stdin (R6)
        ),
    ),
    ToolSpec(
        id="peer_flood",
        layer=Layer.D,
        kind=ToolKind.INJECT,
        precond=(reach(RT.GCS14555),),
        produces=(Artifact.CIPHERTEXT,),  # 관측 부산물(캡처)
        effect=Disrupt(),                 # c2 := disrupted (부분·가용성)
        risk=Risk.MED,
        reversible=True,
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/B_TM2_V3/v3_attacker.py",
        ),
    ),
    ToolSpec(
        id="forceland",
        layer=Layer.D,
        kind=ToolKind.INJECT,
        # precond = (reach(gcs14556) ∨ reach(web8080)) ∧ in_flight
        require_any=((reach(RT.GCS14556), reach(RT.WEB8080)),),
        precond=(IN_FLIGHT,),
        effect=SetMode(),  # physical: mode := LAND(9)
        params=dict(_LAND_PARAM),
        risk=Risk.HIGH,     # 물리 (04 §6-2: HITL 필수)
        reversible=False,   # 재이륙 필요(◐) -> 보수적으로 비가역 표기
        win_cause="config-flaw",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/DEMO/sign_mode.py",
            args_template="mode {mode}",
        ),
    ),
    ToolSpec(
        id="naive",
        layer=Layer.D,
        kind=ToolKind.INJECT,
        precond=(reach(RT.GCS14555),),
        # 대조군: 항상 차단 (baseline). effect_eval=Blocked(baseline) -> LLM 회피 유도
        effect=Cond(
            when=CondWhen.NEVER,
            then=SetMode(),
            else_blocked=BlockedBy.BASELINE,
        ),
        params=dict(_MODE_PARAM),
        risk=Risk.LOW,
        reversible=True,
        win_cause="baseline",
        exec_binding=ExecBinding(
            sidecar="sgi",
            script="dah_exec/A_TM1/tm1_naive_blocked.py",
            args_template="{cipher_ip}:14555 mode {mode}",  # IP 는 TargetResolver 런타임 주입
        ),
    ),
]


# id -> ToolSpec (닫힌 화이트리스트). Planner는 이 키만 고를 수 있음.
_REGISTRY: dict[ToolId, ToolSpec] = {s.id: s for s in _SPECS}

# 무결성 불변식 (04 §6-1): 중복/누락 없음 확인
if len(_REGISTRY) != len(_SPECS):
    raise RuntimeError("duplicate tool id in registry")
if len(_REGISTRY) != 23:
    raise RuntimeError(f"expect 23 원시 전량, got {len(_REGISTRY)}")

# 외부 노출은 read-only mapping으로 고정(런타임 변조 방지).
REGISTRY: Mapping[ToolId, ToolSpec] = MappingProxyType(_REGISTRY)


def get_spec(tool_id: ToolId | str) -> ToolSpec:
    """id -> ToolSpec. 화이트리스트 밖이면 KeyError(닫힘 강제)."""
    if tool_id not in REGISTRY:
        raise KeyError(tool_id)
    return REGISTRY[cast(ToolId, tool_id)]


__all__ = ["REGISTRY", "get_spec"]


