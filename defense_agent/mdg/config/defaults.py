"""Python-native 단일 진리원으로서의 FIXED 상수(FEASIBILITY §3 · prototype §5 정본
config). 병렬 *.yaml 파일이 이 값들을 미러링한다; ``loader.py`` 는 pyyaml이 설치되어
있으면 YAML을 선호하고 그렇지 않으면 여기로 폴백한다.

이 값들은 결정론적 scoring 파이프라인(E5-E8/E19)이 읽는 값이다. FEASIBILITY_AUDIT §3
및 prototype thresholds.yaml에 따라 FIXED다(라이브 소스 없음).
"""
from __future__ import annotations

# --- E7: band -> (severity, deviation) 매핑 (prototype thresholds.yaml) ---
SEVERITY_FACTOR: dict[str, float] = {
    "info": 0.0,
    "low": 0.1,
    "medium": 0.3,
    "high": 0.6,
    "critical": 1.0,
}

# dev는 in-band 스케일; obs>0 일괄 dev=1.0 은 DEPRECATED (E7).
BAND_MAP: dict[str, dict[str, object]] = {
    "normal": {"severity": "info", "dev": 0.0},
    "warning": {"severity": "medium", "dev": 0.4},
    "critical": {"severity": "high", "dev": 0.7},
    "danger": {"severity": "critical", "dev": 1.0},
}

# --- Trust / Impact banding (M5/M7) 신뢰/영향 밴딩 ---
TRUST_BANDS: dict[str, tuple[int, int]] = {
    "very_high": (90, 100),
    "high": (70, 89),
    "moderate": (50, 69),
    "low": (30, 49),
    "very_low": (0, 29),
}
IMPACT_BANDS: dict[str, tuple[int, int]] = {
    "Green": (0, 30),
    "Yellow": (31, 70),
    "Red": (71, 100),
}
IMPACT_BAND_ORDER: list[str] = ["Green", "Yellow", "Red"]

# --- E8: confidence는 보수적 band shift로 한 번만 사용(곱셈 없음) ---
LOW_CONFIDENCE_THRESHOLD: float = 0.5

# --- 메트릭 가중치 테이블 (weight는 도메인별 합 <= 1, E6; 재정규화 없음) ---
# {metric: {domain, bands..., weight}}
METRICS: dict[str, dict[str, object]] = {
    "PFCP_Delete_Attempt": {"domain": "session_network", "normal": [0, 0], "warning": [1, 1], "critical": [2, 3], "danger": [4, "inf"], "weight": 0.55},  # 0.40->0.55: danger distrust 49.5 >= session_network floor 40 -> Yellow -> orient (PFCP 단독 탐지). warning/critical 은 여전히 Green(오탐 방지).
    "Unauthorized_Command": {"domain": "command", "normal": [0, 0], "warning": [1, 1], "critical": [2, "inf"], "weight": 0.35},
    "Signature_Verify_Fail": {"domain": "command", "warning": [1, 3], "critical": [4, "inf"], "weight": 0.20},
    "Port_5762_State": {"domain": "command", "normal": "LISTEN_NO_ESTAB", "danger": "ESTAB_PRESENT", "weight": 0.45},
    "DB_Access": {"domain": "identity_access", "normal": [0, 0], "warning": [1, 2], "critical": [3, "inf"], "weight": 0.35},
    "Packet_Loss": {"domain": "communication", "normal": [0, 1], "warning": [2, 5], "critical": [6, 20], "danger": [21, 100], "weight": 0.30},
    "RTT": {"domain": "communication", "normal": [0, 40], "warning": [41, 80], "critical": [81, 150], "weight": 0.20},
    "NAS_Cipher_Order": {"domain": "communication", "danger_if": "EEA0 first", "weight": 0.15, "once": True},
}

DOMAINS: list[str] = ["communication", "identity_access", "session_network", "command", "mission"]

# --- Mission profile (M1~M3·M8 정본) ---
MISSION_PROFILE: dict[str, object] = {
    "mission_type": "Recon",
    "mission_phase": "En-route",
    "mission_priority": "High",
    "mission_goal": "Area surveillance sector B3",
    "critical_asset": "UAV+camera",
    # E20: identity_access 키 통일; 5개 impact 도메인 전체 합이 100
    "mission_weight": {"communication": 30, "identity_access": 10, "session_network": 20, "command": 20, "mission": 20, "recovery": 0},
    # P0 panel-3: weight 독립 criticality floor. {domain: [[distrust_thr, floor], ...]}
    # high->low로 평가, 첫 매치가 이기고 없으면 0. overall = max(weighted_mean, max_d floor).
    # mission_weight==0 에서도 발화하여 보상적 평균이 안전 도메인을 희석하지 못하게 한다.
    # 71/45 는 band-cut에서 유도된 LOCK 상수(71 ≡ IMPACT_BANDS Red low; 45 ∈ Yellow[31,70]),
    # network-vuln-detector 패널이 검증·lock함(P3-Q4) — 자유 seed가 아님; 재발명 금지.
    "criticality_floor": {
        "command": [[71, 71], [40, 45]],
        "session_network": [[71, 71], [40, 45]],
        "identity_access": [[71, 45]],
        "communication": [],
        "mission": [],
    },
    "operational_constraints": {"max_alt_m": 120, "rtl_on_link_loss": True, "rtb_min": 30},
    "environment": "clear/urban",
    "session_ttl_s": 3240,
    "flight_modes": {"GUIDED": 4, "LOITER": 5, "RTL": 6, "LAND": 9},  # ArduPilot
    "config_version": "mdg-cfg-2026-07-07",  # X7 고정
}

# --- Confidence channel-quality priors (FEASIBILITY §3) 신뢰 채널품질 prior ---
CHANNEL_QUALITY: dict[str, float] = {
    "plaintext_mavlink_tap": 0.95,   # 14560/14556 평문 탭
    "port_5762_read": 0.90,
    "prometheus_9090": 0.90,
    "nas_log": 0.85,
    "mongo_conn_log": 0.60,
    "active_probe_estimate": 0.70,   # rtt/loss probe(능동 프로브 추정)
}

# --- Time-window / decay 파라미터 (FEASIBILITY §3) ---
TIME_WINDOWS: dict[str, float] = {
    "decay_s": 60,
    "policy_decay_s": 300,
    "rolling_s": 10,
    "observation_s": 5,
    "aggregation_s": 60,
    "evidence_ttl_s": 60,
    "correlation_window_s": 5,
}

# --- Recovery Feasibility priors (FEASIBILITY §3 · prototype §5) 복구 실현가능성 prior ---
# type -> success_probability, 예상 신뢰회복(domain->delta), risk, reversible,
# enforce_at (P4-2 강제-chokepoint ROLE KEY — INPUT이 공격자 SOURCE를 필터하는 netns;
# source와는 구별됨. config에서 소싱되어 결정론 코어가 testbed role/container 리터럴을 ZERO로
# 담게 한다, finding P2-3/A-1. dispatch 시 role KEY로 해석됨; 해석되지 않는 key는 mis-DROP이
# 아니라 inert DRY를 낸다).
RECOVERY_DEFAULT_ENFORCE_AT: str = "gcs_proxy"  # command plane 진입점 (폴백 chokepoint role key)
# response_tool/flight은 recovery_priors.yaml에서 MIRROR되어 pyyaml-부재 폴백이 type별
# response-tool TIER를 보존하게 한다(audit defaults.py:116 tier-inversion):
# 여기 response_tool이 없으면 _candidates(select_policy)가 모든 type에 대해 AUTO 도구
# nsenter_input_drop으로 폴백하여, backdoor_pause(docker_pause/OPER)와 send_signed_mode
# flight type들을 조용히 AUTO DROP 레인으로 강등시킨다. flight도 마찬가지로 HIGH/operator
# 에스컬레이션을 게이트한다. 이 두 key는 yaml 행 값과 byte 단위로 동일하게 유지하라.
RECOVERY_PRIORS: dict[str, dict[str, object]] = {
    "signed_land": {"success_probability": 0.90, "expected_trust_recovery": {"command": 40}, "risk": "HIGH", "reversible": False, "response_tool": "send_signed_mode", "flight": True, "enforce_at": "gcs_proxy"},
    "signed_rtl": {"success_probability": 0.90, "expected_trust_recovery": {"command": 40}, "risk": "HIGH", "reversible": False, "response_tool": "send_signed_mode", "flight": True, "enforce_at": "gcs_proxy"},
    "signed_guided": {"success_probability": 0.90, "expected_trust_recovery": {"command": 40}, "risk": "HIGH", "reversible": False, "response_tool": "send_signed_mode", "flight": True, "enforce_at": "gcs_proxy"},
    "backdoor_pause": {"success_probability": 0.95, "expected_trust_recovery": {"command": 30}, "risk": "MED", "reversible": True, "response_tool": "docker_pause", "flight": False, "enforce_at": "web_backend"},
    "backdoor_drop": {"success_probability": 0.85, "expected_trust_recovery": {"command": 30}, "risk": "MED", "reversible": True, "response_tool": "nsenter_input_drop", "flight": False, "enforce_at": "uav_ue"},
    "pfcp_firewall": {"success_probability": 0.80, "expected_trust_recovery": {"session_network": 20}, "risk": "MED", "reversible": True, "response_tool": "nsenter_input_drop", "flight": False, "enforce_at": "gcs_proxy"},
    "mongo_acl": {"success_probability": 0.85, "expected_trust_recovery": {"identity_access": 20}, "risk": "MED", "reversible": True, "response_tool": "nsenter_input_drop", "flight": False, "enforce_at": "web_backend"},
    "command_override": {"success_probability": 0.90, "expected_trust_recovery": {"command": 30}, "risk": "HIGH", "reversible": False, "response_tool": "send_signed_mode", "flight": True, "enforce_at": "gcs_proxy"},
}
# Feasibility 게이트 = success_probability >= 이 floor (M6/E-2 resolution).
# recovery_score>=0.7 이 아님: 20-40pt trust-delta prior는 recovery_score를 ~0.14로 상한하므로,
# 0.7 recovery_score 게이트는 모든 응답을 영구히 infeasible로 만든다.
# recovery_score (scoring.recovery_score)는 RANKING 전용. 이걸로 재게이트하지 마라.
RECOVERY_FEASIBLE_MIN: float = 0.70  # 최소 success_probability; prior는 0.80-0.95

# --- P1: 관측/C2 인프라를 DESTRUCTIVE 자율 복구로부터 SHIELD ------------------------------
# 컨테이너 전체를 파괴하는 복구 — docker_pause(컨테이너 전체 freeze) 또는
# docker_net_disconnect(네트워크에서 차단) — 중 enforce_at CONTAINER KEY가 이 집합에 속하면
# dispatch 시 INERT 처리된다(response.ResponseController.plan). 이는 STRUCTURAL 가드로,
# 탐지 신호(오탐 포함) 및 operator_auto와 무관하다: 어떤 자율 집행도 관측 대시보드
# (web_backend / :8080)나 C2 명령 chokepoint(gcs_proxy / :14556)를 무력화할 수 없다.
# 결정론적 집합 멤버십만 사용 — 어떤 LLM 필드도 이걸 읽지 않으므로(불변식1.), 적대적
# advice는 여기 컨테이너를 추가할 수도, 파괴적 도구를 이를 우회해 라우팅할 수도 없다.
#
# PRESERVATION(실제 위협 복구는 손대지 않음): SURGICAL / keyed 응답은 INFRA_DESTRUCTIVE_TOOLS
# 에 없으므로, 이 가드에 절대 걸리지 않는다 —
#   • backdoor_drop @ uav_ue : nsenter_input_drop '-s <verified attacker> -j DROP' (5762 차단),
#     이미 two-endpoint verified/DISTINCT/self-DoS resolver로 이중 게이트됨.
#   • send_signed_mode @ gcs_proxy : gcs_proxy를 THROUGH하여 서명 명령을 EMIT함(gcs_c2에
#     위임); chokepoint를 freeze/disconnect하지 않는다.
PROTECTED_INFRA_CONTAINERS: frozenset[str] = frozenset({"web_backend", "gcs_proxy"})
INFRA_DESTRUCTIVE_TOOLS: frozenset[str] = frozenset({"docker_pause", "docker_net_disconnect"})

# --- Debounce / de-escalation (X5/E15) 디바운스/완화 ---
DEBOUNCE_PHYSICAL_MIN_TICKS: int = 3
DEESCALATION_REVERT_QUIET_S: int = 120
FLIGHT_ACTION_AUTO_REVERT: bool = False

# --- Phase 2 (PS-7/B3) demo-mode 완화 — pyyaml-부재 경로의 폴백 (loader.demo_mode).
# 이 값들은 operator_auto(sandbox demo)에서만 적용된다; production은 전적으로 무시한다.
DEMO_PROVENANCE_RELAXED: bool = True   # operator_auto 하에서 주입된 high-severity를 record-then-pass
DEMO_DEBOUNCE_TICKS: int = 1           # demo debounce 유지 (< DEBOUNCE_PHYSICAL_MIN_TICKS)

# --- Anti-replay (PS-6) 재전송 방지 ---
SEQ_WINDOW: int = 1024
# Q-D-4 DOCUMENTATION-ONLY: SEQ_SKEW_S는 UNUSED(reader 없음 — grep 확인). 재전송 방지는
# SEQ_WINDOW(intent_ledger sequence band) + TS_SKEW_S(envelope ts skew)로 강제된다; 이 NTP
# max-skew 노트는 어떤 consumer에도 배선된 적이 없다. 문서화된 보정 노트로 남겨둠(무해한
# orphan), 삭제하지 않음; 어떤 scoring/routing 스칼라도 읽지 않는다. 값을 바꾸지 마라.
SEQ_SKEW_S: int = 200 / 1000.0 * 1  # ntp max_skew_ms 200 -> 아래에서 ±W초 band로 처리됨
TS_SKEW_S: int = 5  # envelope ts에 대한 ±W초 clock skew 허용치

# --- RTT baseline (P4-6, 라이브 uav_ue->gcs_proxy 14.5/30.2/38.6ms, mdev~11) ---
RTT_BASELINE_MS: float = 27.7
RTT_MDEV_MS: float = 11.0
RTT_K: float = 3.0  # baseline + k*mdev jitter band

# --- Correlation rules (E19) 상관 규칙 ---
CORRELATION_RULES: dict[str, dict[str, object]] = {
    "CR01": {
        "metrics": ["PFCP_Delete_Attempt", "Unauthorized_Command"],
        "max_time_diff_s": 5,
        "join": "time_only",
        "weight": 1.0,
        "min_members": 2,
    },
}

# --- Driver budgets (PA-1) 드라이버 예산 ---
DRIVER_BUDGETS: dict[str, int] = {
    "max_iters": 64,
    "max_pivots": 8,
    "k_dry": 4,
    "recursion_limit": 16,
}

# --- DefInputSpec (P2 target/recon spec) — 단일 진리원으로서 DefInputSpec이 inline
# testbed 리터럴을 ZERO로 담게 한다(A-1 교훈: 고정된 동적 IP 없음). STABLE 식별자만
# 여기 둔다(container/network 이름, 포트, NF :9090 엔드포인트, *pool*의 CIDR — per-UE
# 주소가 아님). Per-UE tun IP는 LIVE로 해석되며(resolve.py stage-2), 절대 고정하지
# 않는다. ------------------------------------------------------------------------ #
INPUT_SPEC: dict[str, object] = {
    "config_version": "mdg-cfg-2026-07-07",   # X7 고정 (MISSION_PROFILE 미러링)
    # §9-B 업링크 서명은 강제됨이 EXPECTED(MEMORY: uav_proxy drop 로그로 실제 ON —
    # gcs_proxy env로 판단하지 않음). 이는 정책 기대값이며; 관측값(world.signing)은
    # drop-log collector가 확인한다.
    "signing_expected": True,
    "ue_pool_cidr": "10.45.0.0/16",           # 동적 UE pool (tun_srsue); IP는 고정 안 함
    "ran_cidr": "10.44.0.0/16",               # RAN/cellular docker net (inspect로 보임)
    # role -> container -> (netns tap? / cellular docker net / tun iface / static IMSI / verify anchor)
    # IMSI는 ue.conf/ue2.conf BOOT 상수(P2-Q1 layer-1 정적 IMSI<->container 맵);
    # 동적 10.45.x tun IP는 LIVE로 해석됨(stage-2), 절대 고정 안 함.
    #
    # Role-set reconciliation (GATE2 resolve+verify, finding P2-5). 두 가지 검증 모드:
    #   - UE-pool role (uav, attacker): tun_iface 설정됨 => 2-stage (inspect + live tun-scan);
    #     동적 10.45.x IP 와 행위 anchor를 모두 만든다.
    #   - infra role (gcs_proxy, web_backend, uav_proxy): tun_iface=None, cellular_network=None
    #     => VERIFIED-BY-PRESENCE (resolve.py: rb.verified = pid is not None), ip=''(해석할
    #     UE-pool 주소 없음). Presence != 행위 검증; 라이브 anchor는 별도로 확인됨
    #     (targets/behavioral.py, ``verify_anchor`` 소비).
    # ``verify_anchor`` 는 LIVE 소비 필드(targets/behavioral.confirm_behavioral_anchor)로,
    # dead 아님: GATE2 probe가 읽는 별개의 ``behaviorally_verified`` 술어를 게이트한다.
    # v3-topology "6/6"은 여기 선언된 5개의 해석 가능 role + epc_smf(log-tail 전용,
    # ``log_containers`` 내)에 매핑됨; attacker_ue는 IMSI<->container pause 맵(P2-Q1 L1)이
    # 필요로 하므로 유지된다(문서의 6에는 없음). uav_proxy는 §9-B 업링크 서명 강제
    # 지점(MEMORY: gcs_proxy env가 아니라 그 drop-log로 signing ON 확인됨) — netns tap이
    # 아니라 그 docker-logs drop line으로 관측되므로 netns=False.
    "roles": [
        {"role": "gcs_proxy", "container": "gcs_proxy", "netns": True,
         "cellular_network": None, "tun_iface": None,
         "verify_anchor": "command_entry_udp_14556", "reach": ["gcs14556"]},
        {"role": "uav", "container": "uav_ue", "netns": True,
         "cellular_network": "net_cellular", "tun_iface": "tun_srsue",
         "imsi": "001010000000001",                       # ue.conf (uav_ue)
         "verify_anchor": "lo_14550_heartbeat_sys1", "reach": ["net_cellular"]},
        {"role": "attacker", "container": "attacker_ue", "netns": False,
         "cellular_network": "net_cellular", "tun_iface": "tun_srsue",
         "imsi": "001010000000002",                       # ue2.conf (attacker_ue)
         "verify_anchor": "port_5762_backdoor_attempt", "reach": []},
        {"role": "web_backend", "container": "web_backend", "netns": True,
         "cellular_network": None, "tun_iface": None,
         # 5762 LISTEN/ESTAB는 web_backend netns가 아니라 uav_ue netns에 존재(WebProbe도
         # uav_ue netns로 이전 관측). 따라서 이 role은 더 이상 5762 앵커를 소유하지 않는다. uav_ue의
         # behavioral bit는 design-lock된 lo_14550_heartbeat_sys1(anti-spoof)로 확정되므로 5762
         # LISTEN을 uav_ue anchor로 합류시키지 않는다(heartbeat 없이 flip 방지). web8080-native
         # 앵커가 없으면 fail-closed "" (behaviorally_verified positive-only, False는 무해).
         "verify_anchor": "", "reach": ["uav5762", "web8080"]},
        {"role": "uav_proxy", "container": "uav_proxy", "netns": False,
         "cellular_network": None, "tun_iface": None,
         "verify_anchor": "signing_drop_log_uav_proxy", "reach": []},
    ],
    # NF 메트릭 엔드포인트 (P4-2, net_core; localhost 아님). SMF/UPF/MME 라이브 확인됨.
    "nf_endpoints": {"smf": "10.50.0.4:9090", "upf": "10.50.0.7:9090",
                     "mme": "10.50.0.2:9090"},
    # log-tail 컨테이너 (docker logs stdout). SMF 세션테이블 + MME attach + Mongo +
    # uav_proxy 서명 drop-log (§9-B 강제 확인 소스; P3+ operator-go).
    "log_containers": {"smf": "epc_smf", "mme": "epc_mme", "mongo": "epc_mongo",
                       "uav_proxy": "uav_proxy"},
    # 관심 포트 (command 진입 / telemetry / uav lo cross-tap / backdoor / db / pfcp / web)
    "ports": {"command": 14556, "telemetry": 14560, "uav_lo_telemetry": 14550,
              "backdoor": 5762, "mongo": 27017, "pfcp": 8805, "web": 8080},
    # boot 시 WorldState.reach에 seed되는 닫힌 reach 어휘 (관측 전까지 전부 False)
    "reach_targets": ["gcs14556", "web8080", "uav5762", "mongo27017", "pfcp8805",
                      "net_core", "net_sgi"],
}
