"""FIXED constants (FEASIBILITY §3 · prototype §5 정본 config) as Python-native
source of truth. The parallel *.yaml files mirror these values; ``loader.py``
prefers YAML when pyyaml is installed and falls back here otherwise.

These are the values the deterministic scoring pipeline (E5-E8/E19) reads. They
are FIXED (no live source) per FEASIBILITY_AUDIT §3 and prototype thresholds.yaml.
"""
from __future__ import annotations

# --- E7: band -> (severity, deviation) mapping (prototype thresholds.yaml) ---
SEVERITY_FACTOR: dict[str, float] = {
    "info": 0.0,
    "low": 0.1,
    "medium": 0.3,
    "high": 0.6,
    "critical": 1.0,
}

# dev is the in-band scale; obs>0 blanket dev=1.0 is DEPRECATED (E7).
BAND_MAP: dict[str, dict[str, object]] = {
    "normal": {"severity": "info", "dev": 0.0},
    "warning": {"severity": "medium", "dev": 0.4},
    "critical": {"severity": "high", "dev": 0.7},
    "danger": {"severity": "critical", "dev": 1.0},
}

# --- Trust / Impact banding (M5/M7) ---
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

# --- E8: confidence used ONCE as a conservative band shift (no multiply) ---
LOW_CONFIDENCE_THRESHOLD: float = 0.5

# --- metric weight table (weight is per-domain sum <= 1, E6; no renormalize) ---
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
    # E20: identity_access key unified; sums to 100 across the 5 impact domains
    "mission_weight": {"communication": 30, "identity_access": 10, "session_network": 20, "command": 20, "mission": 20, "recovery": 0},
    # P0 panel-3: weight-independent criticality floor. {domain: [[distrust_thr, floor], ...]}
    # evaluated high->low, first match wins else 0. overall = max(weighted_mean, max_d floor).
    # Fires even at mission_weight==0 so a compensatory mean cannot dilute a safety domain.
    # 71/45 are band-cut-derived LOCK constants (71 ≡ IMPACT_BANDS Red low; 45 ∈ Yellow[31,70]),
    # network-vuln-detector panel validated & locked (P3-Q4) — NOT free seeds; do NOT re-invent.
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
    "config_version": "mdg-cfg-2026-07-07",  # X7 pin
}

# --- Confidence channel-quality priors (FEASIBILITY §3) ---
CHANNEL_QUALITY: dict[str, float] = {
    "plaintext_mavlink_tap": 0.95,   # 14560/14556 평문 탭
    "port_5762_read": 0.90,
    "prometheus_9090": 0.90,
    "nas_log": 0.85,
    "mongo_conn_log": 0.60,
    "active_probe_estimate": 0.70,   # rtt/loss probe
}

# --- Time-window / decay parameters (FEASIBILITY §3) ---
TIME_WINDOWS: dict[str, float] = {
    "decay_s": 60,
    "policy_decay_s": 300,
    "rolling_s": 10,
    "observation_s": 5,
    "aggregation_s": 60,
    "evidence_ttl_s": 60,
    "correlation_window_s": 5,
}

# --- Recovery Feasibility priors (FEASIBILITY §3 · prototype §5) ---
# type -> success_probability, expected trust recovery (domain->delta), risk, reversible,
# enforce_at (P4-2 enforcement-chokepoint ROLE KEY — the netns whose INPUT filters the attacker
# SOURCE; DISTINCT from the source. Config-sourced so the deterministic core carries ZERO testbed
# role/container literals, finding P2-3/A-1. Resolves to a role KEY at dispatch; a non-resolving
# key yields an inert DRY, never a mis-DROP).
RECOVERY_DEFAULT_ENFORCE_AT: str = "gcs_proxy"  # command plane entry (fallback chokepoint role key)
# response_tool/flight are MIRRORED from recovery_priors.yaml so the pyyaml-absent
# fallback preserves the response-tool TIER per type (audit defaults.py:116 tier-inversion):
# without response_tool here, _candidates(select_policy) falls back to the AUTO tool
# nsenter_input_drop for EVERY type, silently demoting backdoor_pause (docker_pause/OPER)
# and the send_signed_mode flight types into the AUTO DROP lane. flight likewise gates the
# HIGH/operator escalation. Keep these two keys byte-identical to the yaml row values.
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
# Feasibility gate = success_probability >= this floor (M6/E-2 resolution).
# NOT recovery_score>=0.7: the 20-40pt trust-delta priors cap recovery_score at ~0.14,
# so a 0.7 recovery_score gate would make every response permanently infeasible.
# recovery_score (scoring.recovery_score) is RANKING-ONLY. Do not re-gate on it.
RECOVERY_FEASIBLE_MIN: float = 0.70  # min success_probability; priors are 0.80-0.95

# --- Debounce / de-escalation (X5/E15) ---
DEBOUNCE_PHYSICAL_MIN_TICKS: int = 3
DEESCALATION_REVERT_QUIET_S: int = 120
FLIGHT_ACTION_AUTO_REVERT: bool = False

# --- Phase 2 (PS-7/B3) demo-mode relaxation — fallback for the pyyaml-absent path (loader.demo_mode).
# These values apply ONLY under operator_auto (sandbox demo); production ignores them entirely.
DEMO_PROVENANCE_RELAXED: bool = True   # record-then-pass injected high-severity under operator_auto
DEMO_DEBOUNCE_TICKS: int = 1           # demo debounce hold (< DEBOUNCE_PHYSICAL_MIN_TICKS)

# --- Anti-replay (PS-6) ---
SEQ_WINDOW: int = 1024
# Q-D-4 DOCUMENTATION-ONLY: SEQ_SKEW_S is UNUSED (no reader — grep confirmed). Anti-replay is
# enforced by SEQ_WINDOW (intent_ledger sequence band) + TS_SKEW_S (envelope ts skew); this NTP
# max-skew note was never wired to a consumer. Left in place as a documented calibration note,
# NOT deleted (harmless orphan); no scoring/routing scalar reads it. Do NOT change the value.
SEQ_SKEW_S: int = 200 / 1000.0 * 1  # ntp max_skew_ms 200 -> handled as ±W seconds band below
TS_SKEW_S: int = 5  # ±W seconds clock skew allowance for envelope ts

# --- RTT baseline (P4-6, live uav_ue->gcs_proxy 14.5/30.2/38.6ms, mdev~11) ---
RTT_BASELINE_MS: float = 27.7
RTT_MDEV_MS: float = 11.0
RTT_K: float = 3.0  # baseline + k*mdev jitter band

# --- Correlation rules (E19) ---
CORRELATION_RULES: dict[str, dict[str, object]] = {
    "CR01": {
        "metrics": ["PFCP_Delete_Attempt", "Unauthorized_Command"],
        "max_time_diff_s": 5,
        "join": "time_only",
        "weight": 1.0,
        "min_members": 2,
    },
}

# --- Driver budgets (PA-1) ---
DRIVER_BUDGETS: dict[str, int] = {
    "max_iters": 64,
    "max_pivots": 8,
    "k_dry": 4,
    "recursion_limit": 16,
}

# --- DefInputSpec (P2 target/recon spec) — single source of truth so DefInputSpec
# carries ZERO inline testbed literals (A-1 lesson: no pinned dynamic IPs). Only
# STABLE identifiers live here (container/network names, ports, NF :9090 endpoints,
# CIDRs of the *pools* — not per-UE addresses). Per-UE tun IPs are resolved LIVE
# (resolve.py stage-2), never pinned. ------------------------------------------- #
INPUT_SPEC: dict[str, object] = {
    "config_version": "mdg-cfg-2026-07-07",   # X7 pin (mirrors MISSION_PROFILE)
    # §9-B uplink signing is EXPECTED enforced (MEMORY: actual ON via uav_proxy drop
    # log — NOT judged from gcs_proxy env). This is the policy expectation; the
    # observed value (world.signing) is confirmed by the drop-log collector.
    "signing_expected": True,
    "ue_pool_cidr": "10.45.0.0/16",           # dynamic UE pool (tun_srsue); IPs NOT pinned
    "ran_cidr": "10.44.0.0/16",               # RAN/cellular docker net (inspect-visible)
    # role -> container -> (netns tap? / cellular docker net / tun iface / static IMSI / verify anchor)
    # IMSI is the ue.conf/ue2.conf BOOT CONSTANT (P2-Q1 layer-1 static IMSI<->container map);
    # the dynamic 10.45.x tun IP is resolved LIVE (stage-2), never pinned.
    #
    # Role-set reconciliation (GATE2 resolve+verify, finding P2-5). Two verification modes:
    #   - UE-pool roles (uav, attacker): tun_iface set => 2-stage (inspect + live tun-scan);
    #     they yield a dynamic 10.45.x IP AND a behavioural anchor.
    #   - infra roles (gcs_proxy, web_backend, uav_proxy): tun_iface=None, cellular_network=None
    #     => VERIFIED-BY-PRESENCE (resolve.py: rb.verified = pid is not None) with ip='' (no
    #     UE-pool address to resolve). Presence != behavioural verify; the live anchor is
    #     confirmed separately (targets/behavioral.py, consuming ``verify_anchor``).
    # ``verify_anchor`` is a LIVE-consumed field (targets/behavioral.confirm_behavioral_anchor),
    # NOT dead: it gates the distinct ``behaviorally_verified`` predicate the GATE2 probe reads.
    # The v3-topology "6/6" maps to these 5 declared resolvable roles + epc_smf (log-tail only,
    # in ``log_containers``); attacker_ue is retained (not in the doc's 6) because the IMSI<->
    # container pause map (P2-Q1 L1) needs it. uav_proxy is the §9-B uplink-signing enforcement
    # point (MEMORY: signing ON confirmed via its drop-log, NOT gcs_proxy env) — observed via
    # its docker-logs drop line, not a netns tap, so netns=False.
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
    # NF metric endpoints (P4-2, net_core; NOT localhost). SMF/UPF/MME live-confirmed.
    "nf_endpoints": {"smf": "10.50.0.4:9090", "upf": "10.50.0.7:9090",
                     "mme": "10.50.0.2:9090"},
    # log-tail containers (docker logs stdout). SMF session-table + MME attach + Mongo +
    # uav_proxy signing drop-log (§9-B enforcement confirmation source; P3+ operator-go).
    "log_containers": {"smf": "epc_smf", "mme": "epc_mme", "mongo": "epc_mongo",
                       "uav_proxy": "uav_proxy"},
    # ports of interest (command entry / telemetry / uav lo cross-tap / backdoor / db / pfcp / web)
    "ports": {"command": 14556, "telemetry": 14560, "uav_lo_telemetry": 14550,
              "backdoor": 5762, "mongo": 27017, "pfcp": 8805, "web": 8080},
    # closed reach vocabulary seeded into WorldState.reach at boot (all False until observed)
    "reach_targets": ["gcs14556", "web8080", "uav5762", "mongo27017", "pfcp8805",
                      "net_core", "net_sgi"],
}
