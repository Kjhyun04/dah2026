"""닫힌 도구 레지스트리 — 26개 도구 계약(H-A/G, DESIGN_DECISIONS §2).

DefToolId 는 Literal 화이트리스트다: LLM 은 id 를 *선택*만 할 수 있고 절대 *발명*할 수
없다. 모든 도구는 완전히 등록된다(requires/consumes/produces/effect/exec/risk/T)
— ghost/dangling 도구 없음(E20). ``verify_tools`` 가 강제하는 것:
  - DefToolId Literal == REGISTRY 키(정확히 26개, ghost 없음, 누락 없음)
  - 모든 spec 이 모든 계약 필드를 채우고 있음
  - response 도구는 exec=safe-exec 를 바인딩; flight(send_signed_mode) risk=HIGH=operator
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

# --- 닫힌 id 화이트리스트(LLM 이 선택, 생성 불가) --- 26 ids ---
DefToolId = Literal[
    # sensor (10)
    "tap_mavlink_cmd", "tap_telemetry_14560", "tail_signing_drops",
    "scrape_pfcp_metrics", "tail_pfcp_smflog", "tail_mme_log", "read_nas_cipher",
    "tail_upf_antispoof", "probe_rtt_loss", "tail_mongo_conn",
    # analysis (9)
    "build_evidence", "correlate_window", "compute_trust", "compute_confidence",
    "compute_impact", "select_policy", "rank_recovery", "decide_mission", "emit_trace",
    # response (4)
    "send_signed_mode", "nsenter_input_drop", "docker_pause", "docker_net_disconnect",
    # control (3)
    "gate_evaluate", "operator_confirm", "ingest_verify",
]

Category = Literal["sensor", "analysis", "response", "control"]
Tier = Literal["RO", "AUTO", "OPER"]
Risk = Literal["LOW", "MED", "HIGH"]
Secret = Literal["none", "stdin"]


class DefToolSpec(BaseModel):
    """레지스트리 한 행. 완전한 등록 필요(dangling 없음)."""
    id: DefToolId
    owner: str
    category: Category
    backend: str
    requires: list[str] = Field(default_factory=list)     # worldstate 술어 / 사전조건
    consumes: list[str] = Field(default_factory=list)     # 읽는 payload 타입
    produces: list[str] = Field(default_factory=list)     # 방출하는 payload 타입
    effect: Optional[str] = None                          # 상태 전이(response) 또는 None
    exec: Optional[str] = None                            # safe-exec 바인딩(response) 또는 None
    risk: Risk = "LOW"
    tier: Tier = "RO"
    secret: Secret = "none"                               # R6: secret 은 stdin 경유, 절대 argv 아님
    T: str = "SensorEv"                                   # payload 타입 이름


def _s(**kw) -> DefToolSpec:
    return DefToolSpec(**kw)


REGISTRY: dict[str, DefToolSpec] = {t.id: t for t in [
    # ---------------- sensor (10) ---------------- (RO, effect 없음, exec 없음) ----
    _s(id="tap_mavlink_cmd", owner="col_gcs", category="sensor", backend="pymavlink",
       requires=["reach.gcs14556"], consumes=["wire"], produces=["SensorEv"], T="SensorEv",
       tier="RO"),
    _s(id="tap_telemetry_14560", owner="col_web", category="sensor", backend="pymavlink",
       requires=["reach.net_sgi"], consumes=["wire"], produces=["SensorEv"], T="SensorEv",
       tier="RO"),
    _s(id="tail_signing_drops", owner="col_uav", category="sensor", backend="log-tail",
       requires=[], consumes=["log"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="scrape_pfcp_metrics", owner="col_net", category="sensor", backend="prometheus",
       requires=["reach.net_core"], consumes=["metric"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="tail_pfcp_smflog", owner="col_net", category="sensor", backend="log-tail",
       requires=["reach.net_core"], consumes=["log"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="tail_mme_log", owner="col_net", category="sensor", backend="log-tail",
       requires=["reach.net_core"], consumes=["log"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="read_nas_cipher", owner="col_net", category="sensor", backend="docker-sdk",
       requires=[], consumes=["config"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="tail_upf_antispoof", owner="col_net", category="sensor", backend="log-tail",
       requires=["reach.net_core"], consumes=["log"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="probe_rtt_loss", owner="col_uav", category="sensor", backend="ping",
       requires=[], consumes=["probe"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="tail_mongo_conn", owner="col_mongo", category="sensor", backend="mongod-log",
       requires=["reach.mongo27017"], consumes=["log"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    # ---------------- analysis (9) ---------------- (RO, 결정론적) --------
    _s(id="build_evidence", owner="evidence_engine", category="analysis", backend="asyncio",
       consumes=["SensorEv"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="correlate_window", owner="correlation_engine", category="analysis", backend="asyncio",
       consumes=["SensorEv"], produces=["Incident"], T="Incident", tier="RO"),
    _s(id="compute_trust", owner="trust_engine", category="analysis", backend="asyncio",
       consumes=["SensorEv"], produces=["TrustObj"], T="TrustObj", tier="RO"),
    _s(id="compute_confidence", owner="trust_engine", category="analysis", backend="asyncio",
       consumes=["SensorEv"], produces=["TrustObj"], T="TrustObj", tier="RO"),
    _s(id="compute_impact", owner="mission_impact_engine", category="analysis", backend="asyncio",
       consumes=["TrustObj"], produces=["ImpactObj"], T="ImpactObj", tier="RO"),
    _s(id="select_policy", owner="policy_engine", category="analysis", backend="asyncio",
       consumes=["ImpactObj", "Incident"], produces=["Action"], T="Decision", tier="RO"),
    _s(id="rank_recovery", owner="recovery_engine", category="analysis", backend="asyncio",
       consumes=["Action"], produces=["Action"], T="Decision", tier="RO"),
    _s(id="decide_mission", owner="decision_engine", category="analysis", backend="asyncio",
       consumes=["ImpactObj", "Action"], produces=["Decision"], T="Decision", tier="RO"),
    _s(id="emit_trace", owner="decision_engine", category="analysis", backend="asyncio",
       consumes=["Decision"], produces=["Decision"], T="Decision", tier="RO", secret="stdin"),
    # ---------------- response (4) ---------------- (effect + safe-exec) -------
    _s(id="send_signed_mode", owner="response_controller", category="response", backend="signer-shim",
       requires=["signing", "role_verified.gcs"], consumes=["Decision"], produces=["EnforcedAction"],
       effect="flight_mode_set", exec="safe_exec.signer", risk="HIGH", tier="OPER", secret="stdin",
       T="Decision"),
    _s(id="nsenter_input_drop", owner="act_host", category="response", backend="nsenter+iptables",
       requires=["role_verified.target"], consumes=["Decision"], produces=["EnforcedAction"],
       effect="netns_input_drop", exec="safe_exec.nsenter_helper", risk="MED", tier="AUTO", T="Decision"),
    _s(id="docker_pause", owner="act_host", category="response", backend="docker-proxy",
       requires=["role_verified.target"], consumes=["Decision"], produces=["EnforcedAction"],
       effect="container_pause", exec="safe_exec.docker_backend", risk="MED", tier="OPER", T="Decision"),
    _s(id="docker_net_disconnect", owner="act_host", category="response", backend="docker-proxy",
       requires=["role_verified.target"], consumes=["Decision"], produces=["EnforcedAction"],
       effect="container_net_disconnect", exec="safe_exec.docker_backend", risk="MED", tier="OPER", T="Decision"),
    # ---------------- control (3) ---------------- ------------------------------
    _s(id="gate_evaluate", owner="orchestrator", category="control", backend="asyncio",
       requires=["config_version"], consumes=["Decision", "Action"], produces=["Decision"], tier="RO",
       T="Decision"),
    _s(id="operator_confirm", owner="operator_interface", category="control", backend="operator-ws",
       requires=["operator_cert"], consumes=["Decision"], produces=["Decision"], tier="OPER",
       secret="stdin", T="Decision"),
    _s(id="ingest_verify", owner="collector_manager", category="control", backend="mTLS+HMAC",
       requires=["ingest_key"], consumes=["SensorEv"], produces=["SensorEv"], tier="RO",
       secret="stdin", T="SensorEv"),
]}

TOOL_COUNT = 26


def get_spec(tool_id: str) -> DefToolSpec:
    return REGISTRY[tool_id]
