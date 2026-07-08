"""Closed tool registry — 27 tool contracts (H-A/G, DESIGN_DECISIONS §2).

DefToolId is a Literal whitelist: the LLM may only *choose* an id, never *invent*
one. Every tool is FULLY registered (requires/consumes/produces/effect/exec/risk/T)
— no ghost/dangling tools (E20). ``verify_tools`` enforces:
  - DefToolId Literal == REGISTRY keys (exactly 27, no ghost, no missing)
  - every spec has all contract fields populated
  - response tools bind exec=safe-exec; flight (send_signed_mode) risk=HIGH=operator
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

# --- closed id whitelist (LLM chooses, cannot create) --- 27 ids ---
DefToolId = Literal[
    # sensor (11)
    "tap_mavlink_cmd", "tap_telemetry_14560", "tail_signing_drops", "read_port_state",
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
    """One registry row. Complete registration required (no dangling)."""
    id: DefToolId
    owner: str
    category: Category
    backend: str
    requires: list[str] = Field(default_factory=list)     # worldstate predicates / preconds
    consumes: list[str] = Field(default_factory=list)     # payload types read
    produces: list[str] = Field(default_factory=list)     # payload types emitted
    effect: Optional[str] = None                          # state transition (response) or None
    exec: Optional[str] = None                            # safe-exec binding (response) or None
    risk: Risk = "LOW"
    tier: Tier = "RO"
    secret: Secret = "none"                               # R6: secret via stdin, never argv
    T: str = "SensorEv"                                   # payload type name


def _s(**kw) -> DefToolSpec:
    return DefToolSpec(**kw)


REGISTRY: dict[str, DefToolSpec] = {t.id: t for t in [
    # ---------------- sensor (11) ---------------- (RO, no effect, no exec) ----
    _s(id="tap_mavlink_cmd", owner="col_gcs", category="sensor", backend="pymavlink",
       requires=["reach.gcs14556"], consumes=["wire"], produces=["SensorEv"], T="SensorEv",
       tier="RO"),
    _s(id="tap_telemetry_14560", owner="col_web", category="sensor", backend="pymavlink",
       requires=["reach.net_sgi"], consumes=["wire"], produces=["SensorEv"], T="SensorEv",
       tier="RO"),
    _s(id="tail_signing_drops", owner="col_uav", category="sensor", backend="log-tail",
       requires=[], consumes=["log"], produces=["SensorEv"], T="SensorEv", tier="RO"),
    _s(id="read_port_state", owner="col_uav", category="sensor", backend="ss",
       requires=["reach.uav5762"], consumes=["ss"], produces=["SensorEv"], T="SensorEv", tier="RO"),
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
    # ---------------- analysis (9) ---------------- (RO, deterministic) --------
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

TOOL_COUNT = 27


def get_spec(tool_id: str) -> DefToolSpec:
    return REGISTRY[tool_id]
