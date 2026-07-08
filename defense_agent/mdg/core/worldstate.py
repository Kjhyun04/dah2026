"""WorldState — closed predicates / artifacts (H-E). Single authoritative object
merged by ``sense`` each tick. Closed vocabulary only; no free-form state.

DESIGN_DECISIONS PA-3 names WorldState as a required model; it lives here and is
re-exported from ``state.py`` so ``mdg.core.state.WorldState`` resolves.
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

# Closed reach set (V3 §3): who/what is reachable on which plane.
ReachTarget = Literal[
    "gcs14556", "web8080", "uav5762", "mongo27017", "pfcp8805", "net_core", "net_sgi"
]
Domain = Literal["communication", "identity_access", "session_network", "command", "mission"]
ThreatLevel = Literal["none", "low", "medium", "high", "critical"]
Provenance = Literal["config", "inspect", "verified"]


class SigningObs(str, Enum):
    """Observed uplink-signing enforcement posture (P2-Q2 panel, tri-state).

    A bare bool conflated "confirmed OFF" with "not yet observed" — a security defect
    because §9-B signing is TOGGLE-based (real OFF is possible) and the observation is
    ASYMMETRIC (a drop-log line is positive ON evidence; the ABSENCE of drops is NOT
    OFF evidence). The tri-state encodes that asymmetry so the boot default (UNKNOWN)
    can never be mistaken for a confirmed-OFF posture (which would drive over-response,
    PS-7 self-DoS).

    Transition authority (locked): enforcement changes ONLY on a uav_proxy authoritative
    signal collected at P3+ (drop-log line ``⛔ 서명검증 실패 → SITL 차단 (누적 N)`` or a
    ``🔒 서명 강제 ON`` boot banner / ``/api/signing`` enforced). gcs_proxy env, uav env,
    docker inspect, and drop-ABSENCE never transition it (MEMORY 오판 가드 코드화).
    """
    UNKNOWN = "unknown"            # boot default; NOT off — no authoritative signal yet
    CONFIRMED_ON = "confirmed_on"  # uav_proxy drop-log / ON-banner / /api/signing enforced
    CONFIRMED_OFF = "confirmed_off"  # uav_proxy OFF-banner / unsigned cmd reached SITL


def signing_enforced(obs: "SigningObs") -> bool:
    """is_enforced predicate: only CONFIRMED_ON counts as enforced (legality gate).

    UNKNOWN (unconfirmed) is conservatively treated as NOT enforced — a signed command
    tool must not depend on an unconfirmed authentication control.
    """
    return obs is SigningObs.CONFIRMED_ON


class AppliedRule(BaseModel):
    """An enforced (or attempted) response rule tracked for revert + effect-confirm."""
    rule: str
    revert_cmd: str = ""
    ts: float = 0.0
    applied_tick: int = 0             # tick_i at which act applied it (bundle N-tick debounce, X5)
    decision_id: str = ""
    config_version: str = ""
    confirmed: bool = False           # effect_confirm sets this (PA-2). Not an exec gate.
    reverted: bool = False            # de-escalation revert marker (bundle, X5/E15)
    provenance: Provenance = "config"


class RoleBinding(BaseModel):
    """role -> container -> IP resolved at recon boot (H-I). tun IP via exec-scan (A-1).

    Two DISTINCT predicates (finding P2-1, GATE2 resolve+verify):
      - ``verified``  = RESOLUTION/PRESENCE: the container exists (inspect .State.Pid) and,
        for UE-pool roles, its live tun IP is inside ``ue_pool_cidr``. This is a topology
        check — it does NOT prove the role is behaving. Legality (role_verified) reads this.
      - ``behaviorally_verified`` = the live behavioural anchor (``RoleSpec.verify_anchor``)
        was observed (e.g. HEARTBEAT sysid=1 on uav_ue lo:14550; 5762 ESTAB/LISTEN; signing
        drop-log). Set by ``targets/behavioral.apply_behavioral_verification`` from live
        collector evidence. A container that exists but emits no/adverse anchor is
        ``verified=True, behaviorally_verified=False`` — presence is not overstated as a
        behavioural verify. Boot default False (live observation is operator-go)."""
    role: str
    container: str = ""
    ip: str = ""
    verified: bool = False            # RESOLVED/PRESENT (topology + pool membership) — legality reads this
    behaviorally_verified: bool = False  # live verify_anchor observed (P2-1); NOT a legality predicate
    provenance: Provenance = "config"


class Baseline(BaseModel):
    """Per-signal baselines (RTT EWMA/mdev, counter high-water) — P4-6/P4-3."""
    rtt_baseline_ms: float = 27.7
    rtt_mdev_ms: float = 11.0
    counters: dict[str, int] = Field(default_factory=dict)   # last-seen monotonic counters


class WorldState(BaseModel):
    """Closed-predicate testbed posture. reach/signing/role_verified/threat/applied
    + ip_map/pid/baseline."""
    # posture predicates
    reach: dict[str, bool] = Field(default_factory=dict)          # reach(X) -> bool
    signing: SigningObs = SigningObs.UNKNOWN                       # OBSERVED signing posture (tri-state, P2-Q2)
    role_verified: dict[str, bool] = Field(default_factory=dict)  # container -> RESOLVED/PRESENT (legality predicate)
    behaviorally_verified: dict[str, bool] = Field(default_factory=dict)  # container -> live anchor observed (P2-1)
    threat: dict[str, ThreatLevel] = Field(default_factory=dict)  # domain -> level
    applied: dict[str, AppliedRule] = Field(default_factory=dict) # rule -> AppliedRule
    # artifacts
    ip_map: dict[str, str] = Field(default_factory=dict)          # role/imsi/ip -> ip/container
    roles: dict[str, RoleBinding] = Field(default_factory=dict)
    # static IMSI -> container boot map (spec.imsi_container_map, resolve.ResolveResult.imsi_container).
    # A boot CONSTANT (ue*.conf), NOT dynamic — it lets the response controller re-attribute a live
    # SMF-table IMSI back to a container for the P4 stale-binding cross-check (재할당 IP self-DoS 차단).
    imsi_container: dict[str, str] = Field(default_factory=dict)  # static IMSI -> container (P4-1/P2-Q1)
    pid: dict[str, int] = Field(default_factory=dict)             # role -> pid (nsenter target)
    baseline: Baseline = Field(default_factory=Baseline)
    # Per-domain liveness verdict (P3-Q5). A domain here has a watchdog-dead collector
    # (silence-gap -> signed sensor_loss, PS-2) and is DROPPED from the trust/impact
    # present-set. Driven by the collector HEARTBEAT via Watchdog sensor_loss (the true
    # liveness SOURCE), NOT by evidence.fresh_domains (which conflates a quiet event-driven
    # collector with a dead one). Empty by default -> all-present (fail-safe fallback).
    dead_domains: list[Domain] = Field(default_factory=list)      # watchdog-dead domains (present-set exclusion)
    config_version: str = ""

    def with_applied(self, rule: AppliedRule) -> "WorldState":
        """Pure merge helper used by act's post world_update."""
        nxt = self.model_copy(deep=True)
        nxt.applied[rule.rule] = rule
        return nxt
