"""select_policy (H-F) — Legality gate builds the legal candidate set.

Maps tripped incidents/impact to candidate response Actions from the closed
registry, then filters by legality (registered ∧ preconds ∧ config pin). Physical
actions require N-tick debounce (X5) handled downstream. No SDN/replan (closed set).
"""
from __future__ import annotations

import re

from ...config import defaults as D
from ...config import loader
from ..legality import legal_actions
from ..state import Action, MDGState
from ..worldstate import WorldState

# incident kind -> candidate recovery types (closed mapping)
_INCIDENT_RECOVERY = {
    "CR01": ["pfcp_firewall", "command_override"],
    # Phase 3 (B2, S2) — single-signal now offers BOTH the container-isolation recovery
    # (backdoor_pause, docker_pause) AND the flight-recovery candidate (signed_guided,
    # send_signed_mode). This is CANDIDATE WIRING ONLY — the legality gate (send_signed_mode
    # requires "signing" == CONFIRMED_ON ∧ role_verified.gcs) DOUBLE-GATES signed_guided out
    # whenever signing is UNKNOWN (the live/production posture), so S1 and replay stay
    # byte-identical: only backdoor_pause survives select_policy under UNKNOWN signing. When
    # signing is CONFIRMED (Phase 6, testbed side), signed_guided enters legal_actions as an
    # OPER/HIGH candidate; ranking is left to recovery_priors (no core _sort_key boost) — under
    # equal candidates backdoor_pause (succ 0.95, MED) still out-ranks signed_guided (0.90, HIGH),
    # so admitting signed_guided never perturbs the S1 selection. See recovery_priors.yaml.
    "single-signal": ["backdoor_pause", "signed_guided"],
    # row D (step 5) — dedicated 5762 backdoor kind (correlate emits it ONLY for
    # Port_5762_State). KEY isolates the 5762 signal so no other tripped metric can route
    # to the nsenter DROP. Step 7 lands the recovery-type value: "backdoor_drop" is the
    # dedicated rtype registered (steps 8/9) in recovery_priors with response_tool=
    # nsenter_input_drop + enforce_at="uav_ue" (5762 LISTEN netns). inc.target (step 6
    # peer IP) is carried into Action.params.target by _candidates below; DROP stays inert
    # DRY unless both target selector and enforce_at role-key resolve to VERIFIED+DISTINCT
    # bindings at dispatch (fail-closed).
    "BACKDOOR_5762": ["backdoor_drop"],
}

# Phase 3 panel fix — flight-actuator DOMAIN GUARD. correlate emits the GENERIC
# "single-signal" kind for EVERY tripped non-5762 metric (RTT/mongo/NAS/telemetry/PFCP),
# so the kind alone cannot tell a command-hijack apart from an identity_access or
# communication blip. signed_guided (send_signed_mode) is a HIGH/OPER *irreversible flight
# uplink* (GUIDED 30m re-establish) and must fire ONLY for a command-domain incident — never
# for an unrelated single-signal. Without this, signing=CONFIRMED_ON (testbed posture) +
# gcs_proxy verified while web_backend is NOT (backdoor_pause filtered) would make signed_guided
# the SOLE legal candidate for e.g. a MongoDB anomaly and issue a flight-mode command (PS-7
# spurious-actuator / safety-surface widening). We gate the flight rtype by the incident's
# domain, derived from the tripped member metric's config domain (D.METRICS[metric].domain).
# FAIL-CLOSED: an unrecognized member metric yields no domain -> signed_guided is NOT admitted.
# Container-isolation (backdoor_pause) stays domain-agnostic. This restricts the candidate set
# ONLY; the legality signing gate still double-gates signed_guided out under UNKNOWN signing, so
# the live/replay legal set stays byte-identical (불변식①). Command single-signals
# (Unauthorized_Command / Signature_Verify_Fail) are unaffected — signed_guided still enters.
_RTYPE_DOMAIN_GUARD = {"signed_guided": "command"}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _incident_domains(inc) -> set[str]:
    """Domains of an incident's tripped member metrics (config-sourced, D.METRICS —
    the same table compute_trust reads directly). Unknown metrics contribute nothing
    (fail-closed for the flight-actuator guard)."""
    out: set[str] = set()
    for m in getattr(inc, "members", []) or []:
        spec = D.METRICS.get(m)
        if isinstance(spec, dict) and spec.get("domain"):
            out.add(str(spec["domain"]))
    return out

# recovery_type -> ENFORCEMENT chokepoint CONTAINER key (finding P4-2) is CONFIG-sourced
# (recovery_priors[<rtype>].enforce_at + default_enforce_at), NOT an inline literal here: the
# deterministic core must carry ZERO testbed role/container names (GATE2 hardcoding-0, finding
# P2-3/A-1). The keyspace is the CONTAINER name — pid/role_verified are container-keyed, and
# response._resolve_endpoints resolves enforce_at via the container-keyed pid map (a role alias
# misses -> inert). The netns whose INPUT filters the attacker SOURCE — DISTINCT from the source so
# the DROP is coherent (entering the attacker's own netns to drop its own ip is a no-op). The key
# must resolve to a VERIFIED binding at dispatch or the plan stays inert DRY (fail-closed); the LIVE
# enforcement-point routing is GATE2/operator-go RESERVED — a non-resolving key never mis-DROPs.
# backdoor_drop's enforce_at is pinned to container "uav_ue" (5762 LISTEN netns) by recovery_priors
# (steps 8/9), which OVERRIDES the default_enforce_at=gcs_proxy fallback below; until that config
# row lands, backdoor_drop has empty priors -> the gcs_proxy default (wrong chokepoint) is why the
# config registration is the single source of truth for correct 5762 enforcement.


def _classify_target(t: str) -> str:
    """Derive the target_kind selector KIND (P4-Q1) from the untrusted incident.target string.
    Pure syntactic classification — NO live resolution here (that is a verified-map lookup at
    dispatch). Empty -> "" (falls back to the legacy role at dispatch)."""
    t = (t or "").strip()
    if not t:
        return ""
    if _IPV4_RE.match(t):
        return "ip"
    if t.isdigit():
        return "imsi"
    return "role"


def _candidates(state: MDGState) -> list[Action]:
    rp = loader.recovery_priors()
    priors = rp.get("recovery_priors", {})
    default_enforce_at = str(rp.get("default_enforce_at", ""))
    incidents = state.get("incidents", [])
    seen: set[str] = set()
    out: list[Action] = []
    for inc in incidents:
        doms = None  # lazily computed once per incident
        for rtype in _INCIDENT_RECOVERY.get(inc.kind, []):
            # flight-actuator domain guard (do NOT consume `seen` when skipped: another
            # command-domain incident this tick may still legitimately emit this rtype).
            guard = _RTYPE_DOMAIN_GUARD.get(rtype)
            if guard is not None:
                if doms is None:
                    doms = _incident_domains(inc)
                if guard not in doms:
                    continue
            if rtype in seen:
                continue
            seen.add(rtype)
            p = priors.get(rtype, {})
            out.append(Action(
                tool_id=str(p.get("response_tool", "nsenter_input_drop")),
                params={"recovery_type": rtype, "target": inc.target,
                        "target_kind": _classify_target(inc.target),
                        # ENFORCEMENT chokepoint (finding P4-2) — DISTINCT from the attacker source.
                        # Config-sourced CONTAINER KEY (no core literal, P2-3/A-1). For backdoor_drop
                        # priors carry enforce_at="uav_ue" (steps 8/9), so p.get wins and the
                        # default_enforce_at=gcs_proxy fallback is bypassed for the 5762 DROP.
                        "enforce_at": str(p.get("enforce_at") or default_enforce_at)},
                risk=str(p.get("risk", "MED")),
                reversible=bool(p.get("reversible", True)),
                recovery_type=rtype,
            ))
    return out


def select_policy(state: MDGState) -> dict:
    world: WorldState = state.get("worldstate") or WorldState()
    cfg = state.get("config_version", world.config_version)
    cands = _candidates(state)
    legal = legal_actions(cands, world, cfg)
    return {"legal_actions": legal}
