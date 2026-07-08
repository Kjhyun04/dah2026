"""behavioral — consume ``RoleSpec.verify_anchor`` into the ``behaviorally_verified``
predicate (finding P2-1, GATE2 resolve+verify item A-1).

Why this module exists: ``resolve.py`` sets ``RoleBinding.verified`` from PRESENCE only
(container exists via inspect .State.Pid; UE-pool roles additionally require the live tun
IP to sit inside ``ue_pool_cidr``). Presence is a TOPOLOGY check — a container that exists
but emits no HEARTBEAT / the wrong sysid / no backdoor-port state would still be
``verified=True``, overstating GATE2 assurance. The declared ``RoleSpec.verify_anchor``
(``lo_14550_heartbeat_sys1`` etc.) was a DEAD field, read by no code.

This module makes ``verify_anchor`` LIVE: it maps each anchor token to a predicate over
observed behavioural evidence and produces the DISTINCT ``behaviorally_verified`` bit that
the GATE2 behavioural probe reads — leaving ``verified`` (and therefore legality's
``role_verified``) as the pure presence/resolution predicate.

Operator-go note: the underlying live observations (air-side tcpdump HEARTBEAT decode, ss
5762 state, uav_proxy signing drop-log) are collected out-of-graph and are state-change-0
read-only, but on the sandbox testbed the live taps are operator-go reserved. Absent
evidence => every anchor is UNconfirmed (False) — the honest boot posture. ``recon_boot``
seeds ``behaviorally_verified`` all-False; the runtime feeds live ``AnchorEvidence`` at the
collector/effect-confirm phase (``apply_behavioral_verification``) as observations arrive.

Boundaries: pure functions over a plain dataclass; NO subprocess, NO docker/sock literal,
NO import of the resolve stage. Unknown/empty anchor => False (fail-closed, never crashes).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .inputspec import RoleSpec


@dataclass
class AnchorEvidence:
    """Observed behavioural signals for ONE role, distilled from live collector output.

    All fields default to the 'not observed' value so an empty AnchorEvidence (the boot /
    operator-go posture) confirms nothing. The runtime populates these from the same
    collector payloads that feed ``sense`` (air-side HEARTBEAT decode, ss 5762 state,
    uav_proxy signing drop-log) — this module never observes anything itself.
    """
    heartbeat_sys: Optional[int] = None   # decoded MAVLink system id on uav_ue lo:14550 (None = none seen)
    command_entry_seen: bool = False      # a packet observed on the gcs_proxy command-entry UDP:14556 tap
    port_5762_listen: bool = False        # 5762 in LISTEN (web_backend backdoor port present)
    port_5762_estab: bool = False         # 5762 has an ESTABLISHED connection (attacker backdoor attempt)
    signing_drop_seen: bool = False       # uav_proxy signing-verify-fail drop line observed (§9-B ON)


# anchor token -> predicate over AnchorEvidence. Adding a role's anchor here is the ONLY
# wiring needed to make it live-consumed (keeps the config anchor and its check colocated).
_ANCHOR_CHECKS: dict[str, Callable[[AnchorEvidence], bool]] = {
    # uav: a HEARTBEAT with system id == 1 on the uav_ue lo:14550 cross-tap (D-1).
    "lo_14550_heartbeat_sys1": lambda e: e.heartbeat_sys == 1,
    # gcs_proxy: command-entry plane is live on UDP:14556 (the uplink command entry, §P).
    "command_entry_udp_14556": lambda e: e.command_entry_seen,
    # attacker: an ESTABLISHED connection on the 5762 backdoor = a backdoor attempt.
    "port_5762_backdoor_attempt": lambda e: e.port_5762_estab,
    # web_backend: 5762 present/LISTEN (backdoor port bound; ESTAB also satisfies presence).
    "port_5762_listen": lambda e: e.port_5762_listen or e.port_5762_estab,
    # uav_proxy: the §9-B signing-verify-fail drop line (authoritative enforcement signal).
    "signing_drop_log_uav_proxy": lambda e: e.signing_drop_seen,
}


def confirm_behavioral_anchor(anchor: str, evidence: Optional[AnchorEvidence]) -> bool:
    """True iff the role's declared ``verify_anchor`` is satisfied by ``evidence``.

    Fail-closed: unknown/empty anchor or missing evidence -> False. This is the single
    consumer of ``RoleSpec.verify_anchor`` (it is no longer a dead field)."""
    if not anchor or evidence is None:
        return False
    check = _ANCHOR_CHECKS.get(anchor)
    return bool(check(evidence)) if check is not None else False


def apply_behavioral_verification(
    roles: list[RoleSpec],
    evidence: Optional[dict[str, AnchorEvidence]] = None,
) -> dict[str, bool]:
    """container -> behaviorally_verified, from each role's ``verify_anchor`` + live evidence.

    ``evidence`` is keyed by container (matching ``world.role_verified`` / ``world.roles``);
    a container absent from the map => no evidence => False (operator-go / not-yet-observed).
    Returns a bit for EVERY declared role so the GATE2 probe sees the full role set with a
    behavioural verdict distinct from the presence verdict."""
    ev_map = evidence or {}
    return {
        r.container: confirm_behavioral_anchor(r.verify_anchor, ev_map.get(r.container))
        for r in roles
    }
