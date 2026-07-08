"""recon_boot (PA-1) — OUT-OF-GRAPH one-time boot. Builds state0 from DefInputSpec:
role->container->IP 2-stage resolve+verify (H-I; UE-pool tun IP via live netns scan,
A-1), signing/NAS/port/IP-map baseline, ledger+seq HWM recovery. The tick graph has
NO recon node.

Boot baseline (P2 scope):
  - signing : observed posture starts ``SigningObs.UNKNOWN`` (P2-Q2 tri-state, NOT "off").
    §9-B signing is enforced live but that is CONFIRMED only by a uav_proxy authoritative
    signal (drop-log / ON-banner / /api/signing) at the P3+ collector — never judged from
    gcs_proxy env, and drop-ABSENCE is not OFF evidence (MEMORY 오판 가드). recon is
    out-of-graph and does no log tail, so the boot absence of a confirmation source is
    architecturally correct. ``spec.signing_expected`` carries the policy EXPECTATION
    (trust prior) and NEVER promotes the observed enforcement (expected≠observed).
  - NAS     : threat domains seeded "none" (clean posture); NAS-cipher anomaly is observed
    later from the MME log (P4-5).
  - ports   : closed reach vocabulary seeded False (observed True by collectors).
  - ip map  : role->container->IP resolved live (resolve_targets); UE-pool IPs are dynamic
    and NEVER pinned from config (A-1).

PS-6 ordering: recover_on_boot (ledger/seq HWM) runs here BEFORE any sense drain.
"""
from __future__ import annotations

from ..config import loader
from ..targets.behavioral import apply_behavioral_verification
from ..targets.inputspec import DefInputSpec
from ..targets.resolve import ResolveResult, resolve_targets
from .state import MDGState, initial_state
from .worldstate import Baseline, SigningObs, WorldState

# domains seeded to a clean baseline posture (NAS/command/etc. = no anomaly at boot).
_BASELINE_DOMAINS = ["communication", "identity_access", "session_network", "command", "mission"]


def recon_boot(cfg: dict | None = None, seqwm=None, ledger=None, docker=None,
               backend=None, spec: DefInputSpec | None = None) -> MDGState:
    """Build tick-0 MDGState. ``docker`` (duck-typed inspect) + ``backend`` (safe-exec)
    enable live role/IP resolution; both absent => a config-only inert baseline.

    ``spec`` overrides the loaded DefInputSpec (tests). All live resolution is read-only
    and operator-go safe: a non-allow_live Backend returns DRY-RUN, so UE-pool tun IPs
    stay unresolved (verified False) rather than being invented.
    """
    spec = spec or DefInputSpec.load(cfg.get("input_spec") if cfg else None)
    thr = loader.thresholds()
    config_version = spec.config_version or loader.config_version()

    # PS-6: reload seq HWM + recover leaked intents BEFORE sense drain (G3).
    if seqwm is not None:
        seqwm.recover_on_boot()
    if ledger is not None:
        ledger.recover_on_boot()

    state = initial_state(config_version)

    world = WorldState(
        config_version=config_version,
        reach=spec.initial_reach(),                       # closed vocab, all False
        signing=SigningObs.UNKNOWN,                        # observed posture unconfirmed; expectation in spec (P2-Q2)
        threat={d: "none" for d in _BASELINE_DOMAINS},    # clean NAS/posture baseline
        baseline=Baseline(
            rtt_baseline_ms=float(thr.get("rtt_baseline_ms", 27.7)),
            rtt_mdev_ms=float(thr.get("rtt_mdev_ms", 11.0)),
        ),
    )

    # H-I role->container->IP 2-stage resolution (read-only; operator-go for the tun scan).
    result: ResolveResult = resolve_targets(spec, docker=docker, backend=backend)
    world.roles.update(result.bindings)
    world.pid.update(result.pidmap)
    world.ip_map.update(result.ip_map)
    world.imsi_container.update(result.imsi_container)         # static IMSI->container boot map (P4 stale-binding cross-check)
    world.role_verified.update(result.role_verified())        # RESOLVED/PRESENT (legality predicate)

    # Behavioural verify (finding P2-1): consume each role's ``verify_anchor`` into the
    # DISTINCT ``behaviorally_verified`` predicate. At boot there is no live anchor evidence
    # (the taps are operator-go), so this seeds all-False — presence is NOT overstated as a
    # behavioural verify. The runtime feeds live AnchorEvidence at the collector/effect-confirm
    # phase (targets/behavioral.apply_behavioral_verification) as observations arrive.
    world.behaviorally_verified.update(apply_behavioral_verification(spec.roles, evidence=None))

    state["worldstate"] = world
    return state
