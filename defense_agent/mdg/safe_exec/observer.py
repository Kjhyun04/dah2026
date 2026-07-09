"""observer (Phase 4) — read-only effect-confirm observers for the recovery lifecycle.

``make_effect_observer(...)`` returns an ``observe(rule) -> bool`` closure that
``effect_confirm`` (PA-2) calls to decide whether an applied recovery rule has actually
TAKEN EFFECT in the live testbed. It is the "회복 완료" signal that flips
``worldstate.applied[rule].confirmed`` from False -> True.

Per-mechanism confirmation (rule resolved to its response_tool via RECOVERY_PRIORS):
  - ``docker_pause``   (backdoor_pause) : ``docker inspect .State.Paused`` on the enforce_at
    container is True (the attacker container is frozen).
  - ``nsenter_input_drop`` (backdoor_drop) : inside the enforce_at container's netns the
    RECOVERY ENFORCEMENT is in place. PRIMARY signal = the INPUT-chain DROP rule is installed
    (``iptables -S INPUT`` shows a ``-s <src> -j DROP`` line). SECONDARY = ``ss`` shows NO ESTAB
    on the backdoor port (5762). Rule-existence is primary because an already-ESTABLISHED server
    socket is NOT reset by an ingress DROP — the kernel only discards new packets, so the peer
    ESTAB entry can linger for minutes (keepalive/RTO) after the DROP is effective. Keying the
    "회복 완료" signal on ESTAB-absence alone would leave backdoor_drop UNCONFIRMED for the whole
    preliminary window, so ``already_applied`` (applied∧confirmed) would stay False and the
    NON-idempotent ``iptables -I`` would be re-inserted every debounce window, accumulating
    duplicate rules a single ``-D`` cannot fully revert (가역성/leak-0 저촉). Rule-existence
    confirms as soon as the DROP is actually installed, so re-actuation is suppressed idempotently.
  - ``send_signed_mode`` (signed_*) : downlink telemetry ``rel_alt`` recovered to target
    (30 m ± tol) AND ``mode`` is an explicit non-landing flight mode (present, not LAND) —
    flight re-established. A MISSING mode is NOT treated as recovered (altitude alone is too
    sparse a signal — the vehicle transits 30 m while descending, so a bare altitude match
    could false-confirm; a positive mode reading is required).

불변식2. (누수-0): EVERY probe here is READ-ONLY. The docker probe is a metadata
``inspect`` (read_only=True fast-path); the ss probe is an allowlisted observer wrapped in
the target's netns; telemetry is a passive collector snapshot. NOTHING spawns except through
the single injected ``Backend`` (``backend.run`` = the sole ``_spawn`` site). No new subprocess
path is introduced. 불변식1. (결정론): the observer reads live state only; routing never depends
on it (effect_confirm -> END regardless), so determinism is untouched.

Fail-safe: any unresolved target / missing dep / DRY / error yields ``False`` (UNCONFIRMED),
never a spurious confirm — the next tick re-observes (PA-2). A False-confirm would be the
dangerous direction (falsely declaring recovery done), so the closure is conservative.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..config.defaults import RECOVERY_PRIORS
from .backend import Backend, ExecRequest

# The 5762 backdoor control port (uav_ue netns). ESTAB on this port == attacker still connected.
_BACKDOOR_PORT = 5762
# signed_* flight recovery target: relative altitude (m) and tolerance band.
_TARGET_ALT_M = 30.0
_ALT_TOL_M = 5.0


def _tool_for(rule: str, priors: dict) -> Optional[str]:
    """rule -> response_tool via priors (docker_pause / nsenter_input_drop / send_signed_mode)."""
    row = priors.get(rule) or {}
    return row.get("response_tool")  # type: ignore[return-value]


def _container_for(rule: str, priors: dict) -> Optional[str]:
    """rule -> enforce_at container key (== netns_prefix_map / docker-inspect key for these rules)."""
    row = priors.get(rule) or {}
    ea = row.get("enforce_at")
    return str(ea) if ea else None


def _estab_on_port(ss_stdout: str, port: int) -> bool:
    """True iff ``ss`` output has an ESTAB row referencing ``:port`` (attacker still connected).

    LISTEN rows are IGNORED: a server socket bound to :5762 legitimately survives the DROP —
    only an ESTABlished attacker connection is the thing the DROP removes."""
    needle = f":{port}"
    for line in (ss_stdout or "").splitlines():
        toks = line.split()
        if toks and toks[0].upper() == "ESTAB" and needle in line:
            return True
    return False


def _observe_pause(rule: str, docker: Any, priors: dict) -> bool:
    """backdoor_pause: enforce_at container's ``.State.Paused`` is True."""
    container = _container_for(rule, priors)
    if not container or docker is None:
        return False
    inspect_paused = getattr(docker, "inspect_paused", None)
    if inspect_paused is None:
        return False
    try:
        return inspect_paused(container) is True
    except Exception:
        return False


def _input_source_drop_installed(ipt_s_stdout: str) -> bool:
    """True iff ``iptables -S INPUT`` output has an INPUT ``-s <src> -j DROP`` rule — i.e. the
    recovery DROP is actually installed in the target netns. This is the PRIMARY, promptly-true
    backdoor_drop confirmation (rule-existence), independent of the lagging ESTAB teardown."""
    for line in (ipt_s_stdout or "").splitlines():
        toks = line.split()
        if not toks or toks[0] not in ("-A", "-I"):
            continue
        # an INPUT append/insert that filters a SOURCE with target DROP == our containment rule
        if "INPUT" in toks and "-s" in toks and "DROP" in toks:
            return True
    return False


def _observe_drop(rule: str, netns_prefix_map: dict, backend: Optional[Backend],
                  priors: dict, port: int) -> bool:
    """backdoor_drop confirmed when the recovery ENFORCEMENT is in place inside the enforce_at
    container's netns. PRIMARY: the INPUT DROP rule is installed (``iptables -S INPUT``) — this
    is what flips ``already_applied`` True and stops the non-idempotent ``-I`` re-insertion. Only
    if the rule is not (yet) observable do we fall back to the SECONDARY ESTAB-absence signal
    (which can lag minutes past the DROP being effective, so it is never the sole signal)."""
    container = _container_for(rule, priors)
    if not container or backend is None:
        return False
    prefix = (netns_prefix_map or {}).get(container)
    if not prefix:                                  # unresolved netns -> inert (never a false confirm)
        return False
    # PRIMARY — the DROP rule is installed. ``iptables -S`` is read-only in effect (lists rules,
    # mutates nothing); it is NOT on the read_only fast-path allowlist so it stays operator-go DRY
    # under allow_live=False (the DROP itself is likewise DRY then, so nothing to confirm — safe).
    try:
        rules = backend.run(ExecRequest(argv=[*prefix, "iptables", "-w", "-S", "INPUT"],
                                        timeout_s=6.0))
    except Exception:
        rules = None
    if (rules is not None and not getattr(rules, "dry_run", False)
            and getattr(rules, "ok", False)
            and _input_source_drop_installed(rules.stdout or "")):
        return True
    # SECONDARY — attacker ESTAB on the backdoor port is gone (belt-and-suspenders; lags the DROP).
    try:
        res = backend.run(ExecRequest(argv=[*prefix, "ss", "-tan"], timeout_s=6.0, read_only=True))
    except Exception:
        return False
    if res is None or getattr(res, "dry_run", False) or not getattr(res, "ok", False):
        return False                                # DRY / failure -> unconfirmed
    return not _estab_on_port(res.stdout or "", port)


def _observe_signed(telemetry: Optional[Callable[[], Optional[dict]]],
                    target_alt_m: float, alt_tol_m: float) -> bool:
    """signed_*: rel_alt recovered to target±tol AND mode != LAND (flight re-established)."""
    if telemetry is None:
        return False
    try:
        snap = telemetry()
    except Exception:
        return False
    if not snap:
        return False
    alt = snap.get("rel_alt")
    if alt is None:
        return False
    mode = snap.get("mode", snap.get("flight_mode"))
    # A POSITIVE mode reading is required: altitude alone is too sparse (the vehicle transits the
    # 30 m band while descending), so a MISSING mode is NOT recovered, and LAND is not recovered.
    if mode is None or str(mode).strip() == "" or str(mode).upper() == "LAND":
        return False
    try:
        return abs(float(alt) - target_alt_m) <= alt_tol_m
    except (TypeError, ValueError):
        return False


def make_effect_observer(docker: Any = None, netns_prefix_map: Optional[dict] = None,
                         backend: Optional[Backend] = None,
                         telemetry: Optional[Callable[[], Optional[dict]]] = None,
                         priors: Optional[dict] = None,
                         *, backdoor_port: int = _BACKDOOR_PORT,
                         target_alt_m: float = _TARGET_ALT_M,
                         alt_tol_m: float = _ALT_TOL_M) -> Callable[[str], bool]:
    """Build the ``observe(rule) -> bool`` closure injected into ``effect_confirm`` (deps["observe"]).

    ``docker``           : duck-typed backend exposing ``inspect_paused(container) -> bool|None``
                           (the safe-exec docker backend; read-only ``inspect``).
    ``netns_prefix_map`` : container -> nsenter prefix (for the ss probe inside the target netns).
    ``backend``          : the single safe-exec ``Backend`` (sole spawn site; ss goes through it).
    ``telemetry``        : optional ``() -> {"rel_alt": float, "mode"/"flight_mode": str}|None``
                           snapshot for signed_* flight recovery. live_autorun wires the
                           AirTelemetryTap.snapshot (14560/14550 decode) here; None -> the signed
                           path stays UNCONFIRMED, safe.
    ``priors``           : rule -> {response_tool, enforce_at, ...} (defaults to RECOVERY_PRIORS).

    The returned closure is deterministic given the live world (불변식1.) and probes read-only only
    (불변식2.). Unknown rule / missing dep / any error -> False (never a spurious confirm)."""
    priors = priors if priors is not None else RECOVERY_PRIORS

    def observe(rule: str) -> bool:
        tool = _tool_for(rule, priors)
        if tool == "docker_pause":
            return _observe_pause(rule, docker, priors)
        if tool == "nsenter_input_drop":
            return _observe_drop(rule, netns_prefix_map or {}, backend, priors, backdoor_port)
        if tool == "send_signed_mode":
            return _observe_signed(telemetry, target_alt_m, alt_tol_m)
        return False                                 # unknown/unmapped rule -> unconfirmed

    return observe
