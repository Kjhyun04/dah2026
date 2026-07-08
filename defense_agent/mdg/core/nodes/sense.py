"""sense (PA-1/PA-7/PS-2) — SYNCHRONOUS entry node. Drains the Collector queue
non-blocking, verifies HMAC/seq at drain, merges WorldState, increments tick_i.

Empty queue -> fail-open (G4). Forged envelope -> fail-closed discard + tamper
Incident (not merged into trust/impact/auto-quarantine). No async, no time.* here.

Liveness (P3-Q5): drained ``sensor_loss`` evidence (Watchdog metric, PS-2-verified) maps
its ``value`` (a dead collector source_id) to a domain via the injected ``source_domains``
map and records it in ``worldstate.dead_domains`` — the present-set exclusion source for
compute_trust. The mapping is ASYMMETRIC (SigningObs precedent, PS-7): a domain is only
CLEARED from dead when a live (non-sensor_loss) verified evidence for that domain arrives
this tick (proof the collector emitted); silence never clears it. ``source_domains=None``
(default / test scaffold) -> no liveness bookkeeping, behavior unchanged.
"""
from __future__ import annotations

from ..state import Incident, MDGState, SensorEv
from ..worldstate import SigningObs, WorldState

# The uav_proxy §9-B signing drop-line evidence (SignLogCollector). Its OBSERVATION is the
# ONLY authoritative promoter of world.signing here (P2-Q2/P3-Q2). Matched on BOTH the metric
# and the collector channel so an unrelated 'Signing_Drop'-named signal cannot spoof the latch.
_SIGNING_METRIC = "Signing_Drop"
_SIGNING_CHANNEL = "uav_proxy_signlog"


def _drain(inbox) -> list:
    """Non-blocking drain of a queue.Queue-like object (get_nowait until Empty)."""
    out = []
    if inbox is None:
        return out
    try:
        import queue as _q
        empty_exc = _q.Empty
    except Exception:                       # pragma: no cover
        empty_exc = Exception
    while True:
        try:
            out.append(inbox.get_nowait())
        except empty_exc:
            break
        except Exception:
            break
    return out


def sense(state: MDGState, inbox=None, verify=None, clock=None,
          source_domains=None) -> dict:
    """inbox: queue of (SensorEnvelope). verify(env)->(ok,reason,SensorEv). Injected
    by graph build; defaults make the node callable with just state (fail-open).
    source_domains: {source_id -> domain} (from the collector roster) used to attribute
    a watchdog ``sensor_loss`` to a domain. None -> liveness bookkeeping disabled."""
    tick_i = int(state.get("tick_i", 0)) + 1

    envelopes = _drain(inbox)
    evidence: list[SensorEv] = []
    tamper: list[Incident] = []
    ts = clock.now() if clock is not None else 0.0

    for env in envelopes:
        if verify is not None:
            ok, reason, ev = verify(env)
        else:
            ok, reason, ev = True, "no-verify", env  # scaffold path
        if ok and isinstance(ev, SensorEv) and not ev.tamper:
            evidence.append(ev)
        else:
            tamper.append(Incident(
                id=f"tamper-{tick_i}-{len(tamper)}", kind="tamper",
                score=0.0, ts=ts, members=[getattr(env, "source_id", "?")],
            ))

    # merge worldstate (single authoritative object replace)
    world: WorldState = state.get("worldstate") or WorldState(
        config_version=state.get("config_version", ""))

    # signing posture MONOTONIC LATCH (P2-Q2/P3-Q2): a verified uav_proxy signing drop-line
    # observation (SignLogCollector) is the ONLY promoter — UNKNOWN -> CONFIRMED_ON, once and
    # never back. Observation is REQUIRED (fail-safe asymmetry): no drop-line this tick leaves
    # signing untouched, silence never promotes, and a banner alone never promotes (only the
    # drop evidence does). Already-CONFIRMED postures are left intact (idempotent latch). Only
    # PS-2-verified evidence reaches this list, so a forged latch is structurally excluded.
    if world.signing is SigningObs.UNKNOWN:
        for ev in evidence:
            if (getattr(ev, "metric", "") == _SIGNING_METRIC
                    and getattr(ev, "channel", "") == _SIGNING_CHANNEL):
                world.signing = SigningObs.CONFIRMED_ON
                break

    # liveness present-set bookkeeping (P3-Q5): map watchdog sensor_loss -> dead domain,
    # clear a domain only on a live emission for it (asymmetric; silence never clears).
    if source_domains is not None:
        dead = set(world.dead_domains)
        for ev in evidence:
            metric = getattr(ev, "metric", "")
            if metric == "sensor_loss":
                dom = source_domains.get(str(getattr(ev, "value", "")))
                if dom is not None:
                    dead.add(dom)                     # add-only on loss
            else:
                dom = getattr(ev, "domain", None)
                if dom is not None:
                    dead.discard(dom)                 # live emission = recovered
        world.dead_domains = sorted(dead)

    out: dict = {"tick_i": tick_i, "evidence": evidence, "worldstate": world}
    if tamper:
        out["incidents"] = tamper                 # operator.add accumulator
    return out
