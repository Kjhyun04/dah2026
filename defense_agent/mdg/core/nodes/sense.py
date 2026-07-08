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
from ..worldstate import WorldState


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
