"""effect_confirm (PA-2) — in-graph deterministic post-act delta (NOT the Verifier).

Records the observation delta (ss/pcap/:9090 s5c_rx_deletesession diff / 14560 HB /
uav_ue lo:14550 cross-tap, D-1) and sets worldstate.applied[rule].confirmed. Does
NOT gate execution (already executed for reversible AUTO, D-3). effect_confirm -> END;
the next tick's sense re-observes. This is the in-graph effect-confirm; the out-graph
Verifier (replay JSONL only) is a separate process and is NEVER imported here.
"""
from __future__ import annotations

from ..state import MDGState
from ..worldstate import WorldState


def effect_confirm(state: MDGState, observe=None) -> dict:
    """observe(rule)->bool injected (reads ss/metric delta). Default: unconfirmed
    (next tick re-observes). Returns only applied[rule].confirmed + delta note."""
    world: WorldState = state.get("worldstate") or WorldState()
    if not world.applied:
        return {}

    updated = world.model_copy(deep=True)
    for rule, applied in updated.applied.items():
        if applied.confirmed:
            continue
        confirmed = bool(observe(rule)) if observe is not None else False
        applied.confirmed = confirmed
    return {"worldstate": updated}
