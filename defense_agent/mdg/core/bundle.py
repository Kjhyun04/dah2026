"""bundle.py — atomic response bundle · idempotent applied()-skip · N-tick debounce ·
de-escalation (DETERMINISTIC, secret-free — 불변식①).

An enforced response is an ATOMIC BUNDLE (recovery op + optional attack-path block, X4/X6):
the bundle-level risk = max(atomic risk) and reversible = all(atomic reversible) — the exact
aggregation ``rank_recovery`` promotes into the routing fields (PA-4). This module adds the
three actuation-discipline predicates the act node and the driver's de-escalation sweep read
from WorldState + the tick counter ONLY (no clock in-graph, no LLM, no subprocess):

  1. idempotent skip   — a rule already applied AND effect-confirmed (and not reverted) is a
                         no-op; re-applying it would be a redundant side effect. ``act`` skips.
  2. N-tick debounce   — a physical rule re-selected within ``min_ticks`` of its last apply is
                         held (X5), preventing flap. Uses ``AppliedRule.applied_tick``.
  3. de-escalation     — a rule applied+confirmed and quiet for ``quiet_s`` becomes a revert
                         candidate (X5/E15). The driver reverts it out-of-band (operator-go for
                         live). ``FLIGHT_ACTION_AUTO_REVERT`` stays False (never auto-revert flight).

All functions are pure: same (world, tick) -> same verdict, so replay is byte-stable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import defaults as D
from .state import Action, Intent
from .worldstate import AppliedRule, WorldState

_RISK_ORDER = {"LOW": 0, "MED": 1, "HIGH": 2}


@dataclass
class Bundle:
    """An atomic response bundle. risk = max(op risk), reversible = all(op reversible)."""
    rule: str
    ops: list[Action] = field(default_factory=list)
    revert_cmd: str = ""

    @property
    def risk(self) -> str:
        if not self.ops:
            return "LOW"
        return max(self.ops, key=lambda a: _RISK_ORDER.get(a.risk, 0)).risk

    @property
    def reversible(self) -> bool:
        return all(a.reversible for a in self.ops)


def build_bundle(intent: Intent, extra_ops: list[Action] | None = None) -> Bundle:
    """Assemble the atomic bundle for a chosen Intent (single recovery op + optional
    attack-path-block ops). risk/reversible are aggregated by the ``Bundle`` properties
    (max/all) — the same conservative aggregation the routing fields carry (PA-4)."""
    primary = Action(
        tool_id=intent.tool_id,
        params={"recovery_type": intent.rule},
        risk="MED", reversible=True, recovery_type=intent.rule,
    )
    ops = [primary] + list(extra_ops or [])
    revert = intent.revert_cmd or f"revert:{intent.rule}"
    return Bundle(rule=intent.rule, ops=ops, revert_cmd=revert)


def _live_applied(world: WorldState, rule: str) -> AppliedRule | None:
    """Return the AppliedRule for ``rule`` if it is currently in force (not reverted)."""
    ap = (world.applied or {}).get(rule)
    if ap is None or getattr(ap, "reverted", False):
        return None
    return ap


def already_applied(world: WorldState, rule: str) -> bool:
    """Idempotent skip predicate: the rule is already applied AND effect-confirmed (PA-2),
    so re-applying is a redundant side effect. An applied-but-unconfirmed rule is NOT skipped
    (effect_confirm has not proven the delta yet; the next apply may still be needed)."""
    ap = _live_applied(world, rule)
    return ap is not None and bool(ap.confirmed)


def debounce_blocked(world: WorldState, rule: str, now_tick: int,
                     min_ticks: int | None = None) -> bool:
    """N-tick debounce (X5): True iff the rule was applied fewer than ``min_ticks`` ticks ago.

    Reads ``AppliedRule.applied_tick`` (State-carried -> replay-safe). A rule never applied
    (absent) is not blocked. min_ticks defaults to DEBOUNCE_PHYSICAL_MIN_TICKS.
    """
    m = D.DEBOUNCE_PHYSICAL_MIN_TICKS if min_ticks is None else int(min_ticks)
    ap = _live_applied(world, rule)
    if ap is None:
        return False
    delta = int(now_tick) - int(ap.applied_tick)
    return 0 <= delta < m


def deescalation_due(world: WorldState, now_ts: float,
                     quiet_s: int | None = None) -> list[AppliedRule]:
    """Return applied+confirmed rules quiet for >= quiet_s (revert candidates, X5/E15).

    Flight actions are excluded unless FLIGHT_ACTION_AUTO_REVERT (default False): a flight-mode
    revert is never automatic. The driver performs the revert out-of-band (operator-go for live).
    """
    q = D.DEESCALATION_REVERT_QUIET_S if quiet_s is None else int(quiet_s)
    out: list[AppliedRule] = []
    for rule, ap in (world.applied or {}).items():
        if getattr(ap, "reverted", False) or not ap.confirmed:
            continue
        is_flight = rule.startswith("signed_") or rule == "command_override"
        if is_flight and not D.FLIGHT_ACTION_AUTO_REVERT:
            continue
        if ap.ts and (now_ts - ap.ts) >= q:
            out.append(ap)
    return out


def min_debounce_ticks() -> int:
    return int(D.DEBOUNCE_PHYSICAL_MIN_TICKS)
