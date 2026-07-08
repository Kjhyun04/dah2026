"""rank_recovery (PA-4/PS-7) — DETERMINISTIC action selection.

Sorts legal actions by recovery prior score, binds the top to chosen_action, and
promotes bundle-level chosen_action_risk = max(atomic risk), chosen_action_reversible
= all(op.reversible) as State fields the decide-edge reads. No candidate ->
chosen_action = None. Debounce (dry_streak) + provenance gate keep injected
high-severity from triggering auto-response (PS-7).
"""
from __future__ import annotations

from ...config import loader
from ..scoring import recovery_score
from ..state import Action, Intent, MDGState

_RISK_ORDER = {"LOW": 0, "MED": 1, "HIGH": 2}


def _bundle_risk(actions: list[Action]) -> str:
    if not actions:
        return "LOW"
    return max(actions, key=lambda a: _RISK_ORDER[a.risk]).risk       # max risk


def _bundle_reversible(actions: list[Action]) -> bool:
    return all(a.reversible for a in actions)                          # all reversible


def rank_recovery(state: MDGState) -> dict:
    legal: list[Action] = state.get("legal_actions", [])
    if not legal:
        return {"chosen_action": None, "chosen_action_risk": "LOW",
                "chosen_action_reversible": True}

    rp = loader.recovery_priors()
    priors = rp.get("recovery_priors", {})
    # feasibility gate compares success_probability, NOT recovery_score (M6/E-2). Accept the
    # legacy key as fallback for resilience during config rollover.
    feasible_min = float(rp.get("success_prob_feasible_min", rp.get("feasible_min", 0.70)))

    def _succ(a: Action) -> float:
        return float(priors.get(a.recovery_type, {}).get("success_probability", 0.5))

    def score(a: Action) -> float:
        # composite RANKING score (prototype §5). trust_rec = restored trust points.
        p = priors.get(a.recovery_type, {})
        rec = p.get("expected_trust_recovery", {})
        trust_rec = sum(float(v) for v in rec.values())
        risk_w = {"LOW": 0.1, "MED": 0.3, "HIGH": 0.6}[a.risk]
        return recovery_score(_succ(a), trust_rec, mission_rec=trust_rec, risk=risk_w, cost=0.0)

    # Feasibility gate = success_probability >= feasible_min (FEASIBILITY §3 priors).
    # Ranking among feasible = composite recovery_score. (M6/E-2 reconciliation — see
    # DESIGN note: the doc's "recovery_score>=0.7" and the 20-40pt trust-delta priors
    # do not reconcile; success_probability is the calibrated feasibility signal.)
    feasible = [a for a in legal if _succ(a) >= feasible_min]
    if not feasible:
        return {"chosen_action": None, "chosen_action_risk": "LOW",
                "chosen_action_reversible": True}
    # PP-1 binding contract (panel-1 step d + risk-note 3): sort on an EXPLICIT deterministic
    # key tuple, NOT on a single score with sort-stability. recovery_score compresses to
    # ~0.14-0.38 so ties are common; relying on input order would break replay reproducibility
    # (불변식①). Order = recovery_score desc, then lower risk, then reversible-first, then
    # recovery_type name — total order independent of legal_actions permutation.
    def _sort_key(a: Action) -> tuple:
        return (-score(a), _RISK_ORDER[a.risk], 0 if a.reversible else 1, a.recovery_type)

    ranked = sorted(feasible, key=_sort_key)
    top = ranked[0]

    # atomic bundle = recovery + attack-path block (X4/X6). Here single-op bundle.
    bundle = [top]
    # P4-Q1 — carry the OPAQUE VALIDATED SELECTOR from the ranked candidate's params into the
    # chosen Intent. This is the load-bearing wiring that was missing: rank_recovery previously
    # dropped top.params, so chosen_action lost the target and dispatch had to GUESS. We copy the
    # selector as data ONLY — NO live resolution here (this node holds no backend/netns; 불변식②).
    # (pid, src_ip) binding happens at dispatch as a pure lookup into the verified WorldState map.
    intent = Intent(
        rule=top.recovery_type, tool_id=top.tool_id,
        revert_cmd=f"revert:{top.recovery_type}",
        config_version=state.get("config_version", ""),
        target=str(top.params.get("target", "")),
        target_kind=str(top.params.get("target_kind", "")),
        # P4-2 — carry the ENFORCEMENT chokepoint selector alongside the source selector so dispatch
        # can resolve two DISTINCT verified endpoints. Data ONLY (no live resolution here; 불변식②).
        enforce_at=str(top.params.get("enforce_at", "")),
    )
    return {
        "chosen_action": intent,
        "chosen_action_risk": _bundle_risk(bundle),
        "chosen_action_reversible": _bundle_reversible(bundle),
    }
