"""rank_recovery (PA-4/PS-7) — DETERMINISTIC action selection.

Sorts legal actions by recovery prior score, binds the top to chosen_action, and
promotes bundle-level chosen_action_risk = max(atomic risk), chosen_action_reversible
= all(op.reversible) as State fields the decide-edge reads. No candidate ->
chosen_action = None. Debounce (dry_streak) + provenance gate keep injected
high-severity from triggering auto-response (PS-7).

Phase 2 (B3, sandbox demo) — provenance/debounce RELAXATION: under operator_auto the strict
"require a trusted source" hold is relaxed to RECORD-THEN-PASS. rank_recovery stamps the chosen
Intent with provenance_relaxed=True so the ledger/trace records the waiver transparently, and the
physical-action debounce is shrunk to config demo_mode.debounce_ticks downstream (response.py) so
an injected high-severity recovery re-binds within the next tick. PRODUCTION (operator_auto off)
is UNCHANGED: provenance_relaxed stays False and the full debounce hold applies (strict PS-7).
"""
from __future__ import annotations

from ...config import loader
from ...safe_exec.signer_shim import command_digest
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

    # 1. OPERATOR-SELECT (env->STATE, DETERMINISTIC, 불변식1.): when the operator explicitly picks a
    # candidate (MDG_OPERATOR_PICK -> state['operator_pick'], seeded by live_autorun like
    # operator_auto), promote the MATCHING legal Action to chosen_action, bypassing the autonomous
    # ranking that permanently demotes the reversible-blockade tools below send_signed_mode. Match is
    # by recovery_type OR tool_id (accepts either spelling). A blank/non-matching pick is IGNORED
    # (the autonomous ranking stands — fail-safe). No LLM: a pure string equality over the closed
    # legal set. The promotion is honored even if the pick is below the feasibility floor: it is a
    # HUMAN authorization, so it must not be re-gated by the autonomous feasibility heuristic.
    pick = str(state.get("operator_pick") or "").strip()
    operator_selected = None
    if pick:
        for a in legal:
            if a.recovery_type == pick or a.tool_id == pick:
                operator_selected = a
                break

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
    # PP-1 binding contract (panel-1 step d + risk-note 3): sort on an EXPLICIT deterministic
    # key tuple, NOT on a single score with sort-stability. recovery_score compresses to
    # ~0.14-0.38 so ties are common; relying on input order would break replay reproducibility
    # (불변식1.). Order = recovery_score desc, then lower risk, then reversible-first, then
    # recovery_type name — total order independent of legal_actions permutation.
    def _sort_key(a: Action) -> tuple:
        return (-score(a), _RISK_ORDER[a.risk], 0 if a.reversible else 1, a.recovery_type)

    if operator_selected is not None:
        # operator-select overrides the autonomous ranking AND the feasibility gate (human authority).
        top = operator_selected
    else:
        feasible = [a for a in legal if _succ(a) >= feasible_min]
        if not feasible:
            return {"chosen_action": None, "chosen_action_risk": "LOW",
                    "chosen_action_reversible": True}
        ranked = sorted(feasible, key=_sort_key)
        top = ranked[0]

    # Phase 2 (B3/PS-7) provenance/debounce relaxation — DETERMINISTIC (env bool + config, no LLM,
    # 불변식1.). Under operator_auto (sandbox demo) the strict trusted-source hold on an injected
    # high-severity recovery is RECORDED-THEN-PASSED: stamp provenance_relaxed=True on the chosen
    # Intent so the ledger/trace shows the waiver (response.py separately shrinks the debounce to
    # demo_mode.debounce_ticks). Production (operator_auto off) -> False, strict posture retained.
    operator_auto = bool(state.get("operator_auto"))
    provenance_relaxed = operator_auto and bool(loader.demo_mode().get("provenance_relaxed", False))

    # atomic bundle = recovery + attack-path block (X4/X6). Here single-op bundle.
    bundle = [top]
    # P4-Q1 — carry the OPAQUE VALIDATED SELECTOR from the ranked candidate's params into the
    # chosen Intent. This is the load-bearing wiring that was missing: rank_recovery previously
    # dropped top.params, so chosen_action lost the target and dispatch had to GUESS. We copy the
    # selector as data ONLY — NO live resolution here (this node holds no backend/netns; 불변식2.).
    # (pid, src_ip) binding happens at dispatch as a pure lookup into the verified WorldState map.
    intent = Intent(
        rule=top.recovery_type, tool_id=top.tool_id,
        revert_cmd=f"revert:{top.recovery_type}",
        config_version=state.get("config_version", ""),
        target=str(top.params.get("target", "")),
        target_kind=str(top.params.get("target_kind", "")),
        # P4-2 — carry the ENFORCEMENT chokepoint selector alongside the source selector so dispatch
        # can resolve two DISTINCT verified endpoints. Data ONLY (no live resolution here; 불변식2.).
        enforce_at=str(top.params.get("enforce_at", "")),
        # Phase 2 (B3) — record-then-pass waiver marker (demo only; False in production).
        provenance_relaxed=provenance_relaxed,
        # 1. operator-select provenance: mark WHO chose this action so the ledger/trace shows the
        # human authorization (vs the autonomous ranking). "" for the autonomous path (회귀 0).
        authority="operator-select" if operator_selected is not None else "",
    )
    if operator_selected is not None:
        # COMMAND-BIND the operator-selected Intent (PS-9): stamp the KEY-FREE command_digest so the
        # binding travels ON chosen_action into the OperatorGate authorization (escalate.issue on the
        # operator_auto-off route) and into act's enforced Intent under operator_auto (model_copy
        # preserves it) — a captured approval minted for a different command cannot authorize this
        # one. command_digest is a pure sha256 over identifying fields; NO signing key is opened
        # (verify_signer_no_keyopen — the uplink signature stays with gcs_c2).
        intent = intent.model_copy(update={"command_digest": command_digest(intent)})
    return {
        "chosen_action": intent,
        "chosen_action_risk": _bundle_risk(bundle),
        "chosen_action_reversible": _bundle_reversible(bundle),
    }
