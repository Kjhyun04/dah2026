"""그래프 내(in-graph) node 명단(11): sense, correlate, compute_trust, compute_impact,
orient, select_policy, rank_recovery, decide, act, effect_confirm, escalate.
(recon 은 boot 전용, 그래프 밖.)"""
from .act import act
from .compute_impact import compute_impact
from .compute_trust import compute_trust
from .correlate import correlate
from .decide import decide
from .effect_confirm import effect_confirm
from .escalate import escalate
from .orient import orient
from .rank_recovery import rank_recovery
from .select_policy import select_policy
from .sense import sense

NODES = {
    "sense": sense,
    "correlate": correlate,
    "compute_trust": compute_trust,
    "compute_impact": compute_impact,
    "orient": orient,
    "select_policy": select_policy,
    "rank_recovery": rank_recovery,
    "decide": decide,
    "act": act,
    "effect_confirm": effect_confirm,
    "escalate": escalate,
}
assert len(NODES) == 11, "in-graph node roster must be exactly 11 (PA-8)"

__all__ = ["NODES", *NODES.keys()]
