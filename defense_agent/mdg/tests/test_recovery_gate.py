"""test_recovery_gate — P0 panel-1 (M6/E-2): feasibility gate vs recovery_score split.

Pins the decision so a future refactor cannot silently re-brick the agent by pointing
the feasibility gate back at recovery_score (which caps at ~0.14-0.38, making every
response permanently infeasible). Runnable as ``python tests/test_recovery_gate.py``.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import defaults as D  # noqa: E402
from mdg.config import loader  # noqa: E402
from mdg.core import scoring as s  # noqa: E402
from mdg.core.nodes.rank_recovery import rank_recovery  # noqa: E402
from mdg.core.state import Action  # noqa: E402

_RISK_W = {"LOW": 0.1, "MED": 0.3, "HIGH": 0.6}


def _score(prior: dict) -> float:
    trust_rec = sum(float(v) for v in prior.get("expected_trust_recovery", {}).values())
    return s.recovery_score(float(prior["success_probability"]), trust_rec,
                            mission_rec=trust_rec, risk=_RISK_W[prior["risk"]], cost=0.0)


def _feasible_min() -> float:
    rp = loader.recovery_priors()
    return float(rp.get("success_prob_feasible_min", rp.get("feasible_min", 0.70)))


# --- the split itself: gate on success_probability, NOT recovery_score ---------
def test_every_prior_admitted_by_success_prob_gate():
    fmin = _feasible_min()
    for name, prior in D.RECOVERY_PRIORS.items():
        assert float(prior["success_probability"]) >= fmin, f"{name} blocked by gate"


def test_recovery_score_cannot_be_the_gate():
    # every recovery_score sits FAR below the 0.70 floor -> gating on it = infeasible-forever
    scores = {n: _score(p) for n, p in D.RECOVERY_PRIORS.items()}
    assert max(scores.values()) < _feasible_min(), scores       # pins the contradiction


def test_recovery_score_is_bounded():
    for p in D.RECOVERY_PRIORS.values():
        assert 0.0 <= _score(p) <= 1.0


# --- config key renamed so gate cannot be re-pointed at recovery_score ---------
def test_feasible_min_key_is_success_prob_scoped():
    rp = loader.recovery_priors()
    assert "success_prob_feasible_min" in rp, "renamed gate key missing"


# --- node behavior: gate reads success_probability -----------------------------
def test_unknown_type_filtered_by_gate():
    # unknown recovery_type -> success_probability defaults 0.5 < 0.70 -> filtered out
    st = {"legal_actions": [Action(tool_id="x", recovery_type="unknown_type",
                                   risk="MED", reversible=True)],
          "config_version": "test"}
    out = rank_recovery(st)
    assert out["chosen_action"] is None


def test_feasible_type_selected():
    st = {"legal_actions": [Action(tool_id="docker_pause", recovery_type="backdoor_pause",
                                   risk="MED", reversible=True)],
          "config_version": "test"}
    out = rank_recovery(st)
    assert out["chosen_action"] is not None
    assert out["chosen_action_risk"] == "MED"
    assert out["chosen_action_reversible"] is True


def _run_all() -> int:
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"[FAIL] {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"[ERROR] {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
