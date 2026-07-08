"""test_impact_floor — P0 panel-3: overall_impact = max(weighted_mean, criticality_floor).

Pins the security contract that a single safety-critical domain's full compromise is NOT
diluted to Green by a compensatory weighted mean; that absent/stale domains are excluded
(not defaulted to trust=100); and that the aggregate is monotone in each distrust.
Runnable as ``python tests/test_impact_floor.py``.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import defaults as D  # noqa: E402
from mdg.core import scoring as s  # noqa: E402
from mdg.core.nodes.compute_impact import compute_impact  # noqa: E402
from mdg.core.state import ImpactObj, TrustObj  # noqa: E402

_W = dict(D.MISSION_PROFILE["mission_weight"])            # live Recon weights
_FLOOR = dict(D.MISSION_PROFILE["criticality_floor"])


# --- the load-bearing counterexample: command hijack must NOT read Green -------
def test_command_full_compromise_is_red_not_green():
    distrust = {"command": 100.0, "communication": 0.0, "identity_access": 0.0,
                "session_network": 0.0, "mission": 0.0}
    overall, _ = s.overall_impact(distrust, _W, _FLOOR)
    # plain weighted mean would be 20 (=Green); the floor pins it to 71 (=Red)
    assert overall == 71
    assert s.impact_band(overall) == "Red"


def test_weighted_mean_alone_would_be_green():
    # documents the flaw the floor closes: bare mean of the same input = 20 = Green
    distrust = {"command": 100.0, "communication": 0.0, "identity_access": 0.0,
                "session_network": 0.0, "mission": 0.0}
    num = sum(_W[d] * distrust[d] for d in distrust)
    total_w = sum(_W[d] for d in distrust)
    assert round(num / total_w) == 20
    assert s.impact_band(20) == "Green"


# --- criticality floor fires even at mission_weight == 0 ------------------------
def test_floor_fires_at_zero_weight():
    weights = dict(_W)
    weights["command"] = 0                                 # config tampering: zero the weight
    distrust = {"command": 100.0, "communication": 0.0, "identity_access": 0.0,
                "session_network": 0.0, "mission": 0.0}
    overall, _ = s.overall_impact(distrust, weights, _FLOOR)
    assert overall == 71                                   # floor independent of weight


def test_crit_floor_stepwise():
    assert s.crit_floor("command", 100.0, _FLOOR) == 71.0
    assert s.crit_floor("command", 50.0, _FLOOR) == 45.0
    assert s.crit_floor("command", 10.0, _FLOOR) == 0.0
    assert s.crit_floor("communication", 100.0, _FLOOR) == 0.0   # no floor domain


# --- P3-Q4: 71/45 are band-cut-derived LOCK constants, not free seeds -----------
def test_floors_are_band_cut_derived():
    # regression label for the P3-Q4 re-founding: the upper floor is the Red band's lower
    # cut (71) and the lower floor lives inside Yellow[31,70] (45). If IMPACT_BANDS moves,
    # this fails loudly so the floors are re-derived, never left as stale invented seeds.
    from mdg.config import defaults as _D
    red_lo, _red_hi = _D.IMPACT_BANDS["Red"]
    y_lo, y_hi = _D.IMPACT_BANDS["Yellow"]
    for dom in ("command", "session_network"):
        assert s.crit_floor(dom, 71.0, _FLOOR) == float(red_lo)     # upper floor == Red low
        assert y_lo <= s.crit_floor(dom, 40.0, _FLOOR) <= y_hi      # lower floor within Yellow
    assert s.crit_floor("identity_access", 71.0, _FLOOR) == 45.0    # integrity/recon -> Yellow
    # command distrust at the Red-low cut pins overall to Red-low (band-cut identity)
    distrust = {"command": float(red_lo), "communication": 0.0, "identity_access": 0.0,
                "session_network": 0.0, "mission": 0.0}
    overall, _ = s.overall_impact(distrust, _W, _FLOOR)
    assert overall == red_lo
    assert s.impact_band(overall) == "Red"


def test_partial_command_distrust_stays_yellow_floor_not_auto_red():
    # P3-Q4/PS-7: distrust in [40,71) (suspicion / signing=UNKNOWN, NOT a confirmed
    # unauthenticated actuation) stays at the mid-Yellow floor 45 and never auto-escalates
    # to Red. Only a real actuation observation maps command distrust >=71 (see
    # compute_trust distrust-input contract). Guards against an injected doubt self-DoS.
    assert s.crit_floor("command", 70.0, _FLOOR) == 45.0
    assert s.impact_band(int(s.crit_floor("command", 70.0, _FLOOR))) == "Yellow"
    assert s.crit_floor("command", 39.0, _FLOOR) == 0.0            # below trigger -> no floor


# --- present-set normalization: absent domains excluded, denom = Σ present w ----
def test_present_set_renormalization():
    # only 2 non-floor domains present -> mean normalized by their weights (50), not 100
    distrust = {"communication": 60.0, "mission": 0.0}     # weights 30 + 20 = 50
    overall, _ = s.overall_impact(distrust, _W, _FLOOR)
    assert overall == 36                                   # 30*60/50 = 36 (not 18 = /100)


# --- monotonicity: raising any distrust never lowers overall (PS-7/불변식①) ------
def test_monotone_non_decreasing():
    base = {"command": 30.0, "communication": 20.0, "identity_access": 10.0,
            "session_network": 15.0, "mission": 5.0}
    lo, _ = s.overall_impact(base, _W, _FLOOR)
    for d in base:
        raised = dict(base)
        raised[d] = min(100.0, base[d] + 25.0)
        hi, _ = s.overall_impact(raised, _W, _FLOOR)
        assert hi >= lo, f"raising {d} lowered overall {hi} < {lo}"


def test_clamped_0_100():
    allmax = {d: 100.0 for d in _W if d != "recovery"}
    overall, _ = s.overall_impact(allmax, _W, _FLOOR)
    assert 0 <= overall <= 100
    allmin = {d: 0.0 for d in _W if d != "recovery"}
    overall2, _ = s.overall_impact(allmin, _W, _FLOOR)
    assert overall2 == 0


# --- node integration ----------------------------------------------------------
def _trust(scores: dict) -> dict:
    return {d: TrustObj(domain=d, trust_score=v, confidence=1.0) for d, v in scores.items()}


def test_node_command_compromise_red():
    trust = _trust({"command": 0.0, "communication": 100.0, "identity_access": 100.0,
                    "session_network": 100.0, "mission": 100.0})
    out = compute_impact({"trust": trust, "tick_i": 1})
    assert out["impact"].band == "Red"
    assert "dry_streak" not in out                          # not Green -> no dry increment


def test_node_all_clean_green():
    trust = _trust({d: 100.0 for d in ["command", "communication", "identity_access",
                                       "session_network", "mission"]})
    out = compute_impact({"trust": trust, "tick_i": 1, "dry_streak": 0})
    assert out["impact"].band == "Green"
    assert out["dry_streak"] == 1


def test_node_all_stale_holds_band_never_green():
    # empty trust -> all domains stale -> hold prior (Green floored to Yellow) + incident
    prev = ImpactObj(score=10, band="Green")
    out = compute_impact({"trust": {}, "tick_i": 4, "impact": prev})
    assert out["impact"].band == "Yellow"                  # never emits Green when stale
    assert any(i.kind == "sensor-loss" for i in out["incidents"])


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
