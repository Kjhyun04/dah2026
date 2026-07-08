"""test_math — deterministic scoring pipeline (E5/E6/E7/E8/E19).

pytest-style; also runnable as ``python tests/test_math.py`` (no pytest needed) via
the __main__ runner. Covers: E5 trust idle=100, E6 saturation, E7 band->(sev,dev),
E8 confidence-once band shift, E19 correlation, plus trust_level banding.
"""
from __future__ import annotations

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import scoring as s  # noqa: E402
from mdg.config import defaults as D  # noqa: E402


# --- E5: trust idle -> 100 (confidence irrelevant when Σ=0) ------------------
def test_e5_trust_idle_is_100():
    assert s.trust_score([], 1.0) == 100.0
    assert s.trust_score([], 0.0) == 100.0
    assert s.trust_score([], 0.37) == 100.0            # confidence irrelevant at idle


def test_e5_all_normal_is_100():
    # normal band has sev=0, dev=0 -> penalty 0 -> 100 regardless of confidence
    assert s.trust_score([(0.4, "normal"), (0.35, "normal")], 0.9) == 100.0


# --- E6: saturation min(Σ,1); single critical must NOT zero the domain --------
def test_e6_saturation_caps_at_one():
    # oversized contributions saturate to penalty 1 -> trust 0 at conf=1
    big = [(0.45, "danger"), (0.4, "danger"), (0.5, "danger")]
    assert s.domain_penalty(big) == 1.0
    assert s.trust_score(big, 1.0) == 0.0


def test_e6_single_critical_not_zero():
    # one 'critical' with weight 0.35: penalty = 0.35*0.6*0.7 = 0.147 (not 1)
    p = s.domain_penalty([(0.35, "critical")])
    assert abs(p - 0.147) < 1e-9
    assert s.trust_score([(0.35, "critical")], 1.0) > 80.0   # domain not collapsed


# --- E7: band -> (severity, deviation) table ---------------------------------
def test_e7_band_map():
    assert s.severity_factor("normal") == 0.0 and s.deviation("normal") == 0.0
    assert s.severity_factor("warning") == 0.3 and s.deviation("warning") == 0.4
    assert s.severity_factor("critical") == 0.6 and s.deviation("critical") == 0.7
    assert s.severity_factor("danger") == 1.0 and s.deviation("danger") == 1.0


# --- E8: confidence used EXACTLY once as a conservative band shift ------------
def test_e8_confidence_once_low_bumps_band():
    # score 20 -> Green; low confidence bumps Green -> Yellow, shift 1
    score, band, shift = s.compute_impact(20, 0.3)
    assert band == "Yellow" and shift == 1 and score == 20


def test_e8_confidence_once_high_no_bump():
    score, band, shift = s.compute_impact(20, 0.9)
    assert band == "Green" and shift == 0


def test_e8_no_double_penalty():
    # shifting is additive-band, not multiplicative on the score
    score_hi, _, _ = s.compute_impact(50, 0.9)
    score_lo, _, _ = s.compute_impact(50, 0.1)
    assert score_hi == score_lo == 50                 # score unchanged; only band shifts


def test_e8_red_saturates():
    _, band, shift = s.compute_impact(80, 0.1)        # already Red; band stays Red
    assert band == "Red"


# --- E19: correlation score = weight*mean(sev)*(n>=2) ------------------------
def test_e19_single_member_is_zero():
    assert s.correlation_score(1.0, [0.6]) == 0.0     # n<2 -> 0


def test_e19_two_members():
    assert abs(s.correlation_score(1.0, [0.6, 1.0]) - 0.8) < 1e-9


def test_e19_weight_applies():
    assert abs(s.correlation_score(0.5, [0.6, 1.0]) - 0.4) < 1e-9


# --- trust_level banding -----------------------------------------------------
def test_trust_level_bands():
    assert s.trust_level(100) == "very_high"
    assert s.trust_level(89) == "high"
    assert s.trust_level(50) == "moderate"
    assert s.trust_level(30) == "low"
    assert s.trust_level(0) == "very_low"


# --- confidence composite ----------------------------------------------------
def test_confidence_composite():
    assert abs(s.confidence(0.95, 1.0, 1.0, 0.0) - 0.95) < 1e-9
    assert abs(s.confidence(0.9, 0.8, 1.0, 0.5) - 0.9 * 0.8 * 0.5) < 1e-9
    assert s.confidence(2.0, 2.0, 2.0, 0.0) == 1.0    # clamped to 1


# --- recovery score monotonicity --------------------------------------------
def test_recovery_score_bounds():
    v = s.recovery_score(0.9, 40, 40, 0.6, 0.0)
    assert 0.0 <= v <= 1.0


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
