"""test_math — 결정론적 스코어링 파이프라인 (E5/E6/E7/E8/E19).

pytest 스타일; __main__ 러너를 통해 ``python tests/test_math.py``로도 실행 가능(pytest 불필요).
포함: E5 trust idle=100, E6 포화, E7 band->(sev,dev), E8 confidence 1회 band shift,
E19 상관(correlation), 그리고 trust_level 밴딩.
"""
from __future__ import annotations

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import scoring as s  # noqa: E402
from mdg.config import defaults as D  # noqa: E402


# --- E5: trust idle -> 100 (Σ=0일 때 confidence 무관) ------------------
def test_e5_trust_idle_is_100():
    assert s.trust_score([], 1.0) == 100.0
    assert s.trust_score([], 0.0) == 100.0
    assert s.trust_score([], 0.37) == 100.0            # idle에서 confidence 무관


def test_e5_all_normal_is_100():
    # normal band는 sev=0, dev=0 -> penalty 0 -> confidence와 무관하게 100
    assert s.trust_score([(0.4, "normal"), (0.35, "normal")], 0.9) == 100.0


# --- E6: 포화 min(Σ,1); 단일 critical이 도메인을 0으로 만들어선 안 됨 --------
def test_e6_saturation_caps_at_one():
    # 과도한 기여는 penalty 1로 포화 -> conf=1에서 trust 0
    big = [(0.45, "danger"), (0.4, "danger"), (0.5, "danger")]
    assert s.domain_penalty(big) == 1.0
    assert s.trust_score(big, 1.0) == 0.0


def test_e6_single_critical_not_zero():
    # weight 0.35인 'critical' 하나: penalty = 0.35*0.6*0.7 = 0.147 (1 아님)
    p = s.domain_penalty([(0.35, "critical")])
    assert abs(p - 0.147) < 1e-9
    assert s.trust_score([(0.35, "critical")], 1.0) > 80.0   # 도메인 붕괴 안 됨


# --- E7: band -> (severity, deviation) 테이블 ---------------------------------
def test_e7_band_map():
    assert s.severity_factor("normal") == 0.0 and s.deviation("normal") == 0.0
    assert s.severity_factor("warning") == 0.3 and s.deviation("warning") == 0.4
    assert s.severity_factor("critical") == 0.6 and s.deviation("critical") == 0.7
    assert s.severity_factor("danger") == 1.0 and s.deviation("danger") == 1.0


# --- E8: confidence는 보수적 band shift로 정확히 1회만 사용 ------------
def test_e8_confidence_once_low_bumps_band():
    # score 20 -> Green; 낮은 confidence가 Green -> Yellow로 올림, shift 1
    score, band, shift = s.compute_impact(20, 0.3)
    assert band == "Yellow" and shift == 1 and score == 20


def test_e8_confidence_once_high_no_bump():
    score, band, shift = s.compute_impact(20, 0.9)
    assert band == "Green" and shift == 0


def test_e8_no_double_penalty():
    # shift는 band 가산이지 score에 대한 곱셈이 아님
    score_hi, _, _ = s.compute_impact(50, 0.9)
    score_lo, _, _ = s.compute_impact(50, 0.1)
    assert score_hi == score_lo == 50                 # score 불변; band만 shift


def test_e8_red_saturates():
    _, band, shift = s.compute_impact(80, 0.1)        # 이미 Red; band는 Red 유지
    assert band == "Red"


# --- E19: correlation score = weight*mean(sev)*(n>=2) ------------------------
def test_e19_single_member_is_zero():
    assert s.correlation_score(1.0, [0.6]) == 0.0     # n<2 -> 0


def test_e19_two_members():
    assert abs(s.correlation_score(1.0, [0.6, 1.0]) - 0.8) < 1e-9


def test_e19_weight_applies():
    assert abs(s.correlation_score(0.5, [0.6, 1.0]) - 0.4) < 1e-9


# --- trust_level 밴딩 -----------------------------------------------------
def test_trust_level_bands():
    assert s.trust_level(100) == "very_high"
    assert s.trust_level(89) == "high"
    assert s.trust_level(50) == "moderate"
    assert s.trust_level(30) == "low"
    assert s.trust_level(0) == "very_low"


# --- confidence 합성 ----------------------------------------------------
def test_confidence_composite():
    assert abs(s.confidence(0.95, 1.0, 1.0, 0.0) - 0.95) < 1e-9
    assert abs(s.confidence(0.9, 0.8, 1.0, 0.5) - 0.9 * 0.8 * 0.5) < 1e-9
    assert s.confidence(2.0, 2.0, 2.0, 0.0) == 1.0    # 1로 clamp


# --- recovery score 단조성 --------------------------------------------
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
