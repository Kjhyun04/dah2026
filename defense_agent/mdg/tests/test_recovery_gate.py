"""test_recovery_gate — P0 panel-1 (M6/E-2): feasibility gate 대 recovery_score 분리.

이 결정을 고정하여, 이후 리팩터가 feasibility gate 를 다시 recovery_score(~0.14-0.38 로
상한이 걸려 모든 응답을 영구히 infeasible 로 만듦)로 가리켜 에이전트를 조용히
재차 벽돌화하지 못하게 한다. ``python tests/test_recovery_gate.py`` 로 실행 가능.
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


# --- 분리 자체: recovery_score 아닌 success_probability 로 게이트 ---------
def test_every_prior_admitted_by_success_prob_gate():
    fmin = _feasible_min()
    for name, prior in D.RECOVERY_PRIORS.items():
        assert float(prior["success_probability"]) >= fmin, f"{name} blocked by gate"


def test_recovery_score_cannot_be_the_gate():
    # 모든 recovery_score 는 0.70 하한보다 한참 아래 -> 이를 게이트로 쓰면 영구 infeasible
    scores = {n: _score(p) for n, p in D.RECOVERY_PRIORS.items()}
    assert max(scores.values()) < _feasible_min(), scores       # 모순을 고정


def test_recovery_score_is_bounded():
    for p in D.RECOVERY_PRIORS.values():
        assert 0.0 <= _score(p) <= 1.0


# --- gate 를 recovery_score 로 재지정 못하도록 config 키 개명 ---------
def test_feasible_min_key_is_success_prob_scoped():
    rp = loader.recovery_priors()
    assert "success_prob_feasible_min" in rp, "renamed gate key missing"


# --- 노드 동작: gate 는 success_probability 를 읽음 -----------------------------
def test_unknown_type_filtered_by_gate():
    # 미지 recovery_type -> success_probability 기본값 0.5 < 0.70 -> 필터링됨
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
