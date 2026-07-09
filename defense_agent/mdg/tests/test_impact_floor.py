"""test_impact_floor — P0 panel-3: overall_impact = max(weighted_mean, criticality_floor).

단일 안전 크리티컬 도메인의 완전 침해가 보상적 가중 평균에 의해 Green으로 희석되지 않고,
부재/노후(stale) 도메인은 제외되며(trust=100으로 기본값 처리되지 않음), 집계가 각 distrust에
대해 단조(monotone)임을 고정하는 보안 계약을 핀으로 고정한다.
``python tests/test_impact_floor.py``로 실행 가능.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import defaults as D  # noqa: E402
from mdg.core import scoring as s  # noqa: E402
from mdg.core.nodes.compute_impact import compute_impact  # noqa: E402
from mdg.core.state import ImpactObj, TrustObj  # noqa: E402

_W = dict(D.MISSION_PROFILE["mission_weight"])            # 라이브 Recon 가중치
_FLOOR = dict(D.MISSION_PROFILE["criticality_floor"])


# --- 핵심 반례: command 하이재킹은 Green으로 읽혀선 안 됨 -------
def test_command_full_compromise_is_red_not_green():
    distrust = {"command": 100.0, "communication": 0.0, "identity_access": 0.0,
                "session_network": 0.0, "mission": 0.0}
    overall, _ = s.overall_impact(distrust, _W, _FLOOR)
    # 단순 가중 평균은 20(=Green); floor가 71(=Red)로 고정
    assert overall == 71
    assert s.impact_band(overall) == "Red"


def test_weighted_mean_alone_would_be_green():
    # floor가 막는 결함을 문서화: 동일 입력의 단순 평균 = 20 = Green
    distrust = {"command": 100.0, "communication": 0.0, "identity_access": 0.0,
                "session_network": 0.0, "mission": 0.0}
    num = sum(_W[d] * distrust[d] for d in distrust)
    total_w = sum(_W[d] for d in distrust)
    assert round(num / total_w) == 20
    assert s.impact_band(20) == "Green"


# --- criticality floor는 mission_weight == 0에서도 발동 ------------------------
def test_floor_fires_at_zero_weight():
    weights = dict(_W)
    weights["command"] = 0                                 # config 변조: 가중치를 0으로
    distrust = {"command": 100.0, "communication": 0.0, "identity_access": 0.0,
                "session_network": 0.0, "mission": 0.0}
    overall, _ = s.overall_impact(distrust, weights, _FLOOR)
    assert overall == 71                                   # floor는 가중치와 무관


def test_crit_floor_stepwise():
    assert s.crit_floor("command", 100.0, _FLOOR) == 71.0
    assert s.crit_floor("command", 50.0, _FLOOR) == 45.0
    assert s.crit_floor("command", 10.0, _FLOOR) == 0.0
    assert s.crit_floor("communication", 100.0, _FLOOR) == 0.0   # floor 없는 도메인


# --- P3-Q4: 71/45는 밴드 컷에서 파생된 LOCK 상수, 임의 시드 아님 -----------
def test_floors_are_band_cut_derived():
    # P3-Q4 재정립에 대한 회귀 라벨: 상단 floor는 Red 밴드의 하단 컷(71)이고 하단 floor는
    # Yellow[31,70] 내부(45)에 위치. IMPACT_BANDS가 바뀌면 이 테스트가 크게 실패하여 floor가
    # 재파생되도록 하며, 노후한 임의 시드로 방치되지 않는다.
    from mdg.config import defaults as _D
    red_lo, _red_hi = _D.IMPACT_BANDS["Red"]
    y_lo, y_hi = _D.IMPACT_BANDS["Yellow"]
    for dom in ("command", "session_network"):
        assert s.crit_floor(dom, 71.0, _FLOOR) == float(red_lo)     # 상단 floor == Red 하단
        assert y_lo <= s.crit_floor(dom, 40.0, _FLOOR) <= y_hi      # 하단 floor는 Yellow 내부
    assert s.crit_floor("identity_access", 71.0, _FLOOR) == 45.0    # integrity/recon -> Yellow
    # Red 하단 컷에서의 command distrust는 overall을 Red 하단으로 고정(밴드 컷 항등)
    distrust = {"command": float(red_lo), "communication": 0.0, "identity_access": 0.0,
                "session_network": 0.0, "mission": 0.0}
    overall, _ = s.overall_impact(distrust, _W, _FLOOR)
    assert overall == red_lo
    assert s.impact_band(overall) == "Red"


def test_partial_command_distrust_stays_yellow_floor_not_auto_red():
    # P3-Q4/PS-7: [40,71) 범위의 distrust(의심 / signing=UNKNOWN, 확인된 비인증
    # 액추에이션 아님)는 중간 Yellow floor 45에 머물며 결코 Red로 자동 격상되지 않는다.
    # 오직 실제 액추에이션 관측만 command distrust를 >=71로 매핑(compute_trust
    # distrust-input 계약 참조). 주입된 의심에 의한 자기 DoS를 방어.
    assert s.crit_floor("command", 70.0, _FLOOR) == 45.0
    assert s.impact_band(int(s.crit_floor("command", 70.0, _FLOOR))) == "Yellow"
    assert s.crit_floor("command", 39.0, _FLOOR) == 0.0            # 트리거 미만 -> floor 없음


# --- present-set 정규화: 부재 도메인 제외, 분모 = Σ present w ----
def test_present_set_renormalization():
    # non-floor 도메인 2개만 존재 -> 평균은 그들의 가중치(50)로 정규화, 100 아님
    distrust = {"communication": 60.0, "mission": 0.0}     # 가중치 30 + 20 = 50
    overall, _ = s.overall_impact(distrust, _W, _FLOOR)
    assert overall == 36                                   # 30*60/50 = 36 (18 = /100 아님)


# --- 단조성: 어떤 distrust를 올려도 overall이 낮아지지 않음 (PS-7/불변식1.) ------
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


# --- 노드 통합 ----------------------------------------------------------
def _trust(scores: dict) -> dict:
    return {d: TrustObj(domain=d, trust_score=v, confidence=1.0) for d, v in scores.items()}


def test_node_command_compromise_red():
    trust = _trust({"command": 0.0, "communication": 100.0, "identity_access": 100.0,
                    "session_network": 100.0, "mission": 100.0})
    out = compute_impact({"trust": trust, "tick_i": 1})
    assert out["impact"].band == "Red"
    assert "dry_streak" not in out                          # Green 아님 -> dry 증가 없음


def test_node_all_clean_green():
    trust = _trust({d: 100.0 for d in ["command", "communication", "identity_access",
                                       "session_network", "mission"]})
    out = compute_impact({"trust": trust, "tick_i": 1, "dry_streak": 0})
    assert out["impact"].band == "Green"
    assert out["dry_streak"] == 1


def test_node_all_stale_holds_band_never_green():
    # 빈 trust -> 모든 도메인 stale -> 이전 값 유지(Green을 Yellow로 floor) + 인시던트
    prev = ImpactObj(score=10, band="Green")
    out = compute_impact({"trust": {}, "tick_i": 4, "impact": prev})
    assert out["impact"].band == "Yellow"                  # stale일 때 결코 Green 방출 안 함
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
