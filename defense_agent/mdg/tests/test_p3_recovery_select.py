"""test_p3_recovery_select — Phase 3 (B2): rank_recovery 는 VISIBLE 복구 도구를 방출한다.

core _sort_key 하드코드 없이 2-시나리오 계약을 고정 (튜닝은 오직
recovery_priors.yaml + 닫힌 _INCIDENT_RECOVERY 후보 맵에만 존재):

  S1 (컨테이너 격리, LIVE posture signing=UNKNOWN):
      single-signal -> select_policy 는 backdoor_pause (docker_pause)만 합법화한다. signed_guided
      는 legality 에 의해 DOUBLE-GATED 로 배제됨 (send_signed_mode 는 signing==CONFIRMED_ON 요구), 따라서
      live/replay 합법 집합은 Phase 3 이전과 byte-identical 하다. rank -> docker_pause, MED, revocable.

  S2 (비행 복구, testbed posture signing=CONFIRMED_ON + role_verified.gcs):
      signed_guided 는 OPER/HIGH 후보로 legal_actions 에 진입한다 (누락되었던 배선 — orphan
      rtype 였음). 유일한 합법 후보일 때 선택된다 (send_signed_mode). backdoor_pause 와
      공존할 때는 backdoor_pause 가 여전히 상위 랭크 (priors, core boost 없음), 따라서
      signed_guided 를 받아들여도 S1 을 절대 교란하지 않는다.

오프라인 실행. 스크립트로 또는 pytest 하에서 실행 가능.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core.nodes.rank_recovery import rank_recovery  # noqa: E402
from mdg.core.nodes.select_policy import _INCIDENT_RECOVERY, select_policy  # noqa: E402
from mdg.core.state import Incident  # noqa: E402
from mdg.core.worldstate import SigningObs, WorldState  # noqa: E402

CFG = "mdg-cfg-2026-07-07"


def _single_signal(target: str = "") -> Incident:
    return Incident(id="sig-0-Unauthorized_Command", kind="single-signal",
                    members=["Unauthorized_Command"], target=target)


def _world(*, signing: SigningObs, verified: dict) -> WorldState:
    return WorldState(config_version=CFG, signing=signing, role_verified=verified)


def _drive(world: WorldState) -> tuple[list, dict]:
    st = {"incidents": [_single_signal()], "worldstate": world, "config_version": CFG}
    legal = select_policy(st)["legal_actions"]
    st["legal_actions"] = legal
    return legal, rank_recovery(st)


# --------------------------------------------------------------------------- #
# 후보 배선 — signed_guided 는 더 이상 ORPHAN rtype 이 아니다
# --------------------------------------------------------------------------- #
def test_signed_guided_is_wired_into_single_signal_mapping():
    assert "signed_guided" in _INCIDENT_RECOVERY["single-signal"]
    assert "backdoor_pause" in _INCIDENT_RECOVERY["single-signal"]


# --------------------------------------------------------------------------- #
# S1 — LIVE posture (signing UNKNOWN): signed_guided 필터링됨, S1 불변
# --------------------------------------------------------------------------- #
def test_s1_unknown_signing_only_backdoor_pause_legal():
    # web_backend (backdoor_pause chokepoint) 와 gcs_proxy (signed_guided chokepoint) 모두
    # verified — signed_guided 를 필터링하는 것은 role 게이트가 아니라 SIGNING 게이트임을 증명.
    world = _world(signing=SigningObs.UNKNOWN,
                   verified={"web_backend": True, "gcs_proxy": True})
    legal, out = _drive(world)
    rtypes = {a.recovery_type for a in legal}
    assert rtypes == {"backdoor_pause"}, rtypes           # signed_guided double-gated 로 배제
    # rank 는 VISIBLE 격리 도구를 바인딩
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.rule == "backdoor_pause"
    assert chosen.tool_id == "docker_pause"
    assert out["chosen_action_risk"] == "MED"
    assert out["chosen_action_reversible"] is True


def test_s1_legal_set_byte_identical_to_pre_phase3():
    # LIVE UNKNOWN posture 하의 합법 집합은 replay 가 byte-identical 하게 유지되도록 정확히
    # Phase 3 이전 집합이어야 한다 (불변식1.). backdoor_pause 만 — signed_guided 는 live 로 절대 새지 않음.
    world = _world(signing=SigningObs.UNKNOWN, verified={"web_backend": True, "gcs_proxy": True})
    legal, _ = _drive(world)
    assert [a.recovery_type for a in legal] == ["backdoor_pause"]


# --------------------------------------------------------------------------- #
# S2 — testbed posture (signing CONFIRMED_ON): signed_guided 가 후보로 진입
# --------------------------------------------------------------------------- #
def test_s2_confirmed_signing_admits_signed_guided_candidate():
    world = _world(signing=SigningObs.CONFIRMED_ON,
                   verified={"web_backend": True, "gcs_proxy": True})
    legal, out = _drive(world)
    rtypes = {a.recovery_type for a in legal}
    assert "signed_guided" in rtypes, rtypes              # 누락되었던 배선이 이제 존재
    assert "backdoor_pause" in rtypes
    # priors (core _sort_key boost 아님)는 여전히 backdoor_pause 를 최상위로 랭크 -> signing ON
    # 이어도 S1 교란 없음.
    assert out["chosen_action"].rule == "backdoor_pause"


def test_s2_signed_guided_chosen_when_sole_legal_candidate():
    # gcs_proxy verified 이지만 web_backend 아님 -> backdoor_pause 필터링됨, signed_guided 유일 합법 ->
    # VISIBLE 비행 복구 도구 (send_signed_mode)가 선택된다.
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={"gcs_proxy": True})
    legal, out = _drive(world)
    assert [a.recovery_type for a in legal] == ["signed_guided"], [a.recovery_type for a in legal]
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.rule == "signed_guided"
    assert chosen.tool_id == "send_signed_mode"
    assert out["chosen_action_risk"] == "HIGH"            # 비행 액션 -> 하류 OPER/HIGH
    assert out["chosen_action_reversible"] is False


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
