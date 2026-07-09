"""test_cr01_signed_recovery — Item 2: incident -> signing-recovery 적법 후보.

"command-도메인 incident -> send_signed_mode 가 적법(LEGAL) recovery 가 됨" 배선을
select_policy + legality + rank_recovery 를 관통해 end to end 로 고정하며, core 하드코드
전혀 없음(튜닝은 recovery_priors.yaml + 닫힌 _INCIDENT_RECOVERY 맵에만 존재). 오프라인
실행이며 완전 결정론적(불변식1.).

두 경로가 send_signed_mode 를 적법 후보로 전달한다; 둘 다 여기서 고정된다:

  A) CR01 (PFCP_Delete_Attempt + Unauthorized_Command 의 E19 시간창 상관)
     -> _INCIDENT_RECOVERY["CR01"] = [pfcp_firewall, command_override]. command_override 의
     response_tool 은 send_signed_mode(recovery_priors). 오직(ONLY)
     signing == CONFIRMED_ON 이고 role_verified[<gcs_proxy>] 가 True 일 때 legal_actions 에
     진입한다. 순수-CR01 적법 집합에서 pfcp_firewall 이 공존하며(CO-EXISTS)(동일 gcs_proxy
     chokepoint) command_override 를 결정론적으로 능가하므로, 자율 선택 액션은
     nsenter_input_drop 이다 — 비행 업링크는 제시되나 자동 선택되지 않는다(send_signed_mode 는 OPER/operator-go 유지).

  B) command single-signal (Unauthorized_Command / Signature_Verify_Fail) -> signed_guided
     (send_signed_mode), _RTYPE_DOMAIN_GUARD command 게이트를 통해. 컨테이너 격리
     피어(backdoor_pause -> web_backend)가 미검증일 때, signed_guided 가 유일한(SOLE) 적법
     후보이며 send_signed_mode 가 선택된(CHOSEN) 비행-recovery 도구다(S2 시나리오).

Fail-safe (MONOTONIC LATCH): signing 이 UNKNOWN 또는 CONFIRMED_OFF, 또는 role_verified
바인딩 누락 시, send_signed_mode 를 적법 집합에서 반드시 배제해야 한다(미확인 인증
비행 업링크를 절대 발사하지 않음).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import loader  # noqa: E402
from mdg.core.nodes.rank_recovery import rank_recovery  # noqa: E402
from mdg.core.nodes.select_policy import _INCIDENT_RECOVERY, select_policy  # noqa: E402
from mdg.core.state import Incident  # noqa: E402
from mdg.core.worldstate import SigningObs, WorldState  # noqa: E402

CFG = "mdg-cfg-2026-07-07"


def _cr01() -> Incident:
    return Incident(id="CR01-0", kind="CR01",
                    members=["PFCP_Delete_Attempt", "Unauthorized_Command"])


def _cmd_single_signal(metric: str = "Signature_Verify_Fail") -> Incident:
    return Incident(id=f"sig-0-{metric}", kind="single-signal", members=[metric])


def _world(*, signing: SigningObs, verified: dict) -> WorldState:
    return WorldState(config_version=CFG, signing=signing, role_verified=verified)


def _drive(incident: Incident, world: WorldState) -> tuple[list, dict]:
    st = {"incidents": [incident], "worldstate": world, "config_version": CFG}
    legal = select_policy(st)["legal_actions"]
    st["legal_actions"] = legal
    return legal, rank_recovery(st)


def _tools(legal) -> set:
    return {a.tool_id for a in legal}


# --------------------------------------------------------------------------- #
# 매핑 일관성 (순수 config; core 리터럴 없음)
# --------------------------------------------------------------------------- #
def test_cr01_maps_to_command_override_signing_recovery():
    assert _INCIDENT_RECOVERY["CR01"] == ["pfcp_firewall", "command_override"]
    priors = loader.recovery_priors().get("recovery_priors", {})
    # CR01 의 signing-recovery 후보는 비행-업링크 도구를 디스패치한다
    assert priors["command_override"]["response_tool"] == "send_signed_mode"
    assert priors["command_override"]["enforce_at"] == "gcs_proxy"


# --------------------------------------------------------------------------- #
# A) CR01 적법성 — send_signed_mode 는 오직 CONFIRMED_ON + role gcs 에서만 허용
# --------------------------------------------------------------------------- #
def test_cr01_confirmed_signing_and_role_gcs_admits_send_signed_mode():
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={"gcs_proxy": True})
    legal, _ = _drive(_cr01(), world)
    rtypes = {a.recovery_type for a in legal}
    assert "command_override" in rtypes, rtypes
    assert "send_signed_mode" in _tools(legal)


def test_cr01_unknown_signing_latch_excludes_send_signed_mode():
    # MONOTONIC LATCH fail-safe: 권위 있는 ON 관측 없음 -> 비행 업링크 비적법.
    world = _world(signing=SigningObs.UNKNOWN, verified={"gcs_proxy": True})
    legal, _ = _drive(_cr01(), world)
    assert "command_override" not in {a.recovery_type for a in legal}
    assert "send_signed_mode" not in _tools(legal)


def test_cr01_confirmed_off_excludes_send_signed_mode():
    # CONFIRMED_ON 만 강제됨(signing_enforced); confirmed-OFF 자세는 비적법.
    world = _world(signing=SigningObs.CONFIRMED_OFF, verified={"gcs_proxy": True})
    legal, _ = _drive(_cr01(), world)
    assert "send_signed_mode" not in _tools(legal)


def test_cr01_missing_role_gcs_excludes_send_signed_mode():
    # role 게이트: gcs_proxy chokepoint 바인딩 부재 -> command_override 비적법(self-DoS 차단).
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={})
    legal, _ = _drive(_cr01(), world)
    assert "send_signed_mode" not in _tools(legal)


# --------------------------------------------------------------------------- #
# A) CR01 랭킹 — 결정론적 전순서 (pfcp_firewall 이 command_override 를 능가)
# --------------------------------------------------------------------------- #
def test_cr01_rank_is_deterministic_pfcp_out_ranks_command_override():
    # CONFIRMED_ON + gcs 하에서 둘 다 적법. recovery_priors 는 복합 recovery_score(위험 가중)를
    # 통해 pfcp_firewall(succ 0.80, MED)을 command_override(succ 0.90, HIGH)보다 높게 점수화하며,
    # core _sort_key 부스트는 없다. 이를 고정하면 자율 CR01 선택이 고정된다: 비행
    # 업링크는 적법 후보이나 자동 선택되지 않는다(send_signed_mode 는 operator-go 유지).
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={"gcs_proxy": True})
    legal, out = _drive(_cr01(), world)
    assert {a.recovery_type for a in legal} == {"pfcp_firewall", "command_override"}
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.rule == "pfcp_firewall"
    assert chosen.tool_id == "nsenter_input_drop"


# --------------------------------------------------------------------------- #
# B) command single-signal — send_signed_mode 가 선택된 비행 recovery(S2)
# --------------------------------------------------------------------------- #
def test_command_hijack_single_signal_chooses_send_signed_mode():
    # command-도메인 single-signal(Signature_Verify_Fail)은 _RTYPE_DOMAIN_GUARD command
    # 게이트를 통해 signed_guided 를 허용. gcs_proxy 검증됨, web_backend 미검증 -> backdoor_pause
    # 필터됨 -> signed_guided 유일 적법 -> send_signed_mode 선택됨(S2 비행 recovery).
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={"gcs_proxy": True})
    legal, out = _drive(_cmd_single_signal("Signature_Verify_Fail"), world)
    assert [a.recovery_type for a in legal] == ["signed_guided"], [a.recovery_type for a in legal]
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.tool_id == "send_signed_mode"
    assert chosen.rule == "signed_guided"
    assert out["chosen_action_risk"] == "HIGH"
    assert out["chosen_action_reversible"] is False


def test_command_single_signal_unknown_signing_no_flight_uplink():
    # LIVE 자세 fail-safe: UNKNOWN signing -> signed_guided 이중 게이트로 배제; 격리
    # 피어도 미검증이면 적법 recovery 없음, 비행 업링크 선택 없음.
    world = _world(signing=SigningObs.UNKNOWN, verified={"gcs_proxy": True})
    legal, out = _drive(_cmd_single_signal("Signature_Verify_Fail"), world)
    assert "send_signed_mode" not in _tools(legal)
    assert out["chosen_action"] is None


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
