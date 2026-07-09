"""test_operator_auto — Phase 1 (샌드박스 데모): OPER 실행 경로의 operator 자동확인.

Phase 1의 세 배선 지점을 다룸(RECOVERY_DEMO_PLAN Phase 1 / B1):
  gate.py            — gate_for(..., operator_auto=True)는 REGISTERED OPER 결정을 auto=True로
                       확장(tier2 "AUTO_BY_OPERATOR"), 투명성을 위해 flight/registry_tier 보존;
                       UNREGISTERED ghost는 결코 확장되지 않음(fail-closed 절대).
  edges.py           — route_after_decide는 원래 escalate될 OPER 응답을 env 출처 operator_auto
                       bool에 따라 act로 라우팅(결정론적; 불변식1. 유지).
  act node           — OPER 도구가 실행됨(집행 기록)되며 ledger Intent에 operator_auto_confirmed=True
                       + authority="sandbox-auto"가 찍힘; operator_auto=0은 레거시 operator-gate
                       defer 유지(회귀: escalate/미집행).

오프라인 실행(Backend.allow_live=False -> DRY; testbed 상태 변경 없음). pytest 또는 스크립트.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import gate as G                       # noqa: E402
from mdg.core.edges import END, route_after_decide   # noqa: E402
from mdg.core.nodes.act import act                   # noqa: E402
from mdg.core.nodes.effect_confirm import effect_confirm  # noqa: E402
from mdg.core.state import Intent, initial_state      # noqa: E402
from mdg.core.worldstate import WorldState            # noqa: E402
from mdg.safe_exec.backend import Backend             # noqa: E402
from mdg.safe_exec.observer import make_effect_observer  # noqa: E402

CFG = "mdg-cfg-2026-07-07"


class _SpyLedger:
    def __init__(self):
        self.intents = []

    def record_intent(self, intent):
        self.intents.append(intent)
        return {"ledger": [intent]}


def _world(**kw) -> WorldState:
    kw.setdefault("role_verified", {"target": True})
    return WorldState(config_version=CFG, **kw)


def _pause_intent() -> Intent:
    # enforce_at="target"은 role_verified["target"]=True로 해석되어 legality가 통과됨(docker_pause는
    # role_verified.target을 요구). revert_cmd 존재 -> 가역 집행, boot 시 revert 가능.
    return Intent(rule="backdoor_pause", tool_id="docker_pause", enforce_at="target",
                  config_version=CFG, revert_cmd="revert:backdoor_pause")


def _state(chosen: Intent, *, risk="MED", reversible=True) -> dict:
    st = dict(initial_state(CFG))
    st["worldstate"] = _world()
    st["chosen_action"] = chosen
    st["chosen_action_risk"] = risk
    st["chosen_action_reversible"] = reversible
    return st


# --------------------------------------------------------------------------- #
# gate.py — operator_auto가 registered OPER -> auto로 확장(투명성 보존)
# --------------------------------------------------------------------------- #
def test_gate_operator_auto_widens_registered_oper():
    # 기본값(operator_auto=0) — 레거시 OPER 분류(회귀 가드)
    d0 = G.gate_for("docker_pause", "MED", True)
    assert d0.operator_required and d0.tier2 == "OPER"

    # operator_auto=1 -> auto, 단 registry_tier는 ledger/routing 투명성을 위해 OPER 유지
    d1 = G.gate_for("docker_pause", "MED", True, operator_auto=True)
    assert d1.auto is True and not d1.operator_required
    assert d1.tier2 == "AUTO_BY_OPERATOR" and d1.registry_tier == "OPER"
    assert G.is_auto("docker_pause", "MED", True, operator_auto=True)

    # flight (send_signed_mode): 마찬가지로 확장, flight 필드 보존(투명성)
    df = G.gate_for("send_signed_mode", "HIGH", False, operator_auto=True)
    assert df.auto is True and df.flight is True and df.registry_tier == "OPER"

    # 네이티브 AUTO 도구는 영향 없음(여전히 순수 AUTO, AUTO_BY_OPERATOR 아님)
    da = G.gate_for("nsenter_input_drop", "MED", True, operator_auto=True)
    assert da.auto is True and da.tier2 == "AUTO"

    # fail-closed 절대: 미등록/ghost id는 operator_auto로 결코 확장되지 않음
    assert G.gate_for("ghost_tool", "LOW", True, operator_auto=True).operator_required


# --------------------------------------------------------------------------- #
# edges.py — route_after_decide가 operator_auto를 결정론적으로 준수(불변식1.)
# --------------------------------------------------------------------------- #
def test_route_after_decide_operator_auto():
    chosen = _pause_intent()
    # HIGH risk: 기본 escalate; operator_auto -> act
    hi = {"chosen_action": chosen, "chosen_action_risk": "HIGH", "chosen_action_reversible": False}
    assert route_after_decide(hi) == "escalate"
    assert route_after_decide({**hi, "operator_auto": True}) == "act"

    # 비가역 MED: 기본 escalate; operator_auto -> act
    nr = {"chosen_action": chosen, "chosen_action_risk": "MED", "chosen_action_reversible": False}
    assert route_after_decide(nr) == "escalate"
    assert route_after_decide({**nr, "operator_auto": True}) == "act"

    # MED + 가역은 항상 act(operator_auto와 무관); None -> END
    ok = {"chosen_action": chosen, "chosen_action_risk": "MED", "chosen_action_reversible": True}
    assert route_after_decide(ok) == "act"
    assert route_after_decide({**ok, "operator_auto": True}) == "act"
    assert route_after_decide({"chosen_action": None}) == END


# --------------------------------------------------------------------------- #
# act node — OPER는 operator_auto=1에서 실행됨(집행 기록)
# --------------------------------------------------------------------------- #
def test_act_operator_auto_enforces_and_records():
    led = _SpyLedger()
    out = act(_state(_pause_intent()), backend=Backend(allow_live=False), ledger=led,
              operator_auto=True)

    # 집행 경로로 라우팅(operator-gate defer 아님): dry_streak 리셋, world 적용
    assert out.get("dry_streak") == 0
    assert out.get("operator_auto_confirmed") is True
    assert "worldstate" in out
    assert out["worldstate"].applied.get("backdoor_pause") is not None

    # ledger Intent가 투명성 감사 필드를 담고 있으며, operator-gate defer가 아님
    assert len(led.intents) == 1
    it = led.intents[0]
    assert it.operator_auto_confirmed is True and it.authority == "sandbox-auto"
    assert it.operator_gate is False


def test_act_operator_auto_off_defers_to_operator():
    # 회귀: operator_auto=0은 레거시 OPER operator-gate defer 유지(부작용 0)
    led = _SpyLedger()
    out = act(_state(_pause_intent()), backend=Backend(allow_live=False), ledger=led,
              operator_auto=False)

    # operator-gate defer: intent가 operator_gate=True로 기록, 집행/world 변경 없음
    assert "worldstate" not in out
    assert out.get("operator_auto_confirmed") is None
    assert len(led.intents) == 1
    it = led.intents[0]
    assert it.operator_gate is True
    assert it.operator_auto_confirmed is False and it.authority == ""


# --------------------------------------------------------------------------- #
# Phase 4 end-to-end: act가 docker_pause를 액추에이트 -> effect_confirm이 확인(S1)
# --------------------------------------------------------------------------- #
class _StatefulDocker:
    """inspect_paused가 실제 pause() 호출을 반영하는 덕타이핑 docker backend — 스크립트된
    _FakeDocker가 표현할 수 없는 결합(pause가 결코 액추에이트되지 않던 간극을 메움)."""
    def __init__(self):
        self.paused = {}

    def pause(self, container):
        self.paused[container] = True
        return {"paused": container}

    def inspect_paused(self, container):
        return self.paused.get(container, False)


# backdoor_pause는 RECOVERY_PRIORS를 통해 enforce_at을 "web_backend"로 해석; observer가 그 동일
# 컨테이너를 탐침하므로, intent enforce_at과 world 검증도 이를 사용해야 함(라이브 일관성).
def _pause_intent_web() -> Intent:
    return Intent(rule="backdoor_pause", tool_id="docker_pause", enforce_at="web_backend",
                  config_version=CFG, revert_cmd="revert:backdoor_pause")


def _state_web(chosen: Intent) -> dict:
    st = dict(initial_state(CFG))
    st["worldstate"] = WorldState(config_version=CFG, role_verified={"web_backend": True})
    st["chosen_action"] = chosen
    st["chosen_action_risk"] = "MED"
    st["chosen_action_reversible"] = True
    return st


def test_act_pause_web_backend_shielded_p1():
    """P1 구조적 방패(이전: pause가 액추에이트+확인): 보호된 관측 인프라 web_backend에 대한
    docker_pause는 operator_auto 하에서도 dispatch 단계에서 무력화(INERT)됨 — 대시보드는 결코
    자율적으로 동결되지 않음. pause() 호출이 docker backend에 도달하지 않고 적용된 규칙은
    미확인 상태 유지(아무것도 액추에이트되지 않아 effect_confirm이 결코 True로 뒤집을 수 없음)."""
    docker = _StatefulDocker()
    out = act(_state_web(_pause_intent_web()), backend=Backend(allow_live=False),
              ledger=_SpyLedger(), operator_auto=True, docker=docker)
    # P1: web_backend (보호된 관측/C2 인프라)는 pause되지 않음
    assert docker.paused.get("web_backend") is None
    world = out["worldstate"]
    assert world.applied["backdoor_pause"].confirmed is False       # 무력화 -> 결코 액추에이트 안 됨

    # 라이브 observer가 있어도 방패 유지: 컨테이너는 결코 pause되지 않음 -> False 유지
    obs = make_effect_observer(docker=docker)
    ec = effect_confirm({"worldstate": world}, observe=obs)
    assert ec["worldstate"].applied["backdoor_pause"].confirmed is False


def test_act_pause_inert_without_docker_stays_unconfirmed():
    """회귀/정직성 가드: docker backend가 없으면 pause는 operator-go DRY로 격하(액추에이션 없음)되어,
    inspect_paused가 결코 True일 수 없고 confirmed는 False 유지(거짓 확인 없음)."""
    out = act(_state_web(_pause_intent_web()), backend=Backend(allow_live=False),
              ledger=_SpyLedger(), operator_auto=True, docker=None)
    world = out["worldstate"]
    assert world.applied["backdoor_pause"].confirmed is False
    ec = effect_confirm({"worldstate": world}, observe=make_effect_observer(docker=None))
    assert ec["worldstate"].applied["backdoor_pause"].confirmed is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[PASS] {name}")
