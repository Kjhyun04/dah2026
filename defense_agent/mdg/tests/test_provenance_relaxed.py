"""test_provenance_relaxed — Phase 2 (RECOVERY_DEMO_PLAN §Phase2, B3/PS-7).

operator_auto (sandbox demo) 하에서 injected-high-severity provenance/debounce 게이트는
record-then-pass 로 RELAXED 된다:
  * rank_recovery 는 chosen_action.provenance_relaxed=True 를 스탬프 (ledger/trace 투명성);
  * physical-action debounce 는 INERT-DRY recovery 경로 (docker_pause / flight — live argv
    빌더 없음)에 대해 config demo_mode.debounce_ticks 로 SHRINK 되어 재선택된 recovery 가
    다음 tick 안에 재바인딩됨. LIVE netns-insertion 경로 (nsenter_input_drop)는 EXCLUDE 되어
    full physical_action_min hold 를 유지: 그 actuator 는 비멱등 iptables -I 를 사용하고,
    observe=None 이면 already_applied 가 절대 발동하지 않으므로, debounce 가 유일한 재작동
    throttle — 이를 줄이면 중복 DROP 규칙이 누적됨 (leak-0 / reversibility 위험).
Production (operator_auto off)은 UNCHANGED: provenance_relaxed=False 이며 full
debounce.physical_action_min_ticks hold 가 적용됨 (strict PS-7). 불변식1. (결정론적: env bool +
config, LLM 없음)과 2. (신규 subprocess 경로 없음)는 온전.

``python mdg/tests/test_provenance_relaxed.py`` 로 독립 실행 가능.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import defaults as D  # noqa: E402
from mdg.config import loader  # noqa: E402
from mdg.core import bundle as bundle_mod  # noqa: E402
from mdg.core.nodes.rank_recovery import rank_recovery  # noqa: E402
from mdg.core.nodes.select_policy import select_policy  # noqa: E402
from mdg.core.state import Action, Incident, Intent  # noqa: E402
from mdg.core.worldstate import AppliedRule, WorldState  # noqa: E402
from mdg.safe_exec.backend import Backend  # noqa: E402
from mdg.safe_exec.response import ResponseController  # noqa: E402


def _injected_backdoor_action() -> Action:
    # injected 후보로서 feasible reversible MED recovery (docker_pause / backdoor_pause)
    return Action(tool_id="docker_pause", recovery_type="backdoor_pause", risk="MED",
                  reversible=True, params={"recovery_type": "backdoor_pause",
                                           "target": "10.45.0.5", "target_kind": "ip",
                                           "enforce_at": "web_backend"})


# --------------------------------------------------------------------------- #
# config 표면 — demo_mode 존재, relaxed, 그리고 debounce 가 엄격히 더 짧음
# --------------------------------------------------------------------------- #
def test_demo_mode_config_present_and_shorter_than_strict():
    dm = loader.demo_mode()
    assert dm["provenance_relaxed"] is True
    assert isinstance(dm["debounce_ticks"], int)
    # demo hold 는 strict physical-action debounce 보다 짧아야 함 (아니면 "relax" 가
    # no-op 이 됨)
    assert dm["debounce_ticks"] < D.DEBOUNCE_PHYSICAL_MIN_TICKS


# --------------------------------------------------------------------------- #
# PRODUCTION (operator_auto off) — strict: bind 불변, relaxation 마커 없음
# --------------------------------------------------------------------------- #
def test_production_binds_but_does_not_relax_provenance():
    st = {"legal_actions": [_injected_backdoor_action()], "config_version": "t"}
    out = rank_recovery(st)                                # operator_auto 부재 -> False
    assert out["chosen_action"] is not None               # REGRESSION: 여전히 bind
    assert isinstance(out["chosen_action"], Intent)
    assert out["chosen_action"].provenance_relaxed is False  # strict 자세 미면제

    # 명시적 operator_auto=False 는 동일 (안전 기본값)
    st2 = {"legal_actions": [_injected_backdoor_action()], "config_version": "t",
           "operator_auto": False}
    assert rank_recovery(st2)["chosen_action"].provenance_relaxed is False


# --------------------------------------------------------------------------- #
# DEMO (operator_auto on) — 기록-후-통과: bind + provenance_relaxed=True (trace/ledger)
# --------------------------------------------------------------------------- #
def test_demo_operator_auto_relaxes_and_records():
    st = {"legal_actions": [_injected_backdoor_action()], "config_version": "t",
          "operator_auto": True}
    out = rank_recovery(st)
    intent = out["chosen_action"]
    assert intent is not None
    assert intent.provenance_relaxed is True              # ledger/trace 용 waiver 스탬프됨
    assert out["chosen_action_risk"] == "MED"
    assert out["chosen_action_reversible"] is True
    # 마커는 model_dump 를 견뎌 recording hook / ledger 가 이를 지님
    assert out["chosen_action"].model_dump()["provenance_relaxed"] is True


# --------------------------------------------------------------------------- #
# END-TO-END(ish) — INJECTED 단일 시그널 attack 이 demo 하에서 chosen_action 에 bind
# --------------------------------------------------------------------------- #
def test_injected_attack_binds_to_chosen_action_under_demo():
    # BACKDOOR_5762 injected incident -> select_policy 후보 -> rank_recovery 가 bind
    cfg = loader.config_version()
    rv = {}
    for spec in loader.recovery_priors().get("recovery_priors", {}).values():
        ea = str(spec.get("enforce_at") or "")
        if ea:
            rv[ea] = True
    world = WorldState(config_version=cfg, role_verified=rv)
    inc = Incident(id="sig-0-Port_5762_State", kind="BACKDOOR_5762", target="10.45.0.9")
    st = {"incidents": [inc], "worldstate": world, "config_version": cfg,
          "operator_auto": True}
    st.update(select_policy(st))
    assert st["legal_actions"], "injected 5762 incident must yield a legal recovery candidate"
    out = rank_recovery({**st, **{"legal_actions": st["legal_actions"]}})
    assert out["chosen_action"] is not None, "injected attack must bind to chosen_action"
    assert out["chosen_action"].provenance_relaxed is True


# --------------------------------------------------------------------------- #
# DEBOUNCE relaxation — demo shrink 은 INERT-DRY 경로에만 적용; LIVE
# netns-insertion 경로 (nsenter_input_drop)는 full physical_action_min hold 를 유지.
# --------------------------------------------------------------------------- #
def test_demo_debounce_shrink_holds_live_insertion_frees_inert_path():
    # primitive: tick 1 에서 strict (3)는 HOLD, demo (1)는 아님
    world = WorldState().with_applied(
        AppliedRule(rule="probe", applied_tick=0, confirmed=False))
    assert bundle_mod.debounce_blocked(world, "probe", 1, D.DEBOUNCE_PHYSICAL_MIN_TICKS) is True
    assert bundle_mod.debounce_blocked(world, "probe", 1, loader.demo_mode()["debounce_ticks"]) is False

    prod = ResponseController(backend=Backend(allow_live=False), operator_auto=False)
    demo = ResponseController(backend=Backend(allow_live=False), operator_auto=True)

    # LIVE netns-insertion 경로 (nsenter_input_drop): 그 actuator 는 NON-idempotent iptables
    # -I 를 사용하고, observe=None 이면 already_applied 가 절대 발동 안 함 -> debounce 가 유일한
    # 재작동 throttle. demo shrink 은 여기 적용되어선 안 됨 (아니면 단일 -D revert 로 되돌릴 수 없는
    # 중복 DROP 규칙이 누적). strict 3-tick hold 는 prod 와 operator_auto 양쪽에서 유지.
    live_rule = "backdoor_drop"
    world_live = WorldState().with_applied(
        AppliedRule(rule=live_rule, applied_tick=0, confirmed=False))
    intent_live = Intent(rule=live_rule, tool_id="nsenter_input_drop")
    p_prod = prod.plan(intent_live, world_live, 1, risk="MED", reversible=True)
    assert p_prod.skip is True and "debounced" in p_prod.reason
    p_live = demo.plan(intent_live, world_live, 1, risk="MED", reversible=True)
    assert p_live.skip is True and "debounced" in p_live.reason, \
        "live netns DROP must keep 3-tick damping even under operator_auto (non-idempotent -I)"

    # INERT-DRY 경로 (operator_auto 로 넓혀진 docker_pause -> argv 빌더 없음, 부수효과 0):
    # 여기서 재작동은 순수 no-op 이므로, demo shrink 이 안전하게 recovery 를 다음 tick 에 재바인딩.
    # production 에서는 엄격히 hold.
    inert_rule = "backdoor_pause"
    world_inert = WorldState().with_applied(
        AppliedRule(rule=inert_rule, applied_tick=0, confirmed=False))
    intent_inert = Intent(rule=inert_rule, tool_id="docker_pause", enforce_at="target")
    assert prod.plan(intent_inert, world_inert, 1, risk="MED", reversible=True).skip is True
    p_inert = demo.plan(intent_inert, world_inert, 1, risk="MED", reversible=True)
    assert p_inert.skip is False, "inert OPER recovery re-binds within the next tick under demo"


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
