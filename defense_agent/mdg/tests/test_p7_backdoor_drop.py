"""test_p7_backdoor_drop — 자율 5762 backdoor DROP 의 관통(end-to-end) 회귀.

steps 1-10 에서 도입된 전체 자율 경로를 잠가 이후 refactor 가 체인의 어느 링크도 조용히
깨뜨리지 못하게 한다:

  WebProbe(uav_ue netns) --source=peer--> ingest.SensorEv.source
    -> correlate  : Port_5762_State(danger) -> Incident(kind=BACKDOOR_5762, target=peer)
    -> select_policy: BACKDOOR_5762 -> Action(recovery_type=backdoor_drop, enforce_at=uav_ue,
                                              target=peer, target_kind=ip)
    -> legality    : registry alias 'role_verified.target' 가 enforce_at=uav_ue 에 동적 바인딩
    -> rank_recovery: backdoor_drop (succ 0.85 >= 0.70) -> chosen Intent (selector 전달)
    -> response.plan: 두 개의 별개 verified 엔드포인트 -> NON-inert argv
                      nsenter --target <uav_ue pid> ... -s <peer> -j DROP

커버리지:
  (a) WebProbe 는 peer SOURCE (귀속 selector)를 방출, count 아님.
  (b) correlate 는 target=peer 인 전용 BACKDOOR_5762 kind 를 방출 (metric 값 아님).
  (c) select_policy._candidates 는 backdoor_drop Action 을 빌드 (rtype/target/target_kind/enforce_at).
  (d) 통합: verified world 가 전체 체인을 NON-inert uav_ue-netns DROP argv 로 구동.
  (e) 대조: WRONG enforce_at (web_backend, 다른 netns)는 DROP 을 잘못된
      chokepoint pid 로 보냄 — config 의 enforce_at=uav_ue 가 핵심임을 증명 (5762 는 uav_ue 에 존재).
  (f) legality 동적 바인딩: alias 는 enforce_at (없으면 target)로 해석; 미검증 -> illegal.

오프라인 실행 (Backend.allow_live=False / mock). 스크립트 또는 pytest 로 실행 가능.
"""
from __future__ import annotations

import os
import queue
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.collector.ingest import Keyring                       # noqa: E402
from mdg.collector.web import (WebProbeCollector, parse_ss_established,  # noqa: E402
                               parse_ss_peer)
from mdg.core.legality import _resolve_role_key, is_legal      # noqa: E402
from mdg.core.nodes.correlate import correlate                 # noqa: E402
from mdg.core.nodes.rank_recovery import rank_recovery         # noqa: E402
from mdg.core.nodes.select_policy import _candidates, select_policy  # noqa: E402
from mdg.core.state import Action, Incident, SensorEv          # noqa: E402
from mdg.core.worldstate import RoleBinding, WorldState        # noqa: E402
from mdg.safe_exec.backend import Backend                      # noqa: E402
from mdg.safe_exec.response import ResponseController          # noqa: E402

CFG = "mdg-cfg-2026-07-07"
PEER = "10.45.0.13"            # 실측: attacker_ue tun IP (5762 peer)
UAV_PID = 1001                 # uav_ue netns pid (5762 LISTEN 소유)

# ss ESTAB 행: local = uav_ue:5762, peer = attacker:44321
_SS = "ESTAB 0 0 10.45.0.2:5762 10.45.0.13:44321\n"


def _ev_5762(source: str = PEER) -> SensorEv:
    """correlate 에 도달하는 (post-ingest) WebProbe 5762 danger evidence."""
    return SensorEv(source_id="web_5762_probe", metric="Port_5762_State",
                    value="ESTAB_PRESENT", band="danger", domain="command",
                    channel="port_5762_read", source=source, verified=True)


# --------------------------------------------------------------------------- #
# (a) WebProbe 는 peer SOURCE 를 방출, count 아님
# --------------------------------------------------------------------------- #
def test_webprobe_emits_peer_source_not_count():
    # 두 parser 는 별개: established=count, peer=귀속 IP
    assert parse_ss_established(_SS, 5762) == 1            # count (int)
    assert parse_ss_peer(_SS, 5762) == PEER               # peer IP (str), count 아님
    # collector 는 peer 를 `source` 로, enum 값과 함께 방출 (절대 count 아님)
    col = WebProbeCollector(
        queue.Queue(), Keyring(keys={"k1": b"k"}), "k1",
        backend=Backend(mode="mock", mock_table={":5762": _SS}),
        netns_prefix=["nsenter", "--target", str(UAV_PID), "--net", "--"])
    out = col.collect()
    assert len(out) == 1
    ev = out[0]
    assert ev["source"] == PEER                           # 귀속 selector (peer), count 아님
    assert ev["value"] == "ESTAB_PRESENT" and not isinstance(ev["value"], int)
    assert ev["metric"] == "Port_5762_State" and ev["band"] == "danger"
    assert ev["domain"] == "command" and ev["channel"] == "port_5762_read"


# --------------------------------------------------------------------------- #
# (b) correlate -> target=peer 인 전용 BACKDOOR_5762 kind
# --------------------------------------------------------------------------- #
def test_correlate_emits_backdoor_5762_kind_and_peer_target():
    out = correlate({"evidence": [_ev_5762()], "tick_i": 1})
    incs = out.get("incidents", [])
    b = [i for i in incs if i.kind == "BACKDOOR_5762"]
    assert len(b) == 1, [i.kind for i in incs]
    inc = b[0]
    assert inc.members == ["Port_5762_State"]             # 5762 metric 으로 식별
    assert inc.target == PEER                             # peer IP (e.source 에서), 값 아님
    # NON-5762 danger metric 은 전용 kind 를 받아선 안 됨 (self-DoS 오라우팅 없음)
    other = correlate({"evidence": [SensorEv(source_id="rtt", metric="RTT_ms",
                                             band="danger", source="x")], "tick_i": 1})
    assert all(i.kind != "BACKDOOR_5762" for i in other.get("incidents", []))


# --------------------------------------------------------------------------- #
# (c) select_policy 는 backdoor_drop Action 을 빌드
# --------------------------------------------------------------------------- #
def test_select_policy_builds_backdoor_drop_action():
    inc = Incident(id="sig-1-Port_5762_State", kind="BACKDOOR_5762", score=1.0,
                   members=["Port_5762_State"], target=PEER)
    cands = _candidates({"incidents": [inc]})
    assert len(cands) == 1
    a = cands[0]
    assert a.recovery_type == "backdoor_drop"
    assert a.tool_id == "nsenter_input_drop"
    assert a.params["target"] == PEER
    assert a.params["target_kind"] == "ip"               # peer 는 IPv4 selector
    assert a.params["enforce_at"] == "uav_ue"            # config 고정된 5762 LISTEN netns


# --------------------------------------------------------------------------- #
# (d) 통합: 전체 체인 -> NON-inert uav_ue-netns DROP argv
# --------------------------------------------------------------------------- #
def _verified_world(**over) -> WorldState:
    """uav_ue (enforce chokepoint)와 peer source 가 모두 별개로 verify 되는 world."""
    base = dict(
        config_version=CFG,
        role_verified={"uav_ue": True},
        pid={"uav_ue": UAV_PID},
        ip_map={},
        # peer IP 는 verified 바인딩으로 해석됨 (attacker_ue tun 10.45.0.13)
        roles={"attacker_ue": RoleBinding(role="attacker_ue", container="attacker_ue",
                                          ip=PEER, verified=True)},
    )
    base.update(over)
    return WorldState(**base)


def _drive_to_chosen(world: WorldState):
    """evidence -> correlate -> select_policy -> rank_recovery -> chosen Intent (+risk/reversible)."""
    state: dict = {"evidence": [_ev_5762()], "tick_i": 1,
                   "config_version": CFG, "worldstate": world}
    state["incidents"] = correlate(state).get("incidents", [])
    state["legal_actions"] = select_policy(state)["legal_actions"]
    rr = rank_recovery(state)
    return rr, state


def test_integration_penetrates_to_noninert_uav_ue_drop():
    world = _verified_world()
    rr, state = _drive_to_chosen(world)
    # legality 가 backdoor_drop 후보를 승인 (enforce_at=uav_ue verified)
    assert any(a.recovery_type == "backdoor_drop" for a in state["legal_actions"])
    chosen = rr["chosen_action"]
    assert chosen is not None and chosen.rule == "backdoor_drop"
    assert chosen.tool_id == "nsenter_input_drop"
    assert chosen.enforce_at == "uav_ue" and chosen.target == PEER and chosen.target_kind == "ip"

    ctrl = ResponseController(backend=Backend(allow_live=False))
    plan = ctrl.plan(chosen, world, tick_i=1,
                     risk=rr["chosen_action_risk"], reversible=rr["chosen_action_reversible"])
    assert plan.tier2 == "AUTO" and not plan.skip and not plan.operator_required
    assert plan.exec_request is not None, plan.reason         # NON-inert (two distinct verified endpoints)
    argv = plan.exec_request.argv
    # uav_ue netns (5762 LISTEN 소유자)에 진입, attacker SOURCE 를 drop
    assert argv[:5] == ["nsenter", "--target", str(UAV_PID), "--net", "--"]
    assert argv[-4:] == ["-s", PEER, "-j", "DROP"]
    # run 시 DRY (operator-go 유보), 그러나 실제 argv 는 조립됨
    res = ctrl.run_plan(plan)
    assert res.dry_run and res.ok


# --------------------------------------------------------------------------- #
# (e) 대조: WRONG enforce_at (web_backend)는 잘못된 netns pid 를 대상으로
# --------------------------------------------------------------------------- #
def test_contrast_wrong_enforce_at_uses_wrong_chokepoint():
    """enforce_at 이 web_backend (다른 netns)를 가리키면, DROP 은 uav_ue 가 아닌 web_backend 의
    pid 에 진입 — 5762 backdoor 는 uav_ue 의 netns 에 존재하므로 이를 놓침. config 고정
    enforce_at=uav_ue 가 핵심임을 증명 (mis-config 는 DROP 을 조용히 오라우팅)."""
    WEB_PID = 2002
    world = _verified_world(role_verified={"uav_ue": True, "web_backend": True},
                            pid={"uav_ue": UAV_PID, "web_backend": WEB_PID})
    # 올바르게 선택된 intent 를 취한 뒤 enforce_at 을 web_backend 로 MIS-POINT
    rr, _ = _drive_to_chosen(world)
    chosen = rr["chosen_action"]
    misrouted = chosen.model_copy(update={"enforce_at": "web_backend"})

    ctrl = ResponseController(backend=Backend(allow_live=False))
    plan = ctrl.plan(misrouted, world, tick_i=1, risk="MED", reversible=True)
    assert plan.exec_request is not None                      # 여전히 유효한 (그러나 WRONG) argv
    argv = plan.exec_request.argv
    assert argv[:3] == ["nsenter", "--target", str(WEB_PID)]  # web_backend netns — WRONG chokepoint
    assert str(UAV_PID) not in argv[:3]                       # uav_ue 5762 netns 아님


# --------------------------------------------------------------------------- #
# (f) legality 동적 바인딩
# --------------------------------------------------------------------------- #
def test_legality_dynamic_binding_resolves_enforce_at():
    a = Action(tool_id="nsenter_input_drop", recovery_type="backdoor_drop",
               params={"target": PEER, "target_kind": "ip", "enforce_at": "uav_ue"})
    # registry alias ('target'/'gcs')는 action 의 enforce_at 컨테이너로 해석
    assert _resolve_role_key(a, "target") == "uav_ue"
    # role_verified[<해석된 컨테이너>] 가 True 일 때만 legal
    assert is_legal(a, WorldState(config_version=CFG, role_verified={"uav_ue": True}), CFG)[0]
    ok, reason = is_legal(a, WorldState(config_version=CFG, role_verified={"web_backend": True}), CFG)
    assert not ok and "role_verified.target" in reason        # uav_ue 미검증 -> illegal
    # enforce_at 부재 시 `target` 으로 폴백
    assert _resolve_role_key(Action(tool_id="nsenter_input_drop",
                                    params={"target": "gcs_proxy"}), "x") == "gcs_proxy"
    # 구체적 컨테이너 selector 없음 -> "" -> fail-closed (허구 alias 는 절대 승인 안 함)
    assert _resolve_role_key(Action(tool_id="nsenter_input_drop", params={}), "target") == ""


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
