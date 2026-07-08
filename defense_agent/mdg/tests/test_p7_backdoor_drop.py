"""test_p7_backdoor_drop — 관통(end-to-end) regression for the autonomous 5762 backdoor DROP.

Locks the full autonomous path introduced in steps 1-10 so a later refactor cannot silently
break any link of the chain:

  WebProbe(uav_ue netns) --source=peer--> ingest.SensorEv.source
    -> correlate  : Port_5762_State(danger) -> Incident(kind=BACKDOOR_5762, target=peer)
    -> select_policy: BACKDOOR_5762 -> Action(recovery_type=backdoor_drop, enforce_at=uav_ue,
                                              target=peer, target_kind=ip)
    -> legality    : registry alias 'role_verified.target' DYNAMICALLY binds to enforce_at=uav_ue
    -> rank_recovery: backdoor_drop (succ 0.85 >= 0.70) -> chosen Intent (selector carried)
    -> response.plan: TWO DISTINCT verified endpoints -> NON-inert argv
                      nsenter --target <uav_ue pid> ... -s <peer> -j DROP

Coverage:
  (a) WebProbe emits a peer SOURCE (an attribution selector), NOT a count.
  (b) correlate emits the dedicated BACKDOOR_5762 kind with target=peer (not the metric value).
  (c) select_policy._candidates builds the backdoor_drop Action (rtype/target/target_kind/enforce_at).
  (d) integration: a verified world drives the whole chain to a NON-inert uav_ue-netns DROP argv.
  (e) contrast: a WRONG enforce_at (web_backend, a DIFFERENT netns) sends the DROP into the wrong
      chokepoint pid — proving enforce_at=uav_ue in config is load-bearing (5762 lives in uav_ue).
  (f) legality dynamic binding: the alias resolves to enforce_at (else target); unverified -> illegal.

Runs offline (Backend.allow_live=False / mock). Executable as a script or under pytest.
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
PEER = "10.45.0.13"            # live fact: attacker_ue tun IP (the 5762 peer)
UAV_PID = 1001                 # uav_ue netns pid (owns the 5762 LISTEN)

# an ss ESTAB row: local = uav_ue:5762, peer = attacker:44321
_SS = "ESTAB 0 0 10.45.0.2:5762 10.45.0.13:44321\n"


def _ev_5762(source: str = PEER) -> SensorEv:
    """The WebProbe 5762 danger evidence as it arrives at correlate (post-ingest)."""
    return SensorEv(source_id="web_5762_probe", metric="Port_5762_State",
                    value="ESTAB_PRESENT", band="danger", domain="command",
                    channel="port_5762_read", source=source, verified=True)


# --------------------------------------------------------------------------- #
# (a) WebProbe emits a peer SOURCE, not a count
# --------------------------------------------------------------------------- #
def test_webprobe_emits_peer_source_not_count():
    # the two parsers are DISTINCT: established=count, peer=attribution IP
    assert parse_ss_established(_SS, 5762) == 1            # count (int)
    assert parse_ss_peer(_SS, 5762) == PEER               # peer IP (str), NOT the count
    # the collector emits the peer as `source`, with an enum value (never a count)
    col = WebProbeCollector(
        queue.Queue(), Keyring(keys={"k1": b"k"}), "k1",
        backend=Backend(mode="mock", mock_table={":5762": _SS}),
        netns_prefix=["nsenter", "--target", str(UAV_PID), "--net", "--"])
    out = col.collect()
    assert len(out) == 1
    ev = out[0]
    assert ev["source"] == PEER                           # attribution selector (peer), not a count
    assert ev["value"] == "ESTAB_PRESENT" and not isinstance(ev["value"], int)
    assert ev["metric"] == "Port_5762_State" and ev["band"] == "danger"
    assert ev["domain"] == "command" and ev["channel"] == "port_5762_read"


# --------------------------------------------------------------------------- #
# (b) correlate -> dedicated BACKDOOR_5762 kind with target=peer
# --------------------------------------------------------------------------- #
def test_correlate_emits_backdoor_5762_kind_and_peer_target():
    out = correlate({"evidence": [_ev_5762()], "tick_i": 1})
    incs = out.get("incidents", [])
    b = [i for i in incs if i.kind == "BACKDOOR_5762"]
    assert len(b) == 1, [i.kind for i in incs]
    inc = b[0]
    assert inc.members == ["Port_5762_State"]             # identified by the 5762 metric
    assert inc.target == PEER                             # peer IP (from e.source), NOT the value
    # a NON-5762 danger metric must NOT get the dedicated kind (no self-DoS mis-route)
    other = correlate({"evidence": [SensorEv(source_id="rtt", metric="RTT_ms",
                                             band="danger", source="x")], "tick_i": 1})
    assert all(i.kind != "BACKDOOR_5762" for i in other.get("incidents", []))


# --------------------------------------------------------------------------- #
# (c) select_policy builds the backdoor_drop Action
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
    assert a.params["target_kind"] == "ip"               # peer is an IPv4 selector
    assert a.params["enforce_at"] == "uav_ue"            # config-pinned 5762 LISTEN netns


# --------------------------------------------------------------------------- #
# (d) integration: full chain -> NON-inert uav_ue-netns DROP argv
# --------------------------------------------------------------------------- #
def _verified_world(**over) -> WorldState:
    """A world where uav_ue (enforce chokepoint) and the peer source both verify DISTINCTLY."""
    base = dict(
        config_version=CFG,
        role_verified={"uav_ue": True},
        pid={"uav_ue": UAV_PID},
        ip_map={},
        # the peer IP resolves to a verified binding (attacker_ue tun 10.45.0.13)
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
    # legality admitted the backdoor_drop candidate (enforce_at=uav_ue verified)
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
    # enters the uav_ue netns (the 5762 LISTEN owner), drops the attacker SOURCE
    assert argv[:5] == ["nsenter", "--target", str(UAV_PID), "--net", "--"]
    assert argv[-4:] == ["-s", PEER, "-j", "DROP"]
    # DRY at run (operator-go 유보), but a real argv was assembled
    res = ctrl.run_plan(plan)
    assert res.dry_run and res.ok


# --------------------------------------------------------------------------- #
# (e) contrast: a WRONG enforce_at (web_backend) targets the wrong netns pid
# --------------------------------------------------------------------------- #
def test_contrast_wrong_enforce_at_uses_wrong_chokepoint():
    """If enforce_at points at web_backend (a DIFFERENT netns), the DROP enters web_backend's pid,
    NOT uav_ue's — the 5762 backdoor lives in uav_ue's netns, so this misses it. Proves the
    config-pinned enforce_at=uav_ue is load-bearing (a mis-config silently mis-routes the DROP)."""
    WEB_PID = 2002
    world = _verified_world(role_verified={"uav_ue": True, "web_backend": True},
                            pid={"uav_ue": UAV_PID, "web_backend": WEB_PID})
    # take the correctly-chosen intent, then MIS-POINT its enforce_at at web_backend
    rr, _ = _drive_to_chosen(world)
    chosen = rr["chosen_action"]
    misrouted = chosen.model_copy(update={"enforce_at": "web_backend"})

    ctrl = ResponseController(backend=Backend(allow_live=False))
    plan = ctrl.plan(misrouted, world, tick_i=1, risk="MED", reversible=True)
    assert plan.exec_request is not None                      # still a valid (but WRONG) argv
    argv = plan.exec_request.argv
    assert argv[:3] == ["nsenter", "--target", str(WEB_PID)]  # web_backend netns — the WRONG chokepoint
    assert str(UAV_PID) not in argv[:3]                       # NOT the uav_ue 5762 netns


# --------------------------------------------------------------------------- #
# (f) legality dynamic binding
# --------------------------------------------------------------------------- #
def test_legality_dynamic_binding_resolves_enforce_at():
    a = Action(tool_id="nsenter_input_drop", recovery_type="backdoor_drop",
               params={"target": PEER, "target_kind": "ip", "enforce_at": "uav_ue"})
    # the registry alias ('target'/'gcs') resolves to the action's enforce_at container
    assert _resolve_role_key(a, "target") == "uav_ue"
    # legal iff role_verified[<resolved container>] is True
    assert is_legal(a, WorldState(config_version=CFG, role_verified={"uav_ue": True}), CFG)[0]
    ok, reason = is_legal(a, WorldState(config_version=CFG, role_verified={"web_backend": True}), CFG)
    assert not ok and "role_verified.target" in reason        # uav_ue unverified -> illegal
    # fallback to `target` when enforce_at is absent
    assert _resolve_role_key(Action(tool_id="nsenter_input_drop",
                                    params={"target": "gcs_proxy"}), "x") == "gcs_proxy"
    # no concrete container selector -> "" -> fail-closed (fictional alias never admits)
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
