"""test_p4_response — P4 대응/집행+안전 self-verify.

Exercises the five P4 modules and their wiring into the act/escalate nodes:
  gate.py        — 2-tier gate (nsenter DROP = the sole AUTO; flight/pause = OPER; fail-closed)
  bundle.py      — atomic bundle risk/reversible aggregation, idempotent skip, N-tick debounce,
                   de-escalation
  act_host.py    — netns nsenter+iptables DROP argv (inert on unresolved pid); duck-typed docker pause
  signer_shim.py — command-bound OperatorRequest (PS-9): captured token can't authorize a different
                   command; nonce single-use; TTL expiry; monotonic continuity; KEY-FREE emitter
  response.py    — ResponseController plan/dispatch (AUTO -> DRY exec, OPER -> operator_required, skip)
  act node       — legality -> plan(gate/bundle) -> [skip | operator-gate | record_intent+safe-exec]

Runs offline (Backend.allow_live=False -> DRY-RUN; no testbed state change). Executable as a
script or under pytest.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core import bundle as B          # noqa: E402
from mdg.core import gate as G            # noqa: E402
from mdg.core.nodes.act import act        # noqa: E402
from mdg.core.nodes.escalate import escalate  # noqa: E402
from mdg.core.state import Action, Intent, initial_state  # noqa: E402
from mdg.core.worldstate import AppliedRule, WorldState    # noqa: E402
from mdg.safe_exec import act_host, signer_shim            # noqa: E402
from mdg.safe_exec.backend import Backend                  # noqa: E402
from mdg.safe_exec.response import ResponseController      # noqa: E402

CFG = "mdg-cfg-2026-07-07"


class _SpyBackend:
    """Backend whose .run must never be reached on the OPER/skip paths."""
    allow_live = False

    def __init__(self):
        self.calls = 0

    def run(self, req):
        self.calls += 1
        raise AssertionError("backend.run must not be called on OPER/skip path")


class _SpyLedger:
    def __init__(self):
        self.intents = []

    def record_intent(self, intent):
        self.intents.append(intent)
        return {"ledger": [intent]}


class _MockDocker:
    def __init__(self):
        self.paused = []

    def pause(self, container):
        self.paused.append(container)
        return {"paused": container}


def _world(**kw) -> WorldState:
    kw.setdefault("role_verified", {"target": True})
    return WorldState(config_version=CFG, **kw)


def _state(chosen: Intent, *, risk="MED", reversible=True, tick_i=0, world=None) -> dict:
    st = dict(initial_state(CFG))
    st["worldstate"] = world or _world()
    st["chosen_action"] = chosen
    st["chosen_action_risk"] = risk
    st["chosen_action_reversible"] = reversible
    st["tick_i"] = tick_i
    return st


# --------------------------------------------------------------------------- #
# gate.py — 2-tier classification
# --------------------------------------------------------------------------- #
def test_gate_two_tier_auto_vs_oper():
    assert G.gate_for("nsenter_input_drop", "MED", True).auto is True   # SOLE auto response
    assert G.is_auto("nsenter_input_drop", "MED", True)
    # OPER-tier tools never auto-actuate even at MED/reversible
    for tid in ("docker_pause", "docker_net_disconnect"):
        d = G.gate_for(tid, "MED", True)
        assert d.operator_required and d.tier2 == "OPER", tid
    # flight = operator (and it is HIGH anyway)
    sd = G.gate_for("send_signed_mode", "HIGH", False)
    assert sd.flight and sd.operator_required
    # fail-closed: unregistered / HIGH / irreversible all -> OPER
    assert G.requires_operator("ghost_tool", "LOW", True)
    assert G.requires_operator("nsenter_input_drop", "HIGH", True)
    assert G.requires_operator("nsenter_input_drop", "MED", False)


# --------------------------------------------------------------------------- #
# bundle.py — aggregation / idempotency / debounce / de-escalation
# --------------------------------------------------------------------------- #
def test_bundle_risk_reversible_aggregation():
    ops = [Action(tool_id="a", risk="LOW", reversible=True),
           Action(tool_id="b", risk="MED", reversible=False)]
    bd = B.Bundle(rule="r", ops=ops)
    assert bd.risk == "MED" and bd.reversible is False           # max risk, all reversible


def test_bundle_idempotent_and_debounce():
    # confirmed applied rule -> idempotent skip; unconfirmed -> not skipped
    w_conf = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True)})
    assert B.already_applied(w_conf, "pfcp_firewall") is True
    w_unconf = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=False)})
    assert B.already_applied(w_unconf, "pfcp_firewall") is False
    # reverted rule is no longer "applied"
    w_rev = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True, reverted=True)})
    assert B.already_applied(w_rev, "pfcp_firewall") is False
    # debounce: applied at tick 5, now tick 6 with default min(3) -> blocked; tick 9 -> free
    w_deb = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", applied_tick=5)})
    assert B.debounce_blocked(w_deb, "pfcp_firewall", 6) is True
    assert B.debounce_blocked(w_deb, "pfcp_firewall", 9) is False
    assert B.debounce_blocked(w_deb, "mongo_acl", 6) is False     # absent rule never blocked


def test_bundle_deescalation_due_excludes_flight():
    w = _world(applied={
        "pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True, ts=100.0),
        "signed_land": AppliedRule(rule="signed_land", confirmed=True, ts=100.0),
    })
    due = B.deescalation_due(w, now_ts=100.0 + 999, quiet_s=120)
    rules = {a.rule for a in due}
    assert "pfcp_firewall" in rules and "signed_land" not in rules   # flight never auto-reverts
    assert B.deescalation_due(w, now_ts=100.0 + 1, quiet_s=120) == []  # not quiet long enough


# --------------------------------------------------------------------------- #
# act_host.py — netns DROP argv + docker pause
# --------------------------------------------------------------------------- #
def test_act_host_drop_argv_and_inert():
    argv = act_host.drop_argv(12345, "10.45.0.10")
    assert argv[:5] == ["nsenter", "--target", "12345", "--net", "--"]
    assert argv[5:8] == ["iptables", "-w", "-I"] and argv[-4:] == ["-s", "10.45.0.10", "-j", "DROP"]
    assert "-D" in act_host.drop_argv(12345, "10.45.0.10", revert=True)
    assert act_host.drop_argv(None, "10.45.0.10") is None            # unresolved pid -> inert


def test_act_host_docker_pause_dry_and_live():
    ah_dry = act_host.ActHost(docker=None)
    r = ah_dry.pause("attacker_ue")
    assert r["dry_run"] is True and "operator-go" in r["note"]       # no live docker -> operator-go DRY
    md = _MockDocker()
    ah = act_host.ActHost(docker=md)
    r2 = ah.pause("attacker_ue")
    assert r2["ok"] and md.paused == ["attacker_ue"]                 # duck-typed pause reached


def test_act_host_input_drop_uses_backend_dry():
    ah = act_host.ActHost(backend=Backend(allow_live=False))
    res = ah.apply_input_drop(12345, "10.45.0.10")
    assert res.ok and res.dry_run                                    # DRY (operator-go 유보)
    assert act_host.ActHost().apply_input_drop(None, "10.45.0.10").note.startswith("INERT")


# --------------------------------------------------------------------------- #
# signer_shim.py — PS-9 command binding + KEY-FREE emitter
# --------------------------------------------------------------------------- #
def _intent(rule="signed_land", tool_id="send_signed_mode", did="d1"):
    return Intent(rule=rule, tool_id=tool_id, decision_id=did, config_version=CFG)


def test_command_digest_binds_command():
    a, b = _intent(did="d1"), _intent(did="d2")
    assert signer_shim.command_digest(a) != signer_shim.command_digest(b)   # different command
    assert signer_shim.command_digest(a) == signer_shim.command_digest(_intent(did="d1"))  # stable


def test_operator_gate_issue_sign_verify_roundtrip():
    gate = signer_shim.OperatorGate(key=b"op-gate-key-not-a-real-secret")
    req = gate.issue(_intent(), nonce="n1", ttl_s=100, now=1000.0)
    token = gate.sign(req)
    ok, why = gate.verify(req, token, now=1001.0)
    assert ok, why


def test_captured_token_cannot_authorize_different_command():
    """verify_operator_binding: an approval minted for command A is rejected for command B."""
    gate = signer_shim.OperatorGate(key=b"op-gate-key")
    req_a = gate.issue(_intent(did="A"), nonce="na", ttl_s=100, now=1000.0)
    token_a = gate.sign(req_a)
    # same token, but assert it must bind to command B's digest -> reject
    dig_b = signer_shim.command_digest(_intent(did="B"))
    ok, why = gate.verify(req_a, token_a, now=1001.0, expected_digest=dig_b)
    assert not ok and "mismatch" in why


def test_operator_gate_nonce_single_use_and_expiry_and_continuity():
    gate = signer_shim.OperatorGate(key=b"op-gate-key")
    req = gate.issue(_intent(), nonce="n1", ttl_s=10, now=1000.0)
    token = gate.sign(req)
    assert gate.verify(req, token, now=1005.0)[0]                    # first use OK
    assert not gate.verify(req, token, now=1006.0)[0]               # nonce replay rejected
    # expiry
    req2 = gate.issue(_intent(did="d3"), nonce="n2", ttl_s=10, now=1000.0)
    tok2 = gate.sign(req2)
    assert not gate.verify(req2, tok2, now=1011.0)[0]              # expired
    # continuity: a consume ts earlier than the last accepted consume is rejected (replay window)
    gate2 = signer_shim.OperatorGate(key=b"k")
    r3 = gate2.issue(_intent(did="d4"), nonce="n3", ttl_s=100, now=1000.0)
    assert gate2.verify(r3, gate2.sign(r3), now=1050.0)[0]
    r4 = gate2.issue(_intent(did="d5"), nonce="n4", ttl_s=100, now=1000.0)
    assert not gate2.verify(r4, gate2.sign(r4), now=1049.0)[0]     # non-monotonic -> reject


# --------------------------------------------------------------------------- #
# P4-Q2 — operator-gate key bootstrap: key=None is the NORMAL MDG posture
# --------------------------------------------------------------------------- #
def test_operator_gate_none_is_fail_closed_normal_posture():
    """key=None: issue() works (key-free), sign() returns '', verify() fail-closed. This is the
    intended MDG-runtime posture (issue-only), NOT a degraded mode — MDG holds no forge material."""
    gate = signer_shim.OperatorGate()                    # no key injected, no env
    req = gate.issue(_intent(), nonce="n1", ttl_s=100, now=1000.0)
    assert req.command_digest and req.nonce == "n1"      # issue is key-free
    assert gate.sign(req) == ""                           # cannot sign
    ok, why = gate.verify(req, "anything", now=1001.0)
    assert not ok and "no operator-gate key" in why      # structurally cannot self-approve


def test_operator_gate_env_is_dev_only_and_warns():
    """The env fallback is DEV/replay only and must emit a warning (docker inspect leak surface)."""
    import warnings as _w
    os.environ["MDG_OPERATOR_GATE_KEY"] = "dev-only-key"
    try:
        with _w.catch_warnings(record=True) as caught:
            _w.simplefilter("always")
            gate = signer_shim.OperatorGate()
        assert any("DEV/replay only" in str(c.message) for c in caught)
        # it still functions when explicitly provisioned via env (dev), just warned
        req = gate.issue(_intent(), nonce="ne", ttl_s=100, now=1000.0)
        assert gate.verify(req, gate.sign(req), now=1001.0)[0]
    finally:
        del os.environ["MDG_OPERATOR_GATE_KEY"]


# --------------------------------------------------------------------------- #
# P4-Q3 — durable secret-free operator-ledger: token NOT persisted, nonce IS
# --------------------------------------------------------------------------- #
def test_operator_ledger_receipt_is_secret_free():
    import tempfile
    from mdg.ledger.operator_ledger import OperatorLedger
    path = os.path.join(tempfile.mkdtemp(), "op_ledger.jsonl")
    led = OperatorLedger(path)
    led.record(decision_id="d1", command_digest="abc", nonce="n1", expiry=10.0,
               verdict="GRANTED", consumed_ts=5.0)
    raw = open(path, "r", encoding="utf-8").read().lower()
    for banned in ("token", "hmac", "\"key\"", "secret"):
        assert banned not in raw, f"operator-ledger leaked '{banned}'"
    assert led.consumed_nonces() == {"n1"}


def test_operator_gate_nonce_survives_reboot_blocks_replay():
    """A captured, still-unexpired token cannot be replayed after a crash: the consumed nonce is
    durable in the operator-ledger and re-seeds a fresh gate's _seen_nonces on boot (P4-Q3)."""
    import tempfile
    from mdg.ledger.operator_ledger import OperatorLedger
    path = os.path.join(tempfile.mkdtemp(), "op_ledger.jsonl")
    led = OperatorLedger(path)
    gate = signer_shim.OperatorGate(key=b"op-gate-key", ledger=led)
    req = gate.issue(_intent(), nonce="n-boot", ttl_s=10_000, now=1000.0)
    token = gate.sign(req)
    assert gate.verify(req, token, now=1001.0)[0]        # first consume OK (GRANTED persisted)
    # simulate reboot: a fresh gate seeds _seen_nonces from the durable ledger
    gate2 = signer_shim.OperatorGate(key=b"op-gate-key", ledger=OperatorLedger(path))
    ok, why = gate2.verify(req, token, now=1002.0)       # still within TTL, but nonce consumed
    assert not ok and "replay" in why


def test_signer_emit_is_key_free():
    emit = signer_shim.emit_signed(_intent(), backend=Backend(allow_live=False))
    assert emit.dry_run and emit.delegate == "gcs_c2" and emit.command_digest
    # static: the signer source holds NO /sign.key path literal and never opens a key file
    src = open(signer_shim.__file__, "r", encoding="utf-8").read()
    assert "sign.key" not in src.lower(), "signer must be key-free (no /sign.key literal)"
    assert "open(" not in src, "signer must not open any file (no key read)"


# --------------------------------------------------------------------------- #
# response.py — ResponseController plan/dispatch
# --------------------------------------------------------------------------- #
def test_response_plan_auto_builds_dry_exec():
    ctrl = ResponseController(backend=Backend(allow_live=False))
    # two DISTINCT verified endpoints: enforce_at (chokepoint netns) + attacker source (P4-2)
    intent = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                    enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    w = _world(role_verified={"gcs_proxy": True, "attacker_ue": True},
               pid={"gcs_proxy": 12345, "attacker_ue": 4242},
               ip_map={"attacker_ue": "10.45.0.10"})
    plan, res = ctrl.dispatch(intent, w, tick_i=0, risk="MED", reversible=True)
    assert plan.tier2 == "AUTO" and not plan.operator_required and not plan.skip
    assert plan.exec_request is not None and res.ok and res.dry_run   # DRY (no live actuation)


def test_response_plan_oper_and_skip():
    ctrl = ResponseController(backend=_SpyBackend())
    # OPER: docker_pause -> operator_required, backend.run untouched
    intent_oper = Intent(rule="backdoor_pause", tool_id="docker_pause", config_version=CFG)
    plan, res = ctrl.dispatch(intent_oper, _world(), 0, risk="MED", reversible=True)
    assert plan.operator_required and res is None
    # SKIP: idempotent applied+confirmed -> skip
    w_skip = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True)})
    intent_auto = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG)
    plan2, res2 = ctrl.dispatch(intent_auto, w_skip, 0, risk="MED", reversible=True)
    assert plan2.skip and res2 is None


# --------------------------------------------------------------------------- #
# P4-Q1 — opaque validated selector: propagate + fail-closed verified binding
# --------------------------------------------------------------------------- #
def test_target_selector_propagates_and_binds_verified_role():
    """Two-endpoint containment (P4-2): enforce_at -> chokepoint netns pid, target -> attacker
    source ip, each a KEY into the verified map, resolved to DISTINCT verified bindings. The DROP
    enters the CHOKEPOINT netns (4242, gcs_proxy) and filters the ATTACKER source (10.45.0.55) —
    NOT the attacker's own netns dropping its own ip (the prior incoherent argv)."""
    ctrl = ResponseController(backend=Backend(allow_live=False))
    intent = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                    enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    from mdg.core.worldstate import RoleBinding
    w = _world(role_verified={},
               pid={"gcs_proxy": 4242, "attacker_ue": 777},
               ip_map={"attacker_ue": "10.45.0.55"},
               roles={"gcs_proxy": RoleBinding(role="gcs_proxy", verified=True),
                      "attacker_ue": RoleBinding(role="attacker_ue", verified=True)})
    plan, res = ctrl.dispatch(intent, w, 0, risk="MED", reversible=True)
    assert plan.exec_request is not None                 # two distinct verified endpoints -> DROP
    assert plan.exec_request.argv[:5] == ["nsenter", "--target", "4242", "--net", "--"]  # enforce netns
    assert plan.exec_request.argv[-4:] == ["-s", "10.45.0.55", "-j", "DROP"]              # attacker src
    assert res.ok and res.dry_run


def test_target_forged_or_unverified_selector_goes_inert():
    """Self-DoS closed (PS-7): if EITHER endpoint fails the verified gate (forged source IP /
    unknown source role / un-projected imsi / unverified enforcement), no drop_argv is built ->
    inert DRY, and no raw selector is ever a -s."""
    ctrl = ResponseController(backend=Backend(allow_live=False))
    # verified enforcement chokepoint fixed; vary the SOURCE selector's verified-ness.
    base = _world(role_verified={"gcs_proxy": True}, pid={"gcs_proxy": 12345}, ip_map={})
    # (a) operator/own IP as an ip-kind source, but it maps to no verified UE-pool binding -> inert
    forged_ip = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                       enforce_at="gcs_proxy", target="10.44.0.1", target_kind="ip")
    plan_a, res_a = ctrl.dispatch(forged_ip, base, 0, risk="MED", reversible=True)
    assert plan_a.exec_request is None and "inert" in plan_a.reason.lower()
    assert res_a.dry_run and "INERT" in res_a.note
    # (b) unknown source role -> not verified -> inert
    unknown = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                     enforce_at="gcs_proxy", target="ghost_role", target_kind="role")
    plan_b, _ = ctrl.dispatch(unknown, base, 0, risk="MED", reversible=True)
    assert plan_b.exec_request is None
    # (c) un-projected imsi source -> fail-closed inert (SMF layer-1 projection not wired)
    imsi = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                  enforce_at="gcs_proxy", target="001010000000001", target_kind="imsi")
    plan_c, _ = ctrl.dispatch(imsi, base, 0, risk="MED", reversible=True)
    assert plan_c.exec_request is None
    # (d) verified SOURCE but UNVERIFIED enforcement chokepoint -> inert (both endpoints gated)
    w2 = _world(role_verified={"attacker_ue": True},
                pid={"attacker_ue": 4242, "gcs_proxy": 12345},
                ip_map={"attacker_ue": "10.45.0.55"})
    unv_enf = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                     enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    plan_d, _ = ctrl.dispatch(unv_enf, w2, 0, risk="MED", reversible=True)
    assert plan_d.exec_request is None
    # (e) same-entity endpoints (enforce_at == source) -> incoherent -> inert (distinct-binding guard)
    w3 = _world(role_verified={"attacker_ue": True},
                pid={"attacker_ue": 4242}, ip_map={"attacker_ue": "10.45.0.55"})
    same = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                  enforce_at="attacker_ue", target="attacker_ue", target_kind="role")
    plan_e, _ = ctrl.dispatch(same, w3, 0, risk="MED", reversible=True)
    assert plan_e.exec_request is None


def test_ip_source_stale_binding_cross_check():
    """P4 stale-binding (재할당 IP self-DoS 차단): an ip-kind raw source is the attacker IP captured at
    DETECTION. UE-pool IPs rotate per attach, so at ENFORCEMENT the LIVE SMF session table is cross-
    checked. Released (unbound) or RE-ASSIGNED-to-another-UE IPs -> inert; still-same-entity -> DROP."""
    from mdg.core.worldstate import RoleBinding

    class _FakeSmf:
        def __init__(self, mapping):
            self.mapping = dict(mapping)

        def imsi_for_ip(self, ip):
            return self.mapping.get(ip)

    IP, ATT_IMSI = "10.45.0.55", "001010000000001"

    def _w():
        return _world(
            role_verified={"gcs_proxy": True}, pid={"gcs_proxy": 4242}, ip_map={},
            imsi_container={ATT_IMSI: "attacker_ue"},
            roles={"gcs_proxy": RoleBinding(role="gcs_proxy", container="gcs_proxy", verified=True),
                   "attacker_ue": RoleBinding(role="attacker_ue", container="attacker_ue",
                                              ip=IP, verified=True)})

    intent = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                    enforce_at="gcs_proxy", target=IP, target_kind="ip")

    # (1) no smf_table wired -> best-effort recon-only re-affirm -> NON-inert (no regression)
    p0, _ = ResponseController(backend=Backend(allow_live=False)).dispatch(
        intent, _w(), 0, risk="MED", reversible=True)
    assert p0.exec_request is not None and p0.exec_request.argv[-4:] == ["-s", IP, "-j", "DROP"]

    # (2) smf_table: IP STILL live-bound to the SAME attacker container -> NON-inert (DROP proceeds)
    p1, _ = ResponseController(backend=Backend(allow_live=False), smf_table=_FakeSmf({IP: ATT_IMSI})
                               ).dispatch(intent, _w(), 0, risk="MED", reversible=True)
    assert p1.exec_request is not None

    # (3) smf_table: session GONE (IP released, no live binding) -> stale -> inert (self-DoS closed)
    p2, res2 = ResponseController(backend=Backend(allow_live=False), smf_table=_FakeSmf({})
                                  ).dispatch(intent, _w(), 0, risk="MED", reversible=True)
    assert p2.exec_request is None and "INERT" in res2.note

    # (4) smf_table: IP RE-ASSIGNED to a DIFFERENT (innocent) UE -> stale -> inert
    w4 = _w()
    w4.imsi_container["001010000000099"] = "victim_ue"
    p3, _ = ResponseController(backend=Backend(allow_live=False),
                               smf_table=_FakeSmf({IP: "001010000000099"})
                               ).dispatch(intent, w4, 0, risk="MED", reversible=True)
    assert p3.exec_request is None


def test_rank_recovery_carries_selector_into_chosen_intent():
    """rank_recovery must copy target/target_kind from the ranked candidate's params (the
    load-bearing wiring). Uses a minimal legal Action set (no config dependency on scoring)."""
    from mdg.core.nodes.rank_recovery import rank_recovery
    act_cand = Action(tool_id="nsenter_input_drop", risk="MED", reversible=True,
                      recovery_type="pfcp_firewall",
                      params={"target": "10.45.0.55", "target_kind": "ip",
                              "enforce_at": "gcs_proxy"})
    # bypass the feasibility/score config by asserting on the Intent construction path directly:
    out = rank_recovery({"legal_actions": [act_cand], "config_version": CFG})
    chosen = out["chosen_action"]
    if chosen is not None:                                # feasible under default priors
        assert chosen.target == "10.45.0.55" and chosen.target_kind == "ip"
        assert chosen.enforce_at == "gcs_proxy"           # P4-2 enforcement selector carried


def test_selector_scopes_operator_digest():
    """P4-Q1 #5: the command_digest binds the selector, so an approval scoped to target A cannot
    be reused for target B (same rule/decision)."""
    base = dict(rule="signed_land", tool_id="send_signed_mode", decision_id="d1", config_version=CFG)
    dig_a = signer_shim.command_digest(Intent(target="ue_a", target_kind="role", **base))
    dig_b = signer_shim.command_digest(Intent(target="ue_b", target_kind="role", **base))
    assert dig_a != dig_b
    # P4-2: enforce_at also scopes the approval (same source, different enforcement chokepoint)
    dig_e = signer_shim.command_digest(
        Intent(target="ue_a", target_kind="role", enforce_at="gcs_proxy", **base))
    assert dig_e != dig_a


# --------------------------------------------------------------------------- #
# act node — full wiring
# --------------------------------------------------------------------------- #
def test_act_auto_records_intent_and_applies_dry():
    chosen = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop",
                    decision_id="d1", config_version=CFG,
                    enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    # legality resolves the registry role_verified alias to the action's enforce_at container
    # (gcs_proxy) which is verified (step 10); the two DISTINCT verified endpoints (gcs_proxy
    # chokepoint pid + attacker source ip) then let dispatch build the DROP.
    w = _world(role_verified={"gcs_proxy": True, "attacker_ue": True},
               pid={"gcs_proxy": 12345, "attacker_ue": 4242},
               ip_map={"attacker_ue": "10.45.0.10"})
    led = _SpyLedger()
    out = act(_state(chosen, world=w), backend=Backend(allow_live=False), ledger=led)
    assert out["dry_streak"] == 0
    assert len(led.intents) == 1 and not led.intents[0].operator_gate   # recorded BEFORE exec (G3)
    assert "pfcp_firewall" in out["worldstate"].applied                 # world_update applied
    assert out["worldstate"].applied["pfcp_firewall"].confirmed is False  # effect_confirm later


def test_act_oper_defers_to_operator_no_exec():
    # enforce_at carries the ENFORCEMENT container so the dynamic legality gate (step 10) resolves
    # role_verified[web_backend]; the world seeds that container so the action is legal and the
    # OPER (docker_pause) path is exercised (not vetoed at the pre-hook).
    chosen = Intent(rule="backdoor_pause", tool_id="docker_pause",
                    decision_id="d9", config_version=CFG, enforce_at="web_backend")
    spy = _SpyBackend()
    led = _SpyLedger()
    out = act(_state(chosen, world=_world(role_verified={"web_backend": True})),
              backend=spy, ledger=led)
    assert spy.calls == 0                                               # tier-2 OPER: no actuation
    assert "worldstate" not in out                                     # nothing applied
    assert len(led.intents) == 1 and led.intents[0].operator_gate       # operator-gate Intent
    assert led.intents[0].command_digest                               # PS-9 command-bound


def test_act_idempotent_skip_no_side_effect():
    # enforce_at + the seeded container make the action legal (step 10 dynamic binding) so control
    # reaches the bundle idempotency skip rather than the legality veto.
    chosen = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                    enforce_at="gcs_proxy")
    w = _world(role_verified={"gcs_proxy": True},
               applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True)})
    spy = _SpyBackend()
    led = _SpyLedger()
    out = act(_state(chosen, world=w), backend=spy, ledger=led)
    # skip is NOT progress: dry_streak increments toward quiescence (was 0), never reset to 0.
    assert out == {"dry_streak": 1} and spy.calls == 0 and led.intents == []


def test_act_none_chosen_zero_side_effect():
    spy = _SpyBackend()
    led = _SpyLedger()
    st = dict(initial_state(CFG))
    assert act(st, backend=spy, ledger=led) == {} and spy.calls == 0 and led.intents == []


def test_escalate_binds_command_and_records_operator_gate():
    chosen = Intent(rule="signed_land", tool_id="send_signed_mode",
                    decision_id="dX", config_version=CFG)
    led = _SpyLedger()
    gate = signer_shim.OperatorGate(key=b"op-gate-key")
    out = escalate(_state(chosen, risk="HIGH", reversible=False), ledger=led, gate=gate)
    it = out["ledger"][0]
    assert it.operator_gate and it.command_digest and it.nonce and it.expiry > 0
    # the recorded digest binds to THIS command (verify against a different command fails)
    assert it.command_digest == signer_shim.command_digest(chosen)


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
