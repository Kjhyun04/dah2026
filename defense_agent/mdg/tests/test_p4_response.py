"""test_p4_response — P4 대응/집행+안전 self-verify.

act/escalate 노드로의 배선을 포함해 다섯 개 P4 모듈을 검증한다:
  gate.py        — 2-tier 게이트 (nsenter DROP = 유일한 AUTO; flight/pause = OPER; fail-closed)
  bundle.py      — 원자적 번들 risk/reversible 집계, 멱등 skip, N-tick debounce,
                   de-escalation
  act_host.py    — netns nsenter+iptables DROP argv (미해결 pid 시 무동작); duck-typed docker pause
  signer_shim.py — command-bound OperatorRequest (PS-9): 탈취 토큰은 다른 명령을 인가할 수 없음;
                   nonce 단일 사용; TTL 만료; 단조 연속성; KEY-FREE emitter
  response.py    — ResponseController plan/dispatch (AUTO -> DRY exec, OPER -> operator_required, skip)
  act 노드       — legality -> plan(gate/bundle) -> [skip | operator-gate | record_intent+safe-exec]

오프라인 실행 (Backend.allow_live=False -> DRY-RUN; 테스트베드 상태 변경 없음). 스크립트 또는
pytest 로 실행 가능.
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
    """OPER/skip 경로에서 .run 이 절대 도달해선 안 되는 Backend."""
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
# gate.py — 2-tier 분류
# --------------------------------------------------------------------------- #
def test_gate_two_tier_auto_vs_oper():
    assert G.gate_for("nsenter_input_drop", "MED", True).auto is True   # 유일한 auto 응답
    assert G.is_auto("nsenter_input_drop", "MED", True)
    # OPER-tier 도구는 MED/reversible 이라도 자동 작동하지 않음
    for tid in ("docker_pause", "docker_net_disconnect"):
        d = G.gate_for(tid, "MED", True)
        assert d.operator_required and d.tier2 == "OPER", tid
    # flight = operator (어차피 HIGH)
    sd = G.gate_for("send_signed_mode", "HIGH", False)
    assert sd.flight and sd.operator_required
    # fail-closed: 미등록 / HIGH / irreversible 모두 -> OPER
    assert G.requires_operator("ghost_tool", "LOW", True)
    assert G.requires_operator("nsenter_input_drop", "HIGH", True)
    assert G.requires_operator("nsenter_input_drop", "MED", False)


# --------------------------------------------------------------------------- #
# bundle.py — 집계 / 멱등성 / debounce / de-escalation
# --------------------------------------------------------------------------- #
def test_bundle_risk_reversible_aggregation():
    ops = [Action(tool_id="a", risk="LOW", reversible=True),
           Action(tool_id="b", risk="MED", reversible=False)]
    bd = B.Bundle(rule="r", ops=ops)
    assert bd.risk == "MED" and bd.reversible is False           # 최대 risk, 전부 reversible


def test_bundle_idempotent_and_debounce():
    # confirmed 적용 규칙 -> 멱등 skip; unconfirmed -> skip 안 함
    w_conf = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True)})
    assert B.already_applied(w_conf, "pfcp_firewall") is True
    w_unconf = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=False)})
    assert B.already_applied(w_unconf, "pfcp_firewall") is False
    # reverted 규칙은 더 이상 "applied" 아님
    w_rev = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True, reverted=True)})
    assert B.already_applied(w_rev, "pfcp_firewall") is False
    # debounce: tick 5 에 적용, 지금 tick 6 기본 min(3) -> 차단; tick 9 -> 해제
    w_deb = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", applied_tick=5)})
    assert B.debounce_blocked(w_deb, "pfcp_firewall", 6) is True
    assert B.debounce_blocked(w_deb, "pfcp_firewall", 9) is False
    assert B.debounce_blocked(w_deb, "mongo_acl", 6) is False     # 없는 규칙은 절대 차단 안 됨


def test_bundle_deescalation_due_excludes_flight():
    w = _world(applied={
        "pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True, ts=100.0),
        "signed_land": AppliedRule(rule="signed_land", confirmed=True, ts=100.0),
    })
    due = B.deescalation_due(w, now_ts=100.0 + 999, quiet_s=120)
    rules = {a.rule for a in due}
    assert "pfcp_firewall" in rules and "signed_land" not in rules   # flight 은 절대 자동 복귀 안 함
    assert B.deescalation_due(w, now_ts=100.0 + 1, quiet_s=120) == []  # 조용한 시간이 충분치 않음


# --------------------------------------------------------------------------- #
# act_host.py — netns DROP argv + docker pause
# --------------------------------------------------------------------------- #
def test_act_host_drop_argv_and_inert():
    argv = act_host.drop_argv(12345, "10.45.0.10")
    assert argv[:5] == ["nsenter", "--target", "12345", "--net", "--"]
    assert argv[5:8] == ["iptables", "-w", "-I"] and argv[-4:] == ["-s", "10.45.0.10", "-j", "DROP"]
    assert "-D" in act_host.drop_argv(12345, "10.45.0.10", revert=True)
    assert act_host.drop_argv(None, "10.45.0.10") is None            # 미해결 pid -> 무동작


def test_act_host_docker_pause_dry_and_live():
    ah_dry = act_host.ActHost(docker=None)
    r = ah_dry.pause("attacker_ue")
    assert r["dry_run"] is True and "operator-go" in r["note"]       # 라이브 docker 없음 -> operator-go DRY
    md = _MockDocker()
    ah = act_host.ActHost(docker=md)
    r2 = ah.pause("attacker_ue")
    assert r2["ok"] and md.paused == ["attacker_ue"]                 # duck-typed pause 도달


def test_act_host_input_drop_uses_backend_dry():
    ah = act_host.ActHost(backend=Backend(allow_live=False))
    res = ah.apply_input_drop(12345, "10.45.0.10")
    assert res.ok and res.dry_run                                    # DRY (operator-go 유보)
    assert act_host.ActHost().apply_input_drop(None, "10.45.0.10").note.startswith("INERT")


# --------------------------------------------------------------------------- #
# signer_shim.py — PS-9 명령 바인딩 + KEY-FREE emitter
# --------------------------------------------------------------------------- #
def _intent(rule="signed_land", tool_id="send_signed_mode", did="d1"):
    return Intent(rule=rule, tool_id=tool_id, decision_id=did, config_version=CFG)


def test_command_digest_binds_command():
    a, b = _intent(did="d1"), _intent(did="d2")
    assert signer_shim.command_digest(a) != signer_shim.command_digest(b)   # 다른 명령
    assert signer_shim.command_digest(a) == signer_shim.command_digest(_intent(did="d1"))  # 안정적


def test_operator_gate_issue_sign_verify_roundtrip():
    gate = signer_shim.OperatorGate(key=b"op-gate-key-not-a-real-secret")
    req = gate.issue(_intent(), nonce="n1", ttl_s=100, now=1000.0)
    token = gate.sign(req)
    ok, why = gate.verify(req, token, now=1001.0)
    assert ok, why


def test_captured_token_cannot_authorize_different_command():
    """verify_operator_binding: 명령 A 용으로 발행된 승인은 명령 B 에 대해 거부된다."""
    gate = signer_shim.OperatorGate(key=b"op-gate-key")
    req_a = gate.issue(_intent(did="A"), nonce="na", ttl_s=100, now=1000.0)
    token_a = gate.sign(req_a)
    # 같은 토큰이지만 명령 B 의 digest 에 바인딩되어야 함 -> 거부
    dig_b = signer_shim.command_digest(_intent(did="B"))
    ok, why = gate.verify(req_a, token_a, now=1001.0, expected_digest=dig_b)
    assert not ok and "mismatch" in why


def test_operator_gate_nonce_single_use_and_expiry_and_continuity():
    gate = signer_shim.OperatorGate(key=b"op-gate-key")
    req = gate.issue(_intent(), nonce="n1", ttl_s=10, now=1000.0)
    token = gate.sign(req)
    assert gate.verify(req, token, now=1005.0)[0]                    # 첫 사용 OK
    assert not gate.verify(req, token, now=1006.0)[0]               # nonce 재전송 거부
    # 만료
    req2 = gate.issue(_intent(did="d3"), nonce="n2", ttl_s=10, now=1000.0)
    tok2 = gate.sign(req2)
    assert not gate.verify(req2, tok2, now=1011.0)[0]              # 만료됨
    # 연속성: 마지막 수락된 consume 보다 이른 consume ts 는 거부 (replay 윈도)
    gate2 = signer_shim.OperatorGate(key=b"k")
    r3 = gate2.issue(_intent(did="d4"), nonce="n3", ttl_s=100, now=1000.0)
    assert gate2.verify(r3, gate2.sign(r3), now=1050.0)[0]
    r4 = gate2.issue(_intent(did="d5"), nonce="n4", ttl_s=100, now=1000.0)
    assert not gate2.verify(r4, gate2.sign(r4), now=1049.0)[0]     # 비단조 -> 거부


# --------------------------------------------------------------------------- #
# P4-Q2 — operator-gate 키 부트스트랩: key=None 이 정상 MDG 자세
# --------------------------------------------------------------------------- #
def test_operator_gate_none_is_fail_closed_normal_posture():
    """key=None: issue() 동작 (key-free), sign() 은 '' 반환, verify() fail-closed. 이것이 의도된
    MDG-runtime 자세 (issue-only)이며, 저하 모드가 아님 — MDG 는 위조 재료를 보유하지 않음."""
    gate = signer_shim.OperatorGate()                    # 키 주입 없음, env 없음
    req = gate.issue(_intent(), nonce="n1", ttl_s=100, now=1000.0)
    assert req.command_digest and req.nonce == "n1"      # issue 는 key-free
    assert gate.sign(req) == ""                           # 서명 불가
    ok, why = gate.verify(req, "anything", now=1001.0)
    assert not ok and "no operator-gate key" in why      # 구조적으로 자가 승인 불가


def test_operator_gate_env_is_dev_only_and_warns():
    """env 폴백은 DEV/replay 전용이며 경고를 발생시켜야 함 (docker inspect 유출면)."""
    import warnings as _w
    os.environ["MDG_OPERATOR_GATE_KEY"] = "dev-only-key"
    try:
        with _w.catch_warnings(record=True) as caught:
            _w.simplefilter("always")
            gate = signer_shim.OperatorGate()
        assert any("DEV/replay only" in str(c.message) for c in caught)
        # env 로 명시적 프로비저닝 시 여전히 동작 (dev), 다만 경고됨
        req = gate.issue(_intent(), nonce="ne", ttl_s=100, now=1000.0)
        assert gate.verify(req, gate.sign(req), now=1001.0)[0]
    finally:
        del os.environ["MDG_OPERATOR_GATE_KEY"]


# --------------------------------------------------------------------------- #
# P4-Q3 — durable secret-free operator-ledger: token 은 미영속, nonce 는 영속
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
    """탈취되었으나 아직 미만료된 토큰은 크래시 후 재전송될 수 없음: 소비된 nonce 는
    operator-ledger 에 durable 하며 부팅 시 새 게이트의 _seen_nonces 를 재시드함 (P4-Q3)."""
    import tempfile
    from mdg.ledger.operator_ledger import OperatorLedger
    path = os.path.join(tempfile.mkdtemp(), "op_ledger.jsonl")
    led = OperatorLedger(path)
    gate = signer_shim.OperatorGate(key=b"op-gate-key", ledger=led)
    req = gate.issue(_intent(), nonce="n-boot", ttl_s=10_000, now=1000.0)
    token = gate.sign(req)
    assert gate.verify(req, token, now=1001.0)[0]        # 첫 consume OK (GRANTED 영속됨)
    # 재부팅 모사: 새 게이트가 durable ledger 에서 _seen_nonces 를 시드
    gate2 = signer_shim.OperatorGate(key=b"op-gate-key", ledger=OperatorLedger(path))
    ok, why = gate2.verify(req, token, now=1002.0)       # 아직 TTL 내이지만 nonce 소비됨
    assert not ok and "replay" in why


def test_signer_emit_is_key_free():
    emit = signer_shim.emit_signed(_intent(), backend=Backend(allow_live=False))
    assert emit.dry_run and emit.delegate == "gcs_c2" and emit.command_digest
    # 정적: signer 소스는 /sign.key 경로 리터럴을 보유하지 않고 키 파일을 절대 열지 않음
    src = open(signer_shim.__file__, "r", encoding="utf-8").read()
    assert "sign.key" not in src.lower(), "signer must be key-free (no /sign.key literal)"
    assert "open(" not in src, "signer must not open any file (no key read)"


# --------------------------------------------------------------------------- #
# Item B — emit_signed LIVE 승격: 단일 Backend spawn 을 통한 gcs_c2 signed-sender
# --------------------------------------------------------------------------- #
class _RecordingBackend:
    """가짜 단일 spawn 소유자: 모든 ExecRequest 를 기록하고 스크립트된 ExecResult 를 반환.
    ``allow_live`` 는 설정 가능하므로 실제 docker 없이 emit_signed 의 라이브 게이트를 검증할 수 있음."""

    def __init__(self, allow_live=True, ok=True, dry_run=False, note="spawned"):
        self.allow_live = allow_live
        self._res = (ok, dry_run, note)
        self.reqs = []

    def run(self, req):
        from mdg.safe_exec.backend import ExecResult
        self.reqs.append(req)
        ok, dry_run, note = self._res
        return ExecResult(ok=ok, code=0, dry_run=dry_run, note=note)


def test_emit_signed_live_delegates_via_single_backend_spawn():
    """allow_live=True: emit_signed 는 gcs_c2 내부에 recovery 트리거 파일을 WRITE 하는 정확히 하나의
    Backend spawn 을 유발 — ``docker exec gcs_c2 sh -c 'printf "%s %s" "$1" "$2" >
    /tmp/mdg_correct' sh GUIDED 30`` — 이후 gcs.py (유일한 SITL signing-link 소유자)가 파일을 폴링해
    set_mode+arm+takeoff 를 자신의 키로 서명. MDG 는 파일을 열지 않음; mode/alt 은
    sh POSITIONAL 인자로 전달 (인젝션 없음); spawn 은 mutating (read_only=False)."""
    be = _RecordingBackend(allow_live=True, ok=True, dry_run=False, note="MOCK exec")
    emit = signer_shim.emit_signed(_signed_intent(), backend=be)
    assert len(be.reqs) == 1                                # 단일 Backend spawn (불변식2.)
    assert be.reqs[0].argv == ["docker", "exec", "gcs_c2", "sh", "-c",
                               'printf "%s %s" "$1" "$2" > /tmp/mdg_correct', "sh", "GUIDED", "30"]
    assert "/tmp/mdg_correct" in be.reqs[0].argv[5]        # 트리거 파일 쓰기, sender exec 아님
    assert be.reqs[0].read_only is False                   # mutating -> allow_live + semaphore 경로
    assert emit.ok and not emit.dry_run
    assert emit.delegate == "gcs_c2" and emit.command_digest
    assert emit.extra.get("mode") == "GUIDED" and emit.extra.get("alt") == 30


def test_emit_signed_live_reflects_backend_dry_run():
    """라이브 요청 경로에서도 Backend 자체가 DRY 이면 (allow_live 플래그 켜졌으나 run 이
    dry_run 반환 — 예: operator-go), emit 은 이를 반영: ok+dry_run, 여전히 spawn 하나."""
    be = _RecordingBackend(allow_live=True, ok=True, dry_run=True, note="DRY-RUN")
    emit = signer_shim.emit_signed(_signed_intent(), backend=be)
    assert len(be.reqs) == 1 and emit.ok and emit.dry_run


def test_emit_signed_dry_path_never_spawns():
    """allow_live=False (기본 operator-go 유보): digest-only, Backend spawn 없음 (레거시 동작
    불변) — 가짜 backend 의 run() 은 절대 도달하지 않음."""
    be = _RecordingBackend(allow_live=False)
    emit = signer_shim.emit_signed(_signed_intent(), backend=be)
    assert be.reqs == []                                   # dry 경로에서 spawn 없음
    assert emit.dry_run and emit.ok and "no signing key held" in emit.note


def test_defense_agent_runtime_is_key_free_asset_excluded():
    """정적 KEY-FREE (verify_signer_no_keyopen, 트리 전체): 어떤 defense_agent RUNTIME 모듈도
    signing 키를 참조하지 않음. /sign.key 를 명명하는 유일한 파일은 gcs_c2 측 asset 으로,
    gcs_c2 안에 DEPLOY 되어 그 안에서 실행됨 — 키는 절대 MDG 프로세스에 들어오지 않음. tests/ 와
    verify/ 는 정당하게 토큰을 언급하며 (assertion) 런타임 작동 코드가 아님."""
    import mdg
    root = os.path.dirname(os.path.abspath(mdg.__file__))
    asset_rel = os.path.join("safe_exec", "assets", "gcs_signed_correct.py")
    offenders = []
    for dp, _dn, fns in os.walk(root):
        rel_dir = os.path.relpath(dp, root)
        if rel_dir.split(os.sep)[0] in ("tests", "verify"):
            continue
        for fn in fns:
            if not fn.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(dp, fn), root)
            src = open(os.path.join(dp, fn), "r", encoding="utf-8").read()
            if "sign.key" in src.lower() and rel != asset_rel:
                offenders.append(rel)
    assert offenders == [], f"defense_agent runtime references a signing key: {offenders}"
    assert os.path.exists(os.path.join(root, asset_rel)), "gcs_c2 signed sender asset missing"


# --------------------------------------------------------------------------- #
# Item 3 — send_signed_mode dispatch: operator_auto 하에서 KEY-FREE emit + gcs_c2 위임
# --------------------------------------------------------------------------- #
def _signed_intent():
    # send_signed_mode 은 gcs_proxy chokepoint (recovery_priors)에서 집행됨, legality 전제조건
    # role_verified.gcs 가 동적으로 해석하는 컨테이너.
    return Intent(rule="signed_guided", tool_id="send_signed_mode", decision_id="s1",
                  config_version=CFG, enforce_at="gcs_proxy",
                  target="gcs_proxy", target_kind="role")


def test_send_signed_mode_stays_oper_without_operator_auto():
    """기본 자세: send_signed_mode (flight·HIGH·irreversible)은 OPER — emit 없음, exec 없음."""
    ctrl = ResponseController(backend=_SpyBackend())        # backend.run 도달 안 됨
    w = _world(role_verified={"gcs_proxy": True})
    plan, res = ctrl.dispatch(_signed_intent(), w, 0, risk="HIGH", reversible=False)
    assert plan.operator_required and res is None
    assert plan.signed_intent is None


def test_send_signed_mode_emits_key_free_delegated_under_operator_auto(monkeypatch):
    """operator_auto 는 send_signed_mode 을 AUTO_BY_OPERATOR 로 넓힘 -> run_plan 은 KEY-FREE
    인가 (command_digest 만)를 EMIT 하고 서명을 gcs_c2 에 위임. allow_live=False ->
    emit 은 operator-go DRY 유지. signing 키 파일은 절대 열리지 않음 (verify_signer_no_keyopen)."""
    import builtins as _b
    opened: list = []
    _real_open = _b.open

    def _spy_open(path, *a, **k):                            # emit 중 어떤 파일 open 이든 걸림
        opened.append(str(path))
        return _real_open(path, *a, **k)

    ctrl = ResponseController(backend=Backend(allow_live=False), operator_auto=True)
    w = _world(role_verified={"gcs_proxy": True})
    plan = ctrl.plan(_signed_intent(), w, 0, risk="HIGH", reversible=False)   # config 로드 (무관)
    assert plan.tier2 == "AUTO" and not plan.operator_required and not plan.skip
    assert plan.operator_auto_confirmed and plan.signed_intent is not None
    # EMIT 자체는 어떤 파일도 열어선 안 됨 (signing 키 읽기가 여기 드러남) — run_plan 만 래핑.
    monkeypatch.setattr(_b, "open", _spy_open)
    res = ctrl.run_plan(plan)
    monkeypatch.undo()
    assert res.ok and res.dry_run                            # operator-go 유보: digest-only DRY
    assert "gcs_c2" in res.note and "KEY-FREE" in res.note   # 위임이 ledger 로 표출됨
    assert opened == [], f"emit opened a file (must be key-free): {opened}"


def test_send_signed_mode_inert_when_enforce_unverified():
    """Fail-closed: operator_auto 이지만 enforce_at chokepoint 가 verified 바인딩이 아님 -> inert
    DRY, emit 대상 없음 (미검증 집행점에 대해 절대 위임하지 않음)."""
    ctrl = ResponseController(backend=Backend(allow_live=False), operator_auto=True)
    w = _world(role_verified={})                            # gcs_proxy 미검증
    plan, res = ctrl.dispatch(_signed_intent(), w, 0, risk="HIGH", reversible=False)
    assert plan.signed_intent is None and plan.exec_request is None
    assert res.dry_run and "INERT" in res.note


def test_act_send_signed_mode_operator_auto_records_and_applies_dry():
    """전체 act 배선: operator_auto 하에서 legal send_signed_mode 는 집행 Intent 를 기록하고
    (authority=sandbox-auto), KEY-FREE emit 하며, 규칙을 적용 (unconfirmed — observer 가
    나중에 30 m recovery 에서 확인). 부수효과는 DRY 유지 (allow_live=False)."""
    from mdg.core.worldstate import SigningObs
    chosen = _signed_intent()
    w = _world(role_verified={"gcs_proxy": True}, signing=SigningObs.CONFIRMED_ON)
    led = _SpyLedger()
    out = act(_state(chosen, risk="HIGH", reversible=False, world=w),
              backend=Backend(allow_live=False), ledger=led, operator_auto=True)
    assert out["dry_streak"] == 0
    assert len(led.intents) == 1 and not led.intents[0].operator_gate   # EXECUTED, 유예 아님
    assert led.intents[0].operator_auto_confirmed and led.intents[0].authority == "sandbox-auto"
    assert "signed_guided" in out["worldstate"].applied
    assert out["worldstate"].applied["signed_guided"].confirmed is False  # observer 가 나중에 확인


# --------------------------------------------------------------------------- #
# response.py — ResponseController plan/dispatch
# --------------------------------------------------------------------------- #
def test_response_plan_auto_builds_dry_exec():
    ctrl = ResponseController(backend=Backend(allow_live=False))
    # 두 개의 별개 verified 엔드포인트: enforce_at (chokepoint netns) + attacker source (P4-2)
    intent = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                    enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    w = _world(role_verified={"gcs_proxy": True, "attacker_ue": True},
               pid={"gcs_proxy": 12345, "attacker_ue": 4242},
               ip_map={"attacker_ue": "10.45.0.10"})
    plan, res = ctrl.dispatch(intent, w, tick_i=0, risk="MED", reversible=True)
    assert plan.tier2 == "AUTO" and not plan.operator_required and not plan.skip
    assert plan.exec_request is not None and res.ok and res.dry_run   # DRY (라이브 작동 없음)


def test_response_plan_oper_and_skip():
    ctrl = ResponseController(backend=_SpyBackend())
    # OPER: docker_pause -> operator_required, backend.run 미접촉
    intent_oper = Intent(rule="backdoor_pause", tool_id="docker_pause", config_version=CFG)
    plan, res = ctrl.dispatch(intent_oper, _world(), 0, risk="MED", reversible=True)
    assert plan.operator_required and res is None
    # SKIP: 멱등 applied+confirmed -> skip
    w_skip = _world(applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True)})
    intent_auto = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG)
    plan2, res2 = ctrl.dispatch(intent_auto, w_skip, 0, risk="MED", reversible=True)
    assert plan2.skip and res2 is None


# --------------------------------------------------------------------------- #
# P4-Q1 — 불투명 검증 selector: 전파 + fail-closed verified 바인딩
# --------------------------------------------------------------------------- #
def test_target_selector_propagates_and_binds_verified_role():
    """양 엔드포인트 봉쇄 (P4-2): enforce_at -> chokepoint netns pid, target -> attacker
    source ip, 각각 verified 맵의 KEY 로 별개의 verified 바인딩으로 해석됨. DROP 은
    CHOKEPOINT netns (4242, gcs_proxy)에 진입해 ATTACKER source (10.45.0.55)를 필터 —
    attacker 자신의 netns 가 자기 ip 를 drop 하는 게 아님 (이전의 비정합 argv)."""
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
    assert plan.exec_request.argv[:5] == ["nsenter", "--target", "4242", "--net", "--"]  # enforce netns (집행 netns)
    assert plan.exec_request.argv[-4:] == ["-s", "10.45.0.55", "-j", "DROP"]              # attacker 소스
    assert res.ok and res.dry_run


def test_target_forged_or_unverified_selector_goes_inert():
    """Self-DoS 차단 (PS-7): 어느 한 엔드포인트라도 verified 게이트를 통과 못 하면 (위조 source IP /
    미지 source role / 미투영 imsi / 미검증 enforcement), drop_argv 를 만들지 않음 ->
    inert DRY, 그리고 raw selector 가 -s 가 되는 일은 절대 없음."""
    ctrl = ResponseController(backend=Backend(allow_live=False))
    # verified enforcement chokepoint 고정; SOURCE selector 의 verified 여부를 변경.
    base = _world(role_verified={"gcs_proxy": True}, pid={"gcs_proxy": 12345}, ip_map={})
    # (a) operator/자기 IP 를 ip-kind source 로, 그러나 verified UE-pool 바인딩에 매핑 안 됨 -> inert
    forged_ip = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                       enforce_at="gcs_proxy", target="10.44.0.1", target_kind="ip")
    plan_a, res_a = ctrl.dispatch(forged_ip, base, 0, risk="MED", reversible=True)
    assert plan_a.exec_request is None and "inert" in plan_a.reason.lower()
    assert res_a.dry_run and "INERT" in res_a.note
    # (b) 미지 source role -> 미검증 -> inert
    unknown = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                     enforce_at="gcs_proxy", target="ghost_role", target_kind="role")
    plan_b, _ = ctrl.dispatch(unknown, base, 0, risk="MED", reversible=True)
    assert plan_b.exec_request is None
    # (c) 미투영 imsi source -> fail-closed inert (SMF layer-1 projection 미배선)
    imsi = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                  enforce_at="gcs_proxy", target="001010000000001", target_kind="imsi")
    plan_c, _ = ctrl.dispatch(imsi, base, 0, risk="MED", reversible=True)
    assert plan_c.exec_request is None
    # (d) verified SOURCE 이지만 UNVERIFIED enforcement chokepoint -> inert (양 엔드포인트 게이트)
    w2 = _world(role_verified={"attacker_ue": True},
                pid={"attacker_ue": 4242, "gcs_proxy": 12345},
                ip_map={"attacker_ue": "10.45.0.55"})
    unv_enf = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                     enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    plan_d, _ = ctrl.dispatch(unv_enf, w2, 0, risk="MED", reversible=True)
    assert plan_d.exec_request is None
    # (e) 동일 엔티티 엔드포인트 (enforce_at == source) -> 비정합 -> inert (distinct-binding 가드)
    w3 = _world(role_verified={"attacker_ue": True},
                pid={"attacker_ue": 4242}, ip_map={"attacker_ue": "10.45.0.55"})
    same = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                  enforce_at="attacker_ue", target="attacker_ue", target_kind="role")
    plan_e, _ = ctrl.dispatch(same, w3, 0, risk="MED", reversible=True)
    assert plan_e.exec_request is None


def test_ip_source_stale_binding_cross_check():
    """P4 stale-binding (재할당 IP self-DoS 차단): ip-kind raw source 는 DETECTION 시점에 포착된
    attacker IP. UE-pool IP 는 attach 마다 순환하므로, ENFORCEMENT 시점에 LIVE SMF session table 을
    교차 확인. 해제된(unbound) 또는 다른 UE 에 RE-ASSIGN 된 IP -> inert; 여전히 동일 엔티티 -> DROP."""
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

    # (1) smf_table 미배선 -> best-effort recon-only 재확인 -> NON-inert (회귀 없음)
    p0, _ = ResponseController(backend=Backend(allow_live=False)).dispatch(
        intent, _w(), 0, risk="MED", reversible=True)
    assert p0.exec_request is not None and p0.exec_request.argv[-4:] == ["-s", IP, "-j", "DROP"]

    # (2) smf_table: IP 가 여전히 동일 attacker 컨테이너에 live-bound -> NON-inert (DROP 진행)
    p1, _ = ResponseController(backend=Backend(allow_live=False), smf_table=_FakeSmf({IP: ATT_IMSI})
                               ).dispatch(intent, _w(), 0, risk="MED", reversible=True)
    assert p1.exec_request is not None

    # (3) smf_table: session 사라짐 (IP 해제, live binding 없음) -> stale -> inert (self-DoS 차단)
    p2, res2 = ResponseController(backend=Backend(allow_live=False), smf_table=_FakeSmf({})
                                  ).dispatch(intent, _w(), 0, risk="MED", reversible=True)
    assert p2.exec_request is None and "INERT" in res2.note

    # (4) smf_table: IP 가 다른 (무고한) UE 에 RE-ASSIGN -> stale -> inert
    w4 = _w()
    w4.imsi_container["001010000000099"] = "victim_ue"
    p3, _ = ResponseController(backend=Backend(allow_live=False),
                               smf_table=_FakeSmf({IP: "001010000000099"})
                               ).dispatch(intent, w4, 0, risk="MED", reversible=True)
    assert p3.exec_request is None


# --------------------------------------------------------------------------- #
# P1 — 보호된 관측/C2 인프라 쉴드 (구조적, 결정론적)
# --------------------------------------------------------------------------- #
def test_p1_protected_infra_destructive_tool_inert():
    """P1: 컨테이너 전체를 파괴하는 도구 (docker_pause / docker_net_disconnect)가 보호된
    관측/C2 컨테이너 (web_backend 대시보드 / gcs_proxy C2 chokepoint)를 대상으로 하면 operator_auto
    하에서도 dispatch 에서 INERT 처리됨 — 인프라의 자율 freeze/disconnect 없음."""
    ctrl = ResponseController(backend=Backend(allow_live=False), operator_auto=True)
    w = _world(role_verified={"web_backend": True, "gcs_proxy": True},
               pid={"web_backend": 111, "gcs_proxy": 222})
    for tool in ("docker_pause", "docker_net_disconnect"):
        for enforce in ("web_backend", "gcs_proxy"):
            intent = Intent(rule="backdoor_pause", tool_id=tool, config_version=CFG,
                            enforce_at=enforce)
            plan = ctrl.plan(intent, w, 0, risk="MED", reversible=True)
            assert plan.pause_container == "" and plan.exec_request is None
            assert "protected" in plan.reason.lower() and enforce in plan.reason


def test_p1_pfcp_firewall_drop_preserved():
    """P1 보존: 실제 위협 복구 pfcp_firewall @ gcs_proxy (nsenter '-s
    <attacker> DROP')는 파괴 도구가 아님 -> 쉴드가 건드리지 않음; 정밀 DROP 은
    두 개의 별개 verified 엔드포인트로 여전히 빌드됨 (DRY)."""
    ctrl = ResponseController(backend=Backend(allow_live=False))
    intent = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                    enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    w = _world(role_verified={"gcs_proxy": True, "attacker_ue": True},
               pid={"gcs_proxy": 4242, "attacker_ue": 777}, ip_map={"attacker_ue": "10.45.0.55"})
    plan = ctrl.plan(intent, w, 0, risk="MED", reversible=True)
    assert plan.exec_request is not None
    assert plan.exec_request.argv[:5] == ["nsenter", "--target", "4242", "--net", "--"]
    assert plan.exec_request.argv[-4:] == ["-s", "10.45.0.55", "-j", "DROP"]


def test_p1_send_signed_mode_gcs_proxy_not_shielded():
    """send_signed_mode 은 gcs_proxy 를 THROUGH 하여 서명된 명령을 EMIT (freeze/disconnect 하지 않음) ->
    파괴 도구가 아니므로, P1 쉴드는 enforce_at=gcs_proxy 에서도 emit 경로를 그대로 둠."""
    ctrl = ResponseController(backend=Backend(allow_live=False), operator_auto=True)
    w = _world(role_verified={"gcs_proxy": True}, pid={"gcs_proxy": 222})
    plan = ctrl.plan(_signed_intent(), w, 0, risk="HIGH", reversible=False)
    assert plan.signed_intent is not None and plan.exec_request is None
    assert "protected" not in plan.reason.lower()


def test_rank_recovery_carries_selector_into_chosen_intent():
    """rank_recovery 는 랭크된 후보의 params 에서 target/target_kind 를 복사해야 함 (핵심
    배선). 최소 legal Action 셋 사용 (scoring 에 대한 config 의존 없음)."""
    from mdg.core.nodes.rank_recovery import rank_recovery
    act_cand = Action(tool_id="nsenter_input_drop", risk="MED", reversible=True,
                      recovery_type="pfcp_firewall",
                      params={"target": "10.45.0.55", "target_kind": "ip",
                              "enforce_at": "gcs_proxy"})
    # Intent 생성 경로에 직접 assert 하여 feasibility/score config 를 우회:
    out = rank_recovery({"legal_actions": [act_cand], "config_version": CFG})
    chosen = out["chosen_action"]
    if chosen is not None:                                # 기본 priors 하에서 feasible
        assert chosen.target == "10.45.0.55" and chosen.target_kind == "ip"
        assert chosen.enforce_at == "gcs_proxy"           # P4-2 enforcement selector 전달됨


def test_selector_scopes_operator_digest():
    """P4-Q1 #5: command_digest 가 selector 를 바인딩하므로, target A 로 범위 지정된 승인은
    target B 에 재사용될 수 없음 (동일 rule/decision)."""
    base = dict(rule="signed_land", tool_id="send_signed_mode", decision_id="d1", config_version=CFG)
    dig_a = signer_shim.command_digest(Intent(target="ue_a", target_kind="role", **base))
    dig_b = signer_shim.command_digest(Intent(target="ue_b", target_kind="role", **base))
    assert dig_a != dig_b
    # P4-2: enforce_at 도 승인을 범위 지정 (동일 source, 다른 enforcement chokepoint)
    dig_e = signer_shim.command_digest(
        Intent(target="ue_a", target_kind="role", enforce_at="gcs_proxy", **base))
    assert dig_e != dig_a


# --------------------------------------------------------------------------- #
# act 노드 — 전체 배선
# --------------------------------------------------------------------------- #
def test_act_auto_records_intent_and_applies_dry():
    chosen = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop",
                    decision_id="d1", config_version=CFG,
                    enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    # legality 는 레지스트리 role_verified alias 를 action 의 enforce_at 컨테이너
    # (gcs_proxy)로 해석하며 이는 verified (step 10); 이후 두 개의 별개 verified 엔드포인트 (gcs_proxy
    # chokepoint pid + attacker source ip)가 dispatch 로 하여금 DROP 을 빌드하게 함.
    w = _world(role_verified={"gcs_proxy": True, "attacker_ue": True},
               pid={"gcs_proxy": 12345, "attacker_ue": 4242},
               ip_map={"attacker_ue": "10.45.0.10"})
    led = _SpyLedger()
    out = act(_state(chosen, world=w), backend=Backend(allow_live=False), ledger=led)
    assert out["dry_streak"] == 0
    assert len(led.intents) == 1 and not led.intents[0].operator_gate   # exec 이전에 기록됨 (G3)
    assert "pfcp_firewall" in out["worldstate"].applied                 # world_update 적용됨
    assert out["worldstate"].applied["pfcp_firewall"].confirmed is False  # effect_confirm 은 나중에


def test_act_oper_defers_to_operator_no_exec():
    # enforce_at 은 ENFORCEMENT 컨테이너를 담으므로 동적 legality 게이트 (step 10)가
    # role_verified[web_backend] 를 해석; world 가 해당 컨테이너를 시드하여 action 이 legal 이 되고
    # OPER (docker_pause) 경로가 검증됨 (pre-hook 에서 veto 되지 않음).
    chosen = Intent(rule="backdoor_pause", tool_id="docker_pause",
                    decision_id="d9", config_version=CFG, enforce_at="web_backend")
    spy = _SpyBackend()
    led = _SpyLedger()
    out = act(_state(chosen, world=_world(role_verified={"web_backend": True})),
              backend=spy, ledger=led)
    assert spy.calls == 0                                               # tier-2 OPER: 작동 없음
    assert "worldstate" not in out                                     # 적용 없음
    assert len(led.intents) == 1 and led.intents[0].operator_gate       # operator-gate Intent (연산자 게이트)
    assert led.intents[0].command_digest                               # PS-9 command-bound (명령 바인딩)


def test_act_idempotent_skip_no_side_effect():
    # enforce_at + 시드된 컨테이너가 action 을 legal 로 만듦 (step 10 동적 바인딩)하여 제어가
    # legality veto 가 아니라 bundle 멱등 skip 에 도달.
    chosen = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version=CFG,
                    enforce_at="gcs_proxy")
    w = _world(role_verified={"gcs_proxy": True},
               applied={"pfcp_firewall": AppliedRule(rule="pfcp_firewall", confirmed=True)})
    spy = _SpyBackend()
    led = _SpyLedger()
    out = act(_state(chosen, world=w), backend=spy, ledger=led)
    # skip 은 진전이 아님: dry_streak 은 정지 방향으로 증가 (0 이었음), 절대 0 으로 리셋 안 됨.
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
    # 기록된 digest 는 THIS 명령에 바인딩 (다른 명령에 대한 verify 는 실패)
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
