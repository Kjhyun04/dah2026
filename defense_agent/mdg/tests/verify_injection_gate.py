"""verify_injection_gate (PS-7 / PS-2, DESIGN_DECISIONS §PS-7 line 334 + 요건매트릭스
line 477 '신뢰불가 고-severity가 act 미도달') — 종단간 NEGATIVE 테스트.

이는 잠금 설계가 명명하지만 그 외에는 단편적으로만 assert 되던 실행 가능한
injection-gate 검증기다. 위조된(bad HMAC -> verified=False / tamper) 고-severity
SensorEv 를 실제 노드 체인
    sense -> correlate -> compute_trust -> compute_impact -> orient
          -> select_policy -> rank_recovery -> decide -> route_after_decide
에 통과시켜 체인 불변식을 증명한다: ``chosen_action is None`` 이며 decide-edge 가
END 로 라우팅되어 ``act`` 에 절대 도달하지 않고 부작용 0 을 낸다. 또한 카나리
STATUSTEXT / 주입된 자유 텍스트 페이로드가 어떤 응답 채널로도 누출되지 않음을 증명한다.

체인은 (컴파일된 LangGraph 대신) 노드별로 구동되는데, 이는 로컬 호스트에 langgraph 가
설치되지 않았기 때문이다(IMPLEMENTATION_GAPS D-1); 노드 함수들은 컴파일 그래프가 감싸는
동일한 순수 callable 이고, edges.route_* 는 add_conditional_edges 가 바인딩하는 바로 그
분기 함수다 — 따라서 이는 동일한 결정 표면을 행사한다.

비공허성(non-vacuity)은 세 가지로 보장:
  * POSITIVE 대조군이 동일 페이로드를 인증된(valid HMAC) 상태로 공급해 실제로
    조치 가능한 인시던트가 되어 ``act`` 까지 라우팅됨을 보인다 — 따라서 negative
    assert 가 자명하게 항상-참이 아니다;
  * value-carry 검사가 인증 시 ``SensorEv.value`` 가 진짜 누출 경로임을 보여,
    카나리 부재 assert 가 하중을 담당한다(위조 카나리는 오직 provenance gate 가
    엔벨로프를 폐기했기 때문에 부재);
  * hostile-LLM 변형이, 최대로 강화된 orient note(severity_bump=1, 주입이 부풀릴 수
    있는 유일한 것)조차 provenance 통과 인시던트 없이는 조치를 만들어낼 수 없음을 보인다.
"""
from __future__ import annotations

import json
import os
import queue
import sys

# ``python mdg/tests/verify_injection_gate.py`` 가 단독 실행되도록 repo 루트를 sys.path 에
# (pytest 는 rootdir 로 추가; 이는 직접 실행 경로도 커버).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.collector.ingest import Keyring, SensorEnvelope, compute_hmac  # noqa: E402
from mdg.config import loader
from mdg.core import edges
from mdg.core.nodes.act import act
from mdg.core.nodes.compute_impact import compute_impact
from mdg.core.nodes.compute_trust import compute_trust
from mdg.core.nodes.correlate import correlate
from mdg.core.nodes.decide import decide
from mdg.core.nodes.orient import orient
from mdg.core.nodes.rank_recovery import rank_recovery
from mdg.core.nodes.select_policy import select_policy
from mdg.core.nodes.sense import sense
from mdg.core.state import OrientNote, SensorEv, initial_state
from mdg.core.worldstate import WorldState
from mdg.ingest.verify import IngestVerifier
from mdg.ledger.intent_ledger import SeqWatermark

# 위조 엔벨로프가 밀반입하는 MAVLink-STATUSTEXT 형태의 injection 카나리. 자유 텍스트
# ``statustext`` 키와 파생 ``value`` 필드 양쪽에 배치하여, provenance gate 가 fail-open
# 이면 evidence/response 채널에 노출되도록 한다.
CANARY = "CANARY-STATUSTEXT::LAND_NOW::b7f3-injection"

_KID = "k1"
_KEY = b"unit-test-ingest-key-not-a-secret"
ACC = ("ledger", "decisions", "incidents")   # operator.add 채널(대체 아닌 확장)


# --------------------------------------------------------------------------- #
# helpers — 진본/위조 엔벨로프 생성 및 결정론적 체인 구동
# --------------------------------------------------------------------------- #
def _keyring() -> Keyring:
    return Keyring(keys={_KID: _KEY})


def _env(metric: str, source_id: str, *, seq: int = 1, band: str = "danger",
         domain: str | None = None, value=None, statustext: str | None = None) -> SensorEnvelope:
    payload: dict = {"metric": metric, "band": band}
    if domain is not None:
        payload["domain"] = domain
    if value is not None:
        payload["value"] = value
    if statustext is not None:
        payload["statustext"] = statustext          # 자유 텍스트(SensorEv 필드 절대 아님)
    return SensorEnvelope(payload=payload, source_id=source_id, kid=_KID,
                          seq=seq, ts=0.0, nonce=f"n-{source_id}-{seq}")


def _sign(env: SensorEnvelope) -> SensorEnvelope:
    env.hmac = compute_hmac(env, _KEY)               # 진본
    return env


def _forge(env: SensorEnvelope) -> SensorEnvelope:
    env.hmac = "0" * 64                              # 잘못된 다이제스트 -> HMAC 불일치 -> tamper
    return env


def _merge(state: dict, update: dict) -> dict:
    """LangGraph 채널 리듀서 시뮬레이션: ACC 채널은 확장, 그 외는 대체."""
    for k, v in update.items():
        if k in ACC:
            state[k] = list(state.get(k, [])) + list(v)
        else:
            state[k] = v
    return state


def _base_state(*, role_verified_target: bool = False) -> dict:
    cfg = loader.config_version()
    st = dict(initial_state(cfg))
    rv: dict[str, bool] = {}
    if role_verified_target:
        # legality 는 role_verified[<action.enforce_at 컨테이너>] 를 동적으로 검증(step 10),
        # 따라서 후보가 해석되는 실제 enforcement-container 키를 시드한다(가상의
        # "target" 별칭 아님). config 에서 파생 -> 고정된 testbed 리터럴 없음.
        for _spec in loader.recovery_priors().get("recovery_priors", {}).values():
            _ea = str(_spec.get("enforce_at") or "")
            if _ea:
                rv[_ea] = True
    st["worldstate"] = WorldState(config_version=cfg, role_verified=rv)
    return st


def _drive(state: dict, envs, *, orient_llm=None):
    """``envs``(이미 inbox 순서) 에 대해 sense..decide 를 실행하고
    (state, route_after_impact, route_after_decide) 를 반환."""
    keyring, seqwm = _keyring(), SeqWatermark()
    verifier = IngestVerifier(keyring, seqwm)
    q: queue.Queue = queue.Queue()
    for e in envs:
        q.put(e)

    _merge(state, sense(state, inbox=q, verify=verifier))
    _merge(state, correlate(state))
    _merge(state, compute_trust(state))
    _merge(state, compute_impact(state))
    r_impact = edges.route_after_impact(state)

    # LLM 절반을 무조건 통과시킨다(관통 검증): route_after_impact 가 이미 END(Green tick)
    # 라 해도, 결정 절반을 강제 실행해 provenance 실패 입력으로부터 체인이 여전히 조치를
    # 만들어낼 수 없음을 증명한다.
    _merge(state, orient(state, llm=orient_llm))
    _merge(state, select_policy(state))
    _merge(state, rank_recovery(state))
    _merge(state, decide(state))
    r_decide = edges.route_after_decide(state)
    return state, r_impact, r_decide


class _SpyLedger:
    def __init__(self):
        self.calls = 0

    def record_intent(self, intent):
        self.calls += 1
        return {"ledger": [intent]}


class _SpyBackend:
    def __init__(self):
        self.calls = 0

    def run(self, req):
        self.calls += 1
        raise AssertionError("backend.run must never be reached in the forged path")


# --------------------------------------------------------------------------- #
# CORE NEGATIVE TEST — 위조 고-severity 는 act 에 절대 도달하지 않음(체인 불변식)
# --------------------------------------------------------------------------- #
def test_forged_high_severity_signal_never_reaches_act():
    # 두 개의 위조 DANGER 신호(인증되면 PFCP+Unauthorized_Command CR01 시간창 상관 ->
    # band bump -> Red -> orient/act 로 라우팅하는 바로 그 번들)
    forged = [
        _forge(_env("Unauthorized_Command", "col_gcs", domain="command",
                    value=CANARY, statustext=CANARY)),
        _forge(_env("PFCP_Delete_Attempt", "col_net", domain="session_network",
                    value=CANARY, statustext=CANARY)),
    ]
    state, r_impact, r_decide = _drive(_base_state(), forged)

    # 1) sense 의 provenance gate: 위조 엔벨로프 폐기, evidence 로 병합 안 됨
    assert state["evidence"] == [], "forged evidence must be fail-closed discarded (PS-2)"
    tamper = [i for i in state["incidents"] if i.kind == "tamper"]
    assert len(tamper) == 2, "each forged envelope must surface as a tamper Incident"

    # 2) provenance 통과 evidence 없음 -> correlate 인시던트 없음, 모든 도메인 유휴(trust 100)
    non_tamper = [i for i in state["incidents"] if i.kind != "tamper"]
    assert non_tamper == [], "no actionable incident may be derived from forged input"
    assert state["impact"].band == "Green", "forged danger must not raise impact"
    assert r_impact == edges.END, "Green tick ends before the LLM half (no orient in-graph)"

    # 3) 체인 불변식: legal 후보 없음, 선택 조치 없음, decide-edge -> END
    assert state["legal_actions"] == [], "tamper/absent incidents yield no legal candidate"
    assert state["chosen_action"] is None, "no action may be selected from forged input"
    assert state["chosen_action_risk"] == "LOW"
    assert r_decide == edges.END, "decide-edge must route to END, NOT act/escalate"

    # 4) 이 state 로 직접 호출해도 act 는 부작용 0
    spy_ledger, spy_backend = _SpyLedger(), _SpyBackend()
    out = act(state, backend=spy_backend, ledger=spy_ledger)
    assert out == {}, "act must early-return with zero side effects (chosen_action None)"
    assert spy_ledger.calls == 0 and spy_backend.calls == 0, "no intent recorded, no exec"


# --------------------------------------------------------------------------- #
# CANARY — 주입된 STATUSTEXT / 자유 텍스트는 어떤 응답 채널에도 진입하지 않음
# --------------------------------------------------------------------------- #
def test_canary_statustext_absent_from_every_response_channel():
    forged = [
        _forge(_env("Unauthorized_Command", "col_gcs", domain="command",
                    value=CANARY, statustext=CANARY)),
        _forge(_env("PFCP_Delete_Attempt", "col_net", domain="session_network",
                    value=CANARY, statustext=CANARY)),
    ]
    state, _, _ = _drive(_base_state(), forged)

    def _dump(obj):
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if isinstance(obj, dict):
            return {k: _dump(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_dump(v) for v in obj]
        return obj

    channels = {
        "evidence": state["evidence"],
        "trust": state["trust"],
        "incidents": state["incidents"],
        "decisions": state["decisions"],
        "ledger": state["ledger"],
        "chosen_action": state["chosen_action"],
        "orient_note": state.get("orient_note"),
        "decide_note": state.get("decide_note"),
        "worldstate": state["worldstate"],
    }
    blob = json.dumps(_dump(channels), default=str, ensure_ascii=False)
    assert CANARY not in blob, "canary STATUSTEXT must not leak into any response channel"
    # 월드에 적용된 응답 규칙은 비어 있어야 함(집행이 한 번도 실행 안 됨)
    assert state["worldstate"].applied == {}


def test_value_field_is_a_real_leak_path_so_canary_check_is_load_bearing():
    """카나리 부재 assert 가 공허하지 않음을 증명: 진본 엔벨로프의 ``value`` 는
    SensorEv 로 전달되며(따라서 fail-open gate 라면 카나리를 노출), 반면 자유 텍스트
    ``statustext`` 키는 envelope_to_ev 가 폐기한다(PS-7 layer 2)."""
    probe = "CANARY-VALUE-CARRY::x9"
    env = _sign(_env("Unauthorized_Command", "col_gcs", domain="command",
                     value=probe, statustext=probe))
    verifier = IngestVerifier(_keyring(), SeqWatermark())
    ok, reason, ev = verifier(env)
    assert ok and ev.verified and not ev.tamper, f"authentic envelope must verify: {reason}"
    assert ev.value == probe, "value IS a carry path -> forged canary-absence is meaningful"
    # 자유 텍스트 statustext 키는 SensorEv 필드가 절대 되지 않음(해당 속성 없음)
    assert not hasattr(ev, "statustext")
    assert probe not in (ev.metric, ev.channel, str(ev.domain or ""))


# --------------------------------------------------------------------------- #
# POSITIVE CONTROL — 동일 신호가 인증되면 act 로 라우팅됨
# --------------------------------------------------------------------------- #
def test_authentic_same_signal_would_reach_act():
    authentic = [
        _sign(_env("Unauthorized_Command", "col_gcs", domain="command")),
        _sign(_env("PFCP_Delete_Attempt", "col_net", domain="session_network")),
    ]
    state, r_impact, r_decide = _drive(
        _base_state(role_verified_target=True), authentic)

    # 인증된 evidence 는 병합되고 조치 가능한 인시던트를 생성
    assert len(state["evidence"]) == 2 and all(e.verified for e in state["evidence"])
    assert not any(i.kind == "tamper" for i in state["incidents"])
    assert any(i.kind == "single-signal" for i in state["incidents"])

    # 국소 command 침해 -> criticality 하한 -> non-Green -> LLM 절반 실행
    assert state["impact"].band == "Red"
    assert r_impact == "orient"

    # ... 그리고 decide-edge 는 act 로 라우팅(위조 입력이 취할 수 없던 바로 그 경로)
    assert state["chosen_action"] is not None, "authentic signal selects an action"
    assert state["chosen_action_risk"] == "MED"
    assert state["chosen_action_reversible"] is True
    assert r_decide == "act", "authentic MED/reversible action routes to act"


# --------------------------------------------------------------------------- #
# TAMPER-KIND 인시던트는 구조적으로 조치 불가(select_policy 에 매핑 없음)
# --------------------------------------------------------------------------- #
def test_tamper_incident_yields_no_legal_candidate():
    state = _base_state(role_verified_target=True)
    # tamper 인시던트를 직접 주입하고 policy 절반만 실행
    _merge(state, sense(state, inbox=queue.Queue(), verify=None))   # 빈 드레인(fail-open)
    from mdg.core.state import Incident
    _merge(state, {"incidents": [Incident(id="t0", kind="tamper", target="")]})
    _merge(state, select_policy(state))
    assert state["legal_actions"] == [], "a tamper-kind incident maps to no response tool"


# --------------------------------------------------------------------------- #
# HOSTILE LLM — 최대로 강화된 orient note(주입이 부풀릴 수 있는 전부)조차
# provenance 통과 인시던트 없이는 조치를 만들어낼 수 없음(PS-7 #2)
# --------------------------------------------------------------------------- #
def test_hostile_orient_severity_bump_cannot_manufacture_action():
    hostile = lambda feats: OrientNote(rationale="inflate", severity_bump=1)
    forged = [
        _forge(_env("Unauthorized_Command", "col_gcs", domain="command",
                    value=CANARY, statustext=CANARY)),
    ]
    state, _, r_decide = _drive(_base_state(role_verified_target=True), forged,
                                orient_llm=hostile)
    # note 가 band 를 상향(상승 전용) 강화했으나, 인시던트가 없으므로 여전히
    # 후보 없음, 선택 조치 없음, decide-edge 는 END 로 라우팅.
    assert state["orient_note"].severity_bump == 1
    assert state["legal_actions"] == []
    assert state["chosen_action"] is None
    assert r_decide == edges.END, "tighten-only advice cannot itself trigger an action"


if __name__ == "__main__":                                    # pragma: no cover
    # pytest 수집 없이 단독 실행(cwd 의존적 rootdir 스캔 회피);
    # 여기의 모든 테스트는 순수 assert 를 쓰므로 직접 호출이 충실하다.
    _fns = [v for k, v in sorted(globals().items())
            if k.startswith("test_") and callable(v)]
    for _fn in _fns:
        _fn()
        print(f"[PASS] {_fn.__name__}")
    print(f"[OK] verify_injection_gate: {len(_fns)} checks")
