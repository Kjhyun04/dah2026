"""P3 — phase-LLM 패키지 + evidence TTL 분석 프리미티브.

포함: graceful degradation (litellm/jinja2/key 없음 -> None), PS-7 feature 살균,
empty-prompt/StrictUndefined 가드, apply_advice 단일 소스 재export + 단조성,
orient/decide 노드 LLM 통합 + fallback, evidence band->sev/dev + TTL 신선도.
"""
from __future__ import annotations

import importlib.util

import pytest

from mdg.config import defaults as D
from mdg.core import advice as core_advice
from mdg.core import evidence, scoring
from mdg.core.nodes.decide import decide
from mdg.core.nodes.orient import orient
from mdg.core.state import DecideNote, ImpactObj, OrientNote, SensorEv, TrustObj
from mdg.llm import (apply_advice, build_llm_deps, make_decide_llm,
                     make_orient_llm, tighten_only)
from mdg.llm.client import _extract_json, has_api_key, litellm_available
from mdg.llm.features import (DECIDE_FEATURES, ORIENT_FEATURES, sanitize)
from mdg.llm.render import LLMUnavailable, guard_nonempty, jinja_available

_HAS_JINJA = importlib.util.find_spec("jinja2") is not None


# --------------------------------------------------------------------------- #
# graceful degradation — 로컬에 litellm/jinja2/key 없음 -> 팩토리가 None 반환
# --------------------------------------------------------------------------- #
def test_factories_degrade_to_none_when_unavailable():
    available = litellm_available() and jinja_available() and has_api_key()
    if not available:
        assert make_orient_llm() is None
        assert make_decide_llm() is None
        deps = build_llm_deps()
        assert deps == {"llm_orient": None, "llm_decide": None}


def test_build_llm_deps_keys_match_graph_contract():
    deps = build_llm_deps()
    assert set(deps) == {"llm_orient", "llm_decide"}


# --------------------------------------------------------------------------- #
# PS-7 feature 살균 — 파생 numeric/enum 만, raw 문자열은 드롭
# --------------------------------------------------------------------------- #
def test_sanitize_orient_valid():
    feats = {"impact_band": "Yellow", "impact_score": 55, "n_incidents": 2,
             "min_trust": 40.0, "raw_wire": "'; DROP TABLE --"}
    clean = sanitize(feats, ORIENT_FEATURES)
    assert clean == {"impact_band": "Yellow", "impact_score": 55,
                     "n_incidents": 2, "min_trust": 40.0}
    assert "raw_wire" not in clean               # 추가 raw key 는 절대 전달되지 않음


def test_sanitize_decide_valid():
    feats = {"impact_band": "Red", "risk": "HIGH", "reversible": False, "has_action": True}
    assert sanitize(feats, DECIDE_FEATURES) == feats


@pytest.mark.parametrize("feats", [
    {"impact_band": "Purple", "impact_score": 1, "n_incidents": 0, "min_trust": 1.0},   # 잘못된 enum
    {"impact_band": "Green", "impact_score": 1.5, "n_incidents": 0, "min_trust": 1.0},  # int 자리에 float
    {"impact_band": "Green", "impact_score": True, "n_incidents": 0, "min_trust": 1.0}, # int 자리에 bool
    {"impact_band": "Green", "impact_score": 1, "n_incidents": 0},                       # key 누락
    {"impact_band": "x" * 40, "impact_score": 1, "n_incidents": 0, "min_trust": 1.0},   # 과대 enum
])
def test_sanitize_rejects_bad_features(feats):
    with pytest.raises(LLMUnavailable):
        sanitize(feats, ORIENT_FEATURES)


# --------------------------------------------------------------------------- #
# prompt 가드 — empty 가드 + StrictUndefined (render)
# --------------------------------------------------------------------------- #
def test_empty_prompt_guard():
    with pytest.raises(LLMUnavailable):
        guard_nonempty("   \n\t ")
    assert guard_nonempty("x") == "x"


@pytest.mark.skipif(not _HAS_JINJA, reason="jinja2 not installed")
def test_render_strict_undefined_raises_on_missing_var():
    from mdg.llm.render import render
    # 완전한 context 는 렌더됨; 누락 변수는 LLMUnavailable 를 던짐 (StrictUndefined)
    full = render("orient.jinja", {"impact_band": "Yellow", "impact_score": 55,
                                    "n_incidents": 2, "min_trust": 40.0})
    assert "Yellow" in full and full.strip()
    with pytest.raises(LLMUnavailable):
        render("orient.jinja", {"impact_band": "Yellow"})   # 변수 누락


@pytest.mark.skipif(_HAS_JINJA, reason="jinja2 installed")
def test_render_unavailable_without_jinja():
    from mdg.llm.render import render
    with pytest.raises(LLMUnavailable):
        render("orient.jinja", {})


# --------------------------------------------------------------------------- #
# apply_advice — 단일 잠금 소스 + 단조 tighten-only
# --------------------------------------------------------------------------- #
def test_apply_advice_is_single_locked_source():
    assert apply_advice is core_advice.apply_advice          # 분기 복사본 없음
    assert tighten_only is core_advice.tighten_only


def test_tighten_only_never_downgrades():
    for band in ("Green", "Yellow", "Red"):
        for bump in (0, 1):
            new = tighten_only(band, bump)
            assert ["Green", "Yellow", "Red"].index(new) >= \
                   ["Green", "Yellow", "Red"].index(band)


def test_apply_advice_raises_band_only():
    state = {"impact": ImpactObj(score=55, band="Yellow")}
    out = apply_advice(state, OrientNote(severity_bump=1))
    assert out["impact"].band == "Red"                        # Yellow -> Red (한 단계 상승)
    # bump 0 = 변화 없음
    assert apply_advice({"impact": ImpactObj(band="Yellow")}, OrientNote(severity_bump=0)) == {}


# --------------------------------------------------------------------------- #
# orient/decide 노드 LLM 통합 + 결정론 fallback (G6)
# --------------------------------------------------------------------------- #
def test_orient_node_applies_injected_note():
    state = {"impact": ImpactObj(score=55, band="Yellow"), "trust": {}, "incidents": []}
    llm = lambda feats: OrientNote(rationale="raise", severity_bump=1)
    out = orient(state, llm=llm)
    assert isinstance(out["orient_note"], OrientNote)
    assert out["impact"].band == "Red"                        # tighten 적용됨


def test_orient_node_falls_back_on_llm_error():
    state = {"impact": ImpactObj(score=55, band="Yellow"), "trust": {}, "incidents": []}
    def boom(feats):
        raise RuntimeError("model down")
    out = orient(state, llm=boom)
    assert out["orient_note"].severity_bump == 0              # fallback, bump 없음
    assert "impact" not in out                                # band 불변


def test_orient_node_rejects_non_orientnote():
    state = {"impact": ImpactObj(band="Yellow"), "trust": {}, "incidents": []}
    out = orient(state, llm=lambda f: "not a note")
    assert out["orient_note"].severity_bump == 0              # fallback


def test_decide_node_applies_injected_note():
    state = {"impact": ImpactObj(band="Yellow"), "chosen_action": None,
             "chosen_action_risk": "LOW", "config_version": "v", "tick_i": 1}
    note = DecideNote(rationale="ok", escalate_recommended=True)
    out = decide(state, llm=lambda f: note)
    assert out["decide_note"] is note
    assert out["decisions"] and out["dry_streak"] == 1        # action 없음 -> dry++


def test_decide_node_falls_back_on_error():
    state = {"impact": ImpactObj(band="Yellow"), "chosen_action": None,
             "chosen_action_risk": "LOW", "config_version": "v"}
    out = decide(state, llm=lambda f: (_ for _ in ()).throw(ValueError("x")))
    assert out["decide_note"].escalate_recommended is False   # fallback


# --------------------------------------------------------------------------- #
# client json 추출
# --------------------------------------------------------------------------- #
def test_extract_json_strips_fence():
    assert _extract_json('```json\n{"a":1}\n```') == '{"a":1}'
    assert _extract_json('{"a":1}') == '{"a":1}'


# --------------------------------------------------------------------------- #
# evidence — band->sev/dev + TTL 신선도
# --------------------------------------------------------------------------- #
def test_evidence_sev_dev_matches_scoring():
    for band in D.BAND_MAP:
        assert evidence.sev_dev(band) == (scoring.severity_factor(band),
                                          scoring.deviation(band))


def test_evidence_ttl_default():
    assert evidence.evidence_ttl_s() == float(D.TIME_WINDOWS["evidence_ttl_s"])


def test_evidence_freshness():
    ttl = 60.0
    assert evidence.is_fresh(0.0, 30.0, ttl) is True
    assert evidence.is_fresh(0.0, 90.0, ttl) is False
    assert evidence.is_stale(0.0, 90.0, ttl) is True
    # clock skew / ts==0 scaffold -> age 클램프됨, fresh
    assert evidence.age(100.0, 50.0) == 0.0


def test_fresh_domains_excludes_stale_and_tamper():
    evs = [
        SensorEv(source_id="a", metric="m1", domain="command", ts=100.0, verified=True),
        SensorEv(source_id="b", metric="m2", domain="communication", ts=10.0, verified=True),
        SensorEv(source_id="c", metric="m3", domain="mission", ts=100.0, tamper=True),
    ]
    fresh = evidence.fresh_domains(evs, now=120.0, ttl=60.0)
    assert fresh == {"command"}          # communication stale (age 110>60), mission tampered 됨
    kept = evidence.fresh(evs, now=120.0, ttl=60.0)
    assert [e.source_id for e in kept] == ["a"]


# --------------------------------------------------------------------------- #
# P3-Q6 — litellm client 계약 (fake 주입; live 호출은 operator-go)
# --------------------------------------------------------------------------- #
def test_emit_temperature_gate():
    from mdg.llm.client import _emit_temperature
    # reject-sampling 계열 (current-gen) -> temperature 생략 (아니면 400)
    assert _emit_temperature("anthropic/claude-opus-4-8") is False
    assert _emit_temperature("anthropic/claude-opus-4-7") is False
    assert _emit_temperature("anthropic/claude-sonnet-5") is False
    assert _emit_temperature("anthropic/claude-fable-5") is False
    # sampling-accepting 계열 -> temperature=0 방출 (결정론)
    assert _emit_temperature("anthropic/claude-sonnet-4-5") is True
    assert _emit_temperature("anthropic/claude-haiku-4-5") is True


def test_emit_temperature_forward_safe_for_unknown_and_nonanthropic():
    from mdg.llm.client import _emit_temperature
    # UNKNOWN/미래 Anthropic 계열 -> 생략 (fail-safe: 최신 세대는 sampling 을 거부하므로,
    # 미등록 모델에 temperature 를 보내 400 -> 영구 결정론 fallback 이 되게 해서는 안 됨).
    for m in ("anthropic/claude-opus-4-9", "anthropic/claude-opus-5",
              "anthropic/claude-sonnet-6", "anthropic/claude-haiku-5"):
        assert _emit_temperature(m) is False
    # non-Anthropic provider 는 temperature 를 수용 -> 결정론을 위해 0 방출.
    assert _emit_temperature("openai/gpt-4o") is True
    assert _emit_temperature("gemini/gemini-2.0-flash") is True
    # 알려진 sampling-accepting Anthropic 계열은 여전히 방출 (회귀 가드).
    assert _emit_temperature("anthropic/claude-sonnet-4-5") is True
    assert _emit_temperature("anthropic/claude-haiku-4-5") is True


def test_note_extra_forbid_rejects_smuggled_keys():
    import pydantic
    OrientNote.model_validate_json('{"severity_bump": 1}')          # clean parses
    with pytest.raises(pydantic.ValidationError):
        OrientNote.model_validate_json('{"severity_bump": 1, "evil": "x"}')
    with pytest.raises(pydantic.ValidationError):
        DecideNote.model_validate_json('{"escalate_recommended": true, "x": 1}')


def test_parse_capped_rejects_oversize_before_parse():
    from mdg.llm.client import _parse_capped
    big = '{"rationale":"' + ("a" * 20000) + '"}'   # > 16384-byte 상한
    with pytest.raises(ValueError):
        _parse_capped(big, OrientNote)
    note = _parse_capped('```json\n{"severity_bump":1}\n```', OrientNote)
    assert note.severity_bump == 1                  # fence-strip + 상한 내 parse


def test_complete_structured_kwargs_gate_and_fallback(monkeypatch):
    import sys
    import types
    from mdg.llm import client as C

    captured: dict = {}
    calls: list[str] = []

    def _completion(**kwargs):
        calls.append(kwargs["model"])
        if kwargs["model"].endswith("opus-4-8"):
            raise RuntimeError("primary down")       # 직접 구현한 fallback 을 구동
        captured.update(kwargs)
        return {"choices": [{"message": {"content": '{"severity_bump": 1}'}}]}

    fake = types.ModuleType("litellm")
    fake.completion = _completion
    monkeypatch.setitem(sys.modules, "litellm", fake)

    role = {"model": "anthropic/claude-opus-4-8",
            "fallback": ["anthropic/claude-sonnet-4-5"], "max_tokens": 512}
    note = C.complete_structured(role, "sys", "usr", OrientNote, timeout_s=5.0)

    assert isinstance(note, OrientNote) and note.severity_bump == 1
    assert calls == ["anthropic/claude-opus-4-8", "anthropic/claude-sonnet-4-5"]  # 폴오버됨
    # 서빙된 모델은 sonnet-4-5 (sampling-accepting) -> temperature=0 방출됨
    assert captured["temperature"] == 0
    assert captured["num_retries"] == 0 and captured["drop_params"] is True
    assert captured["timeout"] == 5.0
    assert captured["response_format"]["type"] == "json_schema"


def test_complete_structured_omits_temperature_for_reject_family(monkeypatch):
    import sys
    import types
    from mdg.llm import client as C

    captured: dict = {}

    def _completion(**kwargs):
        captured.update(kwargs)
        return {"choices": [{"message": {"content": '{"severity_bump": 0}'}}]}

    fake = types.ModuleType("litellm")
    fake.completion = _completion
    monkeypatch.setitem(sys.modules, "litellm", fake)

    role = {"model": "anthropic/claude-opus-4-8", "max_tokens": 256}
    C.complete_structured(role, "sys", "usr", OrientNote)
    assert "temperature" not in captured           # opus-4-8 은 sampling 거부 -> 생략됨


# --------------------------------------------------------------------------- #
# P3-Q5 — watchdog liveness -> WorldState.dead_domains -> compute_trust 배제
# --------------------------------------------------------------------------- #
def test_compute_trust_drops_dead_domains_absent_field_fallback():
    from mdg.core.nodes.compute_trust import compute_trust
    from mdg.core.worldstate import WorldState
    # worldstate 부재 -> 전부 present (기존 동작, fallback)
    out = compute_trust({"evidence": []})
    assert set(out["trust"]) == set(D.DOMAINS)
    # watchdog-dead domain 드롭됨 -> compute_impact present-set 배제 활성화
    w = WorldState(dead_domains=["command"])
    out2 = compute_trust({"evidence": [], "worldstate": w})
    assert "command" not in out2["trust"] and "mission" in out2["trust"]


def test_sense_sensor_loss_marks_dead_and_live_evidence_clears():
    import queue
    from mdg.core.nodes.sense import sense
    from mdg.core.worldstate import WorldState

    sd = {"net_metric": "session_network"}
    q = queue.Queue()
    q.put(SensorEv(source_id="watchdog", metric="sensor_loss", value="net_metric"))
    out = sense({"worldstate": WorldState()}, inbox=q, source_domains=sd)
    assert out["worldstate"].dead_domains == ["session_network"]     # loss 시 add-only

    q2 = queue.Queue()
    q2.put(SensorEv(source_id="net_metric", metric="PFCP_Delete_Attempt",
                    domain="session_network"))
    out2 = sense({"worldstate": out["worldstate"]}, inbox=q2, source_domains=sd)
    assert out2["worldstate"].dead_domains == []                     # live 방출이 clear

    # source_domains=None (기본) -> liveness 기록 없음 (동작 불변)
    q3 = queue.Queue()
    q3.put(SensorEv(source_id="watchdog", metric="sensor_loss", value="net_metric"))
    out3 = sense({"worldstate": WorldState()}, inbox=q3)
    assert out3["worldstate"].dead_domains == []


def test_build_source_domains_from_roster():
    from mdg.collector import build_source_domains

    class _C:
        def __init__(self, sid, dom):
            self.source_id, self.domain = sid, dom

    roster = [_C("net_metric", "session_network"), _C("infra", None), _C(None, "x")]
    assert build_source_domains(roster) == {"net_metric": "session_network"}
