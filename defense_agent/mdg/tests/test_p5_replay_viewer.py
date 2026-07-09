"""test_p5_replay_viewer — P5 Verifier + Viewer + replay self-verify (독립 실행 가능).

langgraph/fastapi 없이 잠긴 네 개 P5 속성을 검증한다:
  - record.py: byte-identical 정규 라인 + secret scrub (PS-3)
  - play.py: tick-timeline 재구성 (양 스키마)
  - verifier.py: 독립 cross-root 진실 + telemetry-silence + agent≠truth 발산,
    그리고 grep0 (Verifier 모듈은 mdg.core.* 를 전혀 import 하지 않음)
  - viewer/app.py: 순수 3-panel 빌더 + fail-closed secret scan + loopback 전용 bind (PS-8)

실행: python mdg/tests/test_p5_replay_viewer.py
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.replay import play, record          # noqa: E402
from mdg.verifier import verifier as V        # noqa: E402
from mdg.viewer import app as viewer          # noqa: E402

_MDG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _StubGraph:
    """record 테스트용 .stream(inp, cfg, stream_mode='updates') 만 노출하는 최소 graph."""
    def __init__(self, updates):
        self._updates = updates

    def stream(self, inp, cfg, stream_mode="updates"):
        assert stream_mode == "updates"
        for u in self._updates:
            yield u


def _synthetic_updates():
    """3 tick: 정상 -> cross-root-inconsistent(silent,streak1) -> telemetry-silence(streak2).
    에이전트는 매 tick 'Continue' 결정 (nominal)하므로 tick 1&2 는 agent≠truth 발산."""
    hb = {"metric": "Link_Heartbeat", "channel": "plaintext_mavlink_tap",
          "domain": "communication", "band": "normal", "value": 3,
          "verified": True, "tamper": False, "source_id": "air_telemetry_tap"}
    loss = {"metric": "Packet_Loss", "channel": "plaintext_mavlink_tap",
            "domain": "communication", "band": "warning", "value": 100,
            "verified": True, "tamper": False, "source_id": "air_telemetry_tap"}
    wsl = {"role_verified": {"gcs_proxy": True}}
    ups = []
    for i, ev in enumerate([hb, loss, loss], start=1):
        ups.append({"sense": {"evidence": [ev], "worldstate": wsl, "tick_i": i}})
        ups.append({"decide": {"decisions": [{"decision": "Continue", "enforcement": "auto"}]}})
    return ups


def _record_to(path: str) -> None:
    g = _StubGraph(_synthetic_updates())
    seq = 0
    cfg = {"configurable": {"thread_id": "t"}}
    # 모든 update 를 하나의 논리적 run 으로 기록 (stub 의 단일 stream 에 걸쳐 append)
    record.record_stream(g, None, cfg, path, seq_start=seq)


def test_record_byte_identical():
    with tempfile.TemporaryDirectory() as d:
        a, b = os.path.join(d, "a.jsonl"), os.path.join(d, "b.jsonl")
        _record_to(a)
        _record_to(b)
        with open(a, "rb") as fa, open(b, "rb") as fb:
            assert fa.read() == fb.read(), "recording is not byte-identical across runs"
        # 모든 라인은 정규 스키마의 유효한 JSON
        for ln in open(a, encoding="utf-8"):
            obj = json.loads(ln)
            assert set(obj) == {"seq", "node", "patch"}, obj


# PRODUCTION 드라이버 (run_driver -> _tick)를 결정론적 stub graph 에 대해 end-to-end 구동하고
# run.jsonl 을 argv[1] 에 쓰는 독립 프로그램. subprocess 로 실행하여 PYTHONHASHSEED 를
# 변경할 수 있음 — 최상위 projected-key 순서는 _RECORD_ALLOW *set* (to_record) 순회에서 오며,
# 이는 프로세스마다 hash-seed 에 의존. 정규 recorder (sort_keys)가 그와 무관하게 run.jsonl 을
# byte-identical 로 만들어야 함 (GATE2).
_DRIVER_PROG = textwrap.dedent(
    """
    import sys
    sys.path.insert(0, sys.argv[2])
    from mdg.core.driver import run_driver

    class _G:
        def __init__(self):
            self.n = 0
        def stream(self, inp, cfg, stream_mode="updates"):
            # one stream pass = one tick; a multi-key sense patch exercises set-order keys
            yield {"sense": {"tick_i": self.n + 1, "config_version": "v1", "evidence": [],
                             "worldstate": {"z": 1, "a": 2}, "impact": {"band": "normal"},
                             "trust": {"gcs_proxy": True}, "pivots": 0, "dry_streak": 0}}
            yield {"decide": {"decisions": [{"decision": "Continue", "enforcement": "auto"}]}}
            self.n += 1
        def get_state(self, cfg):
            class _S:
                pass
            s = _S()
            s.values = {"tick_i": self.n, "goal_reached": self.n >= 3,
                        "pivots": 0, "dry_streak": 0}
            return s

    run_driver(_G(), "run", jsonl_path=sys.argv[1],
               max_iters=10, max_pivots=10, k_dry=10)
    """
)


def test_driver_production_path_byte_identical():
    """PRODUCTION 경로의 GATE2: run_driver/_tick 이 정규 recorder 에 위임하므로,
    동일한 결정론적 입력은 서로 다른 hash seed 프로세스 간에도 byte-identical run.jsonl 을
    산출 (sort_keys 없이 갈라진 옛 json.dumps 는 이를 실패했음)."""
    parent = os.path.dirname(_MDG)
    with tempfile.TemporaryDirectory() as d:
        prog = os.path.join(d, "drv.py")
        with open(prog, "w", encoding="utf-8") as fh:
            fh.write(_DRIVER_PROG)
        outs = []
        for seed in ("0", "1"):
            out = os.path.join(d, f"run_{seed}.jsonl")
            env = dict(os.environ, PYTHONHASHSEED=seed)
            r = subprocess.run([sys.executable, prog, out, parent],
                               env=env, capture_output=True, text=True)
            assert r.returncode == 0, f"driver run failed (seed {seed}): {r.stderr}"
            with open(out, "rb") as f:
                outs.append(f.read())
        assert outs[0] and outs[1], "driver produced empty run.jsonl"
        assert outs[0] == outs[1], "production run.jsonl not byte-identical across hash seeds"
        # 방출 스키마는 정규 {seq,node,patch} (레거시 {node:patch} 아님)
        first = json.loads(outs[0].splitlines()[0])
        assert set(first) == {"seq", "node", "patch"}, first
        # seq 는 run 전체에서 0 부터 단조 (tick 간 이어짐)
        seqs = [json.loads(ln)["seq"] for ln in outs[0].splitlines()]
        assert seqs == list(range(len(seqs))), seqs


class _FakeSaver:
    """InMemorySaver 형태 stub: delete_thread(thread_id) 호출을 기록 (P3 pruning)."""
    def __init__(self):
        self.deleted = []

    def delete_thread(self, thread_id):
        self.deleted.append(thread_id)


class _GraphWithSaver:
    """(.checkpointer 를 지닌) 결정론적 multi-tick stub (컴파일된 Pregel 처럼)."""
    def __init__(self, saver, goal_at=3):
        self.n = 0
        self.checkpointer = saver
        self._goal_at = goal_at

    def stream(self, inp, cfg, stream_mode="updates"):
        yield {"sense": {"tick_i": self.n + 1, "pivots": 0, "dry_streak": 0}}
        self.n += 1

    def get_state(self, cfg):
        class _S:
            pass
        s = _S()
        s.values = {"tick_i": self.n, "goal_reached": self.n >= self._goal_at,
                    "pivots": 0, "dry_streak": 0}
        return s


def test_driver_prunes_prior_tick_thread_p3():
    """P3: run_driver 는 대체된 per-tick thread 를 각각 삭제하여 InMemorySaver 가
    O(ticks) 대신 O(1) 로 유지되게 함. tick 3 에서 goal 도달 (thread run-t0..run-t2): 이전
    두 thread (t0, t1)는 pruning; 최종 잔여 thread (t2)는 남음 (경계됨)."""
    from mdg.core.driver import run_driver
    saver = _FakeSaver()
    final = run_driver(_GraphWithSaver(saver, goal_at=3), "run",
                       max_iters=10, max_pivots=10, k_dry=10)
    assert final["tick_i"] == 3 and final["goal_reached"] is True
    # 대체된 두 thread 만 순서대로 삭제, 현재/마지막 것은 절대 아님
    assert saver.deleted == ["run-t0", "run-t1"], saver.deleted


def test_driver_prune_fail_safe_no_delete_thread():
    """Fail-safe: delete_thread 없는 checkpointer (langgraph-checkpoint < 2.0.25) 또는
    checkpointer 가 아예 없어도, 루프는 올바르게 실행되며 절대 crash 안 함 (단지 unpruned)."""
    from mdg.core.driver import run_driver

    class _NoDelete:            # delete_thread 없는 saver (구버전 checkpoint 빌드)
        pass
    g = _GraphWithSaver(_NoDelete(), goal_at=2)
    assert run_driver(g, "run", max_iters=10, max_pivots=10, k_dry=10)["tick_i"] == 2
    g2 = _GraphWithSaver(None, goal_at=2)   # checkpointer 가 None (없이 컴파일)
    assert run_driver(g2, "run", max_iters=10, max_pivots=10, k_dry=10)["tick_i"] == 2


def test_record_secret_scrub():
    # ALLOWED 문자열 필드에 canary 를 담은 patch 는 record 시점에 scrub 되어야 함
    canary_key = "sk-ant-" + "abcd1234efgh"  # 런타임 생성하여 소스 리터럴이 verify_keys 를 건드리지 않게 함
    line = record.canonical_line(0, "sense", {"config_version": "api_key=MDG_CANARY_LLM " + canary_key})
    assert "MDG_CANARY_LLM" not in line and canary_key not in line
    assert "[REDACTED]" in line
    json.loads(line)  # 여전히 유효한 JSON
    # UNDECLARED 키는 to_record projection 이 드롭 (default-deny)
    line2 = record.canonical_line(0, "sense", {"secret_smuggled": "MDG_CANARY_OP"})
    assert "MDG_CANARY_OP" not in line2 and "secret_smuggled" not in line2


def test_play_reconstruct_both_schemas():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "run.jsonl")
        _record_to(p)
        ticks = play.load_timeline(p)
        assert len(ticks) == 3, f"expected 3 ticks, got {len(ticks)}"
        assert ticks[0].last_decision()["decision"] == "Continue"
        assert len(ticks[0].evidence) == 1
        # 레거시 {node: patch} 스키마 허용
        legacy = os.path.join(d, "legacy.jsonl")
        with open(legacy, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"sense": {"evidence": [], "tick_i": 1}}) + "\n")
            fh.write(json.dumps({"decide": {"decisions": [{"decision": "Mission Abort"}]}}) + "\n")
        lt = play.load_timeline(legacy)
        assert len(lt) == 1 and lt[0].last_decision()["decision"] == "Mission Abort"


def test_verifier_truth_and_divergence():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "run.jsonl")
        _record_to(p)
        verdicts = V.verify_run(p)
        assert len(verdicts) == 3
        assert verdicts[0].verdict == V.LINK_HEALTHY, verdicts[0]
        assert verdicts[1].verdict == V.CROSS_ROOT_INCONSISTENT, verdicts[1]
        assert verdicts[2].verdict == V.TELEMETRY_SILENCE, verdicts[2]
        # cross-root ∧: tick0 양 root up -> consistent True
        assert verdicts[0].cross_root_consistent is True
        # tick 1, 2 에서 agent≠truth (agent 'Continue' vs silence/inconsistent)
        assert verdicts[0].agent_truth_divergence is False
        assert verdicts[1].agent_truth_divergence is True
        assert verdicts[2].agent_truth_divergence is True
        s = V.summarize(verdicts)
        assert s["agent_truth_divergences"] == 2 and s["silence"] == 1


def test_gcs_proxy_alive_p5q3_layering():
    """P5-Q3: role_verified 우선; behaviorally_verified 는 POSITIVE 전용 업그레이드
    (절대 다운그레이드 아님); .get 가드는 키 없는 레거시 worldstate 를 degrade."""
    ga = V._gcs_proxy_alive
    hb = {"metric": "Link_Heartbeat", "channel": "plaintext_mavlink_tap",
          "domain": "communication", "tamper": False, "source_id": "air_telemetry_tap"}
    # 1. role_verified True -> True (우선, short-circuit)
    assert ga({"role_verified": {"gcs_proxy": True}}, []) is True
    # 2. behaviorally_verified True 는 존재하나 False 인 role_verified 를 업그레이드 -> True
    assert ga({"role_verified": {"gcs_proxy": False},
               "behaviorally_verified": {"gcs_proxy": True}}, []) is True
    # 2b. behaviorally_verified True 는 role_verified 부재 시에도 업그레이드 -> True
    assert ga({"behaviorally_verified": {"gcs_proxy": True}}, []) is True
    # 3. behaviorally_verified False 는 절대 다운그레이드 아님: 존재하나 False 인 role 은 False 유지,
    #    그리고 False anchor 단독 (role 키 없음)은 unknown (None) 유지, 절대 강제 False 아님
    assert ga({"role_verified": {"gcs_proxy": False},
               "behaviorally_verified": {"gcs_proxy": False}}, []) is False
    assert ga({"behaviorally_verified": {"gcs_proxy": False}}, []) is None
    # 4. behaviorally_verified 키 없는 레거시 worldstate 는 role_verified/None 로 degrade
    assert ga({"role_verified": {"gcs_proxy": False}}, []) is False
    assert ga({}, []) is None
    # positive tap evidence 는 여전히 낡은 존재-하나-False inspect 를 override
    assert ga({"role_verified": {"gcs_proxy": False}},
              [dict(hb, source_id="air_command_tap", domain="command")]) is True


def test_verifier_grep0_no_core_import():
    """PA-2 grep0: Verifier 모듈은 mdg.core.* 를 전혀 import 하지 않음 (독립 trust root)."""
    src = open(os.path.join(_MDG, "verifier", "verifier.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    mods = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            mods.append(n.module or "")
    bad = [m for m in mods if m == "mdg.core" or m.startswith("mdg.core.") or m.startswith("mdg.replay")]
    assert not bad, f"verifier imports forbidden module(s): {bad}"


def test_viewer_panels_and_failclosed():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "run.jsonl")
        _record_to(p)
        panels = viewer.load_panels(p)
        # 경보성 banner 텍스트 제거됨 (2026-07); agent≠truth 의미는 header meta 로 잔존
        assert "text" not in panels["banner"]
        assert "mdg.verifier" in panels["banner"]["trust_root"]
        assert panels["banner"]["divergences"] == 2
        assert panels["record_time_redact"] is True and panels["read_only"] is True
        assert len(panels["panels"]["action"]) == 3
        assert len(panels["panels"]["verification"]) == 3
        # communication 패널은 telemetry 행을 담음
        comm = panels["panels"]["communication"]
        assert any(row["telemetry"] for row in comm)
        # fail-closed: 오염된 파일은 거부, 표시 시점에 redact 안 함 (PS-3)
        tainted = os.path.join(d, "tainted.jsonl")
        with open(tainted, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": 0, "node": "sense",
                                 "patch": {"config_version": "MDG_CANARY_HMAC"}}) + "\n")
        assert viewer.scan_secrets(open(tainted, encoding="utf-8").read())
        try:
            viewer.load_panels(tainted)
            raise AssertionError("expected SecretLeakError on tainted run.jsonl")
        except viewer.SecretLeakError:
            pass


def test_classify_view_standing_vs_attack():
    """표현계층 분류(2026-07): 상시(구조적) 시그니처는 로그 밴드에서 제외하여 평시로 두고,
    비-상시 공격 시그니처만 위험/주의를 유발한다. (탐지 엔진 출력은 불변; 순수 표현계층)"""
    # 상시조건만 있으면 평시(Green), attack_signals 비어있음
    assert viewer._classify_view(["Unauthorized_Command"]) == ([], "Green")
    assert viewer._classify_view([]) == ([], "Green")
    # 상시 + 실제 공격이면 위험(Red), attack_signals 는 공격만 남김
    atk, band = viewer._classify_view(["Unauthorized_Command", "PFCP_Delete_Attempt"])
    assert band == "Red" and atk == ["PFCP_Delete_Attempt"]
    # 저심각(정찰) 단독이면 주의(Yellow)
    assert viewer._classify_view(["Recon"]) == (["Recon"], "Yellow")
    # 저심각 + 상시면 주의 (상시 제거 후 저심각만 남으므로)
    assert viewer._classify_view(["Recon", "Unauthorized_Command"]) == (["Recon"], "Yellow")


def test_viewer_standing_panel_and_view_band():
    """load_panels 가 상시 취약 노드 상태(standing)와 틱별 view_band/attack_signals 를 노출한다."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "run.jsonl")
        _record_to(p)
        panels = viewer.load_panels(p)
        assert "standing" in panels                       # 우측 상태 패널 데이터
        for row in panels["panels"]["action"]:
            assert row["view_band"] in ("Red", "Yellow", "Green")
            assert isinstance(row["attack_signals"], list)
            # attack_signals 는 상시 시그니처를 포함하지 않는다
            assert not (set(row["attack_signals"]) & set(viewer.STANDING_SIGNALS))


def _tele(metric, value):
    return {"metric": metric, "value": value, "band": "normal",
            "domain": "communication", "channel": "plaintext_mavlink_tap"}


def _write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as fh:
        for seq, (node, patch) in enumerate(lines):
            fh.write(json.dumps({"seq": seq, "node": node, "patch": patch}) + "\n")


def test_recovery_panel_lifecycle_and_flight():
    """Phase 7: load_panels 는 recovery 패널을 방출 — 사건별 lifecycle
    (탐지 -> 대응 -> 집행 -> 확인 -> 회복)을 ledger/worldstate.applied/view_band + rel_alt/flight_mode
    flight 시리즈로부터. S2 형태 run: attack(Red, alt 12) -> operator-auto enforce -> confirm/recover
    (Green, alt 30)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "run.jsonl")
        applied_unconf = {"applied": {"signed_guided": {
            "rule": "signed_guided", "revert_cmd": "mode LAND", "confirmed": False}}}
        applied_conf = {"applied": {"signed_guided": {
            "rule": "signed_guided", "revert_cmd": "mode LAND", "confirmed": True}}}
        intent = {"rule": "signed_guided", "tool_id": "send_signed_mode",
                  "revert_cmd": "mode LAND", "operator_gate": False,
                  "operator_auto_confirmed": True, "provenance_relaxed": True}
        _write_lines(p, [
            # tick 0 — attack 가시 (Red), LAND injection 하에서 고도가 12m 로 떨어짐,
            # operator-auto OPER 도구 실행 (ledger intent + applied[rule] unconfirmed).
            # incident member 는 실제 command-hijack 시그니처 (Unauthorized_Command)로,
            # 이는 STANDING_SIGNAL: view_band 가 이를 Green 으로 벗김, 따라서 recovery 카드는 반드시
            # 밴드를 engine impact_band / incident 존재로부터 소싱해야 함 (view_band 아님) —
            # 아니면 flight-hijack 시나리오가 밴드 Green-to-Green (공격 없음)으로 렌더됨. Phase 7
            # 핵심 S2 산출물에 대한 회귀.
            ("sense", {"tick_i": 1, "evidence": [_tele("rel_alt", 12), _tele("flight_mode", "LAND")],
                       "incidents": [{"members": ["Unauthorized_Command"]}]}),
            ("decide", {"decisions": [{"decision": "Graceful Degradation", "enforcement": "auto"}]}),
            ("act", {"ledger": [intent], "worldstate": applied_unconf}),
            # tick 1 — 복구됨: incident 없음 (Green), alt 30m 복귀, effect_confirm 이 confirmed 설정
            ("sense", {"tick_i": 2, "evidence": [_tele("rel_alt", 30), _tele("flight_mode", "GUIDED")]}),
            ("decide", {"decisions": [{"decision": "Continue", "enforcement": "auto"}]}),
            ("effect_confirm", {"worldstate": applied_conf}),
        ])
        panels = viewer.load_panels(p)
        assert "recovery" in panels
        rec = panels["recovery"]
        # flight 시리즈는 tick 별 rel_alt/flight_mode 를 담음
        alts = [f["rel_alt"] for f in rec["flight"] if f["rel_alt"] is not None]
        assert 12.0 in alts and 30.0 in alts, rec["flight"]
        assert any(f["flight_mode"] == "GUIDED" for f in rec["flight"])
        # 정확히 하나의 recovery 이벤트, 완전히 실현된 lifecycle
        assert len(rec["events"]) == 1, rec["events"]
        e = rec["events"][0]
        assert e["tool"] == "send_signed_mode" and e["rule"] == "signed_guided"
        assert e["enforced"] is True and e["confirmed"] is True
        assert e["operator_auto_confirmed"] is True and "OPER" in e["tier"]
        assert e["revert_cmd"] == "mode LAND"
        done = {s["label"]: s["done"] for s in e["steps"]}
        assert all(done[k] for k in ("탐지", "대응", "집행", "확인", "회복")), done
        # 집행 step 은 sandbox auto 플래그를 담음; 밴드 + 고도 회복
        enf = next(s for s in e["steps"] if s["label"] == "집행")
        assert enf["auto"] is True
        # recovery 카드는 공격 시그니처가 view_band 로 Green 처리되는 STANDING 시그널임에도 불구하고
        # 반드시 탐지-to-회복 을 밴드 전이로 보여줘야 함 (실제 결함).
        assert e["band_before"] == "Red" and e["band_after"] == "Green"
        assert e["alt_before"] == 12.0 and e["alt_after"] == 30.0
        # 수정이 핵심임의 증명: THIS run 에서 로그의 view_band 는 attack tick 에서 Green
        # (standing 시그널 필터됨) — 따라서 recovery 밴드는 view_band 에서 소싱될 수 없음.
        act0 = panels["panels"]["action"][0]
        assert "Unauthorized_Command" in act0["signals"]
        assert act0["view_band"] == "Green"        # view_band 는 standing-metric attack 을 숨김
        assert act0["attack_signals"] == []        # (반면 위 recovery 밴드는 Red 표시)


def test_recovery_panel_signed_mechanism_annotations():
    """Item C: send_signed_mode (S2 물리 복귀) recovery 이벤트는 그 메커니즘을 렌더 —
    대응(operator-select) -> 집행(gcs_c2 위임) -> 확인(rel_alt 30m) — per-step 노트로, 그리고
    이벤트는 signed 로 플래그되어 카드가 S2 물리 복귀 맥락을 보여줌. 기본 라벨
    (탐지/대응/집행/확인/회복)은 불변 (표현 전용 보강)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "run.jsonl")
        applied_unconf = {"applied": {"signed_guided": {
            "rule": "signed_guided", "confirmed": False}}}
        applied_conf = {"applied": {"signed_guided": {
            "rule": "signed_guided", "confirmed": True}}}
        intent = {"rule": "signed_guided", "tool_id": "send_signed_mode",
                  "operator_gate": False}
        _write_lines(p, [
            ("sense", {"tick_i": 1, "evidence": [_tele("rel_alt", 12), _tele("flight_mode", "LAND")],
                       "incidents": [{"members": ["Unauthorized_Command"]}]}),
            ("act", {"ledger": [intent], "worldstate": applied_unconf}),
            ("sense", {"tick_i": 2, "evidence": [_tele("rel_alt", 30), _tele("flight_mode", "GUIDED")]}),
            ("effect_confirm", {"worldstate": applied_conf}),
        ])
        rec = viewer.load_panels(p)["recovery"]
        assert len(rec["events"]) == 1
        e = rec["events"][0]
        assert e["signed"] is True and e["tool"] == "send_signed_mode"
        note = {s["label"]: s.get("note") for s in e["steps"]}
        assert note["대응"] == "operator-select"
        assert note["집행"] == "gcs_c2 위임"
        assert note["확인"] == "rel_alt 30m"
        # 탐지/회복 step 은 메커니즘 노트 없음 (respond/enforce/confirm 만 주석)
        assert note["탐지"] is None and note["회복"] is None
        # containment 복구는 주석 없음 / signed=False 유지
        assert viewer._is_signed_recovery("nsenter_input_drop", "pfcp_firewall") is False
        assert viewer._is_signed_recovery("send_signed_mode", "signed_guided") is True


def test_recovery_band_prefers_engine_impact_over_view_band():
    """단위: _recovery_band 는 존재 시 엔진의 권위 있는 per-tick impact_band (Green/Yellow/Red)를
    사용하고, 부재 시 incident 존재 (_detect_band, standing 시그널 포함)로 폴백 —
    standing 필터된 view_band 는 절대 아님."""
    # engine impact_band 존재 -> 그대로 사용 (view_band 가 불일치하더라도)
    assert viewer._recovery_band({"impact_band": "Red", "signals": []}) == "Red"
    assert viewer._recovery_band({"impact_band": "Green", "signals": ["Unauthorized_Command"]}) == "Green"
    # impact_band 부재/무효 -> standing 시그널을 포함하는 detection 밴드로 폴백
    assert viewer._recovery_band({"impact_band": None, "signals": ["Unauthorized_Command"]}) == "Red"
    assert viewer._recovery_band({"signals": ["Recon"]}) == "Yellow"
    assert viewer._recovery_band({"signals": []}) == "Green"
    # _detect_band (recovery)는 _classify_view (log)처럼 standing 시그널을 벗기지 않음
    assert viewer._detect_band(["Unauthorized_Command"]) == "Red"
    assert viewer._classify_view(["Unauthorized_Command"]) == ([], "Green")


def test_recovery_panel_empty_when_no_ledger():
    """run 에 enforcement 없음 -> recovery.events 비어있음 (viewer 는 crash 아닌 대기 카드 표시)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "run.jsonl")
        _record_to(p)                       # synthetic run 은 ledger / applied / rel_alt 없음
        rec = viewer.load_panels(p)["recovery"]
        assert rec["events"] == [] and rec["flight"] == []
        assert rec["flight_target"] == 30.0


def test_viewer_bind_loopback_only():
    """PS-8: serve() 는 0.0.0.0 / public bind 거부 (attacker UE 가 mgmt plane 에 도달해선 안 됨)."""
    for bad in ("0.0.0.0", "::", "", "8.8.8.8", "203.0.113.5"):
        try:
            viewer.serve("x.jsonl", host=bad, port=1)
            raise AssertionError(f"serve accepted non-loopback host {bad!r}")
        except ValueError:
            pass
        except ImportError:
            raise AssertionError("host validation must run BEFORE the uvicorn import")


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
