"""test_p5_replay_viewer — P5 Verifier + Viewer + replay self-verify (runnable standalone).

Exercises the four locked P5 properties without langgraph/fastapi:
  - record.py: byte-identical canonical lines + secret scrub (PS-3)
  - play.py: tick-timeline reconstruction (both schemas)
  - verifier.py: independent cross-root truth + telemetry-silence + agent≠truth divergence,
    AND grep0 (the Verifier module imports NO mdg.core.*)
  - viewer/app.py: pure 3-panel builder + fail-closed secret scan + loopback-only bind (PS-8)

Run: python mdg/tests/test_p5_replay_viewer.py
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
    """Minimal graph exposing .stream(inp, cfg, stream_mode='updates') for record tests."""
    def __init__(self, updates):
        self._updates = updates

    def stream(self, inp, cfg, stream_mode="updates"):
        assert stream_mode == "updates"
        for u in self._updates:
            yield u


def _synthetic_updates():
    """3 ticks: healthy -> cross-root-inconsistent(silent,streak1) -> telemetry-silence(streak2).
    Agent decides 'Continue' every tick (nominal) so ticks 1&2 are agent≠truth divergences."""
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
    # record all updates as ONE logical run (append across the stub's single stream)
    record.record_stream(g, None, cfg, path, seq_start=seq)


def test_record_byte_identical():
    with tempfile.TemporaryDirectory() as d:
        a, b = os.path.join(d, "a.jsonl"), os.path.join(d, "b.jsonl")
        _record_to(a)
        _record_to(b)
        with open(a, "rb") as fa, open(b, "rb") as fb:
            assert fa.read() == fb.read(), "recording is not byte-identical across runs"
        # every line is valid JSON with the canonical schema
        for ln in open(a, encoding="utf-8"):
            obj = json.loads(ln)
            assert set(obj) == {"seq", "node", "patch"}, obj


# Standalone program that drives the PRODUCTION driver (run_driver -> _tick) end-to-end
# against a deterministic stub graph and writes run.jsonl to argv[1]. Run in a subprocess so
# we can vary PYTHONHASHSEED — the top-level projected-key order comes from iterating the
# _RECORD_ALLOW *set* (to_record), which is hash-seed dependent across processes. The
# canonical recorder (sort_keys) must make run.jsonl byte-identical regardless (GATE2).
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
    """GATE2 on the PRODUCTION path: run_driver/_tick delegates to the canonical recorder, so
    identical deterministic input yields byte-identical run.jsonl even across processes with
    different hash seeds (the old forked json.dumps without sort_keys failed this)."""
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
        # emitted schema is canonical {seq,node,patch} (not legacy {node:patch})
        first = json.loads(outs[0].splitlines()[0])
        assert set(first) == {"seq", "node", "patch"}, first
        # seq is monotonic from 0 across the whole run (carried across ticks)
        seqs = [json.loads(ln)["seq"] for ln in outs[0].splitlines()]
        assert seqs == list(range(len(seqs))), seqs


class _FakeSaver:
    """InMemorySaver-shaped stub: records delete_thread(thread_id) calls (P3 pruning)."""
    def __init__(self):
        self.deleted = []

    def delete_thread(self, thread_id):
        self.deleted.append(thread_id)


class _GraphWithSaver:
    """Deterministic multi-tick stub carrying a .checkpointer (like a compiled Pregel)."""
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
    """P3: run_driver deletes each superseded per-tick thread so the InMemorySaver stays
    O(1) instead of O(ticks). Runs to goal at tick 3 (threads run-t0..run-t2): the two
    prior threads (t0, t1) are pruned; the final residual thread (t2) is left (bounded)."""
    from mdg.core.driver import run_driver
    saver = _FakeSaver()
    final = run_driver(_GraphWithSaver(saver, goal_at=3), "run",
                       max_iters=10, max_pivots=10, k_dry=10)
    assert final["tick_i"] == 3 and final["goal_reached"] is True
    # exactly the two superseded threads deleted, in order, never the current/last one
    assert saver.deleted == ["run-t0", "run-t1"], saver.deleted


def test_driver_prune_fail_safe_no_delete_thread():
    """Fail-safe: on a checkpointer WITHOUT delete_thread (langgraph-checkpoint < 2.0.25) or
    no checkpointer at all, the loop must run correctly and never crash (just unpruned)."""
    from mdg.core.driver import run_driver

    class _NoDelete:            # saver lacking delete_thread (older checkpoint build)
        pass
    g = _GraphWithSaver(_NoDelete(), goal_at=2)
    assert run_driver(g, "run", max_iters=10, max_pivots=10, k_dry=10)["tick_i"] == 2
    g2 = _GraphWithSaver(None, goal_at=2)   # checkpointer is None (compiled w/o one)
    assert run_driver(g2, "run", max_iters=10, max_pivots=10, k_dry=10)["tick_i"] == 2


def test_record_secret_scrub():
    # a patch carrying a canary in an ALLOWED string field must be scrubbed at record time
    canary_key = "sk-ant-" + "abcd1234efgh"  # built at runtime so no source literal trips verify_keys
    line = record.canonical_line(0, "sense", {"config_version": "api_key=MDG_CANARY_LLM " + canary_key})
    assert "MDG_CANARY_LLM" not in line and canary_key not in line
    assert "[REDACTED]" in line
    json.loads(line)  # still valid JSON
    # an UNDECLARED key is dropped by to_record projection (default-deny)
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
        # legacy {node: patch} schema tolerated
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
        # cross-root ∧: tick0 both roots up -> consistent True
        assert verdicts[0].cross_root_consistent is True
        # agent≠truth on ticks 1 and 2 (agent 'Continue' vs silence/inconsistent)
        assert verdicts[0].agent_truth_divergence is False
        assert verdicts[1].agent_truth_divergence is True
        assert verdicts[2].agent_truth_divergence is True
        s = V.summarize(verdicts)
        assert s["agent_truth_divergences"] == 2 and s["silence"] == 1


def test_gcs_proxy_alive_p5q3_layering():
    """P5-Q3: role_verified primary; behaviorally_verified is a POSITIVE-only upgrade
    (never a downgrade); .get guard degrades legacy worldstate w/o the key."""
    ga = V._gcs_proxy_alive
    hb = {"metric": "Link_Heartbeat", "channel": "plaintext_mavlink_tap",
          "domain": "communication", "tamper": False, "source_id": "air_telemetry_tap"}
    # 1. role_verified True -> True (primary, short-circuit)
    assert ga({"role_verified": {"gcs_proxy": True}}, []) is True
    # 2. behaviorally_verified True upgrades a present-but-False role_verified -> True
    assert ga({"role_verified": {"gcs_proxy": False},
               "behaviorally_verified": {"gcs_proxy": True}}, []) is True
    # 2b. behaviorally_verified True upgrades even when role_verified absent -> True
    assert ga({"behaviorally_verified": {"gcs_proxy": True}}, []) is True
    # 3. behaviorally_verified False is NEVER a downgrade: present-but-False role stays False,
    #    and a False anchor alone (no role key) stays unknown (None), never forced False
    assert ga({"role_verified": {"gcs_proxy": False},
               "behaviorally_verified": {"gcs_proxy": False}}, []) is False
    assert ga({"behaviorally_verified": {"gcs_proxy": False}}, []) is None
    # 4. legacy worldstate without the behaviorally_verified key degrades to role_verified/None
    assert ga({"role_verified": {"gcs_proxy": False}}, []) is False
    assert ga({}, []) is None
    # positive tap evidence still overrides a stale present-but-False inspect
    assert ga({"role_verified": {"gcs_proxy": False}},
              [dict(hb, source_id="air_command_tap", domain="command")]) is True


def test_verifier_grep0_no_core_import():
    """PA-2 grep0: the Verifier module imports NO mdg.core.* (independent trust root)."""
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
        # alarming banner text removed (2026-07); agent≠truth semantics survive as header meta
        assert "text" not in panels["banner"]
        assert "mdg.verifier" in panels["banner"]["trust_root"]
        assert panels["banner"]["divergences"] == 2
        assert panels["record_time_redact"] is True and panels["read_only"] is True
        assert len(panels["panels"]["action"]) == 3
        assert len(panels["panels"]["verification"]) == 3
        # communication panel carries telemetry rows
        comm = panels["panels"]["communication"]
        assert any(row["telemetry"] for row in comm)
        # fail-closed: a tainted file is refused, NOT redacted at display time (PS-3)
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
    assert viewer._classify_view(["Port_5762_State", "BACKDOOR_5762"]) == ([], "Green")
    assert viewer._classify_view([]) == ([], "Green")
    # 상시 + 실제 공격이면 위험(Red), attack_signals 는 공격만 남김
    atk, band = viewer._classify_view(["Unauthorized_Command", "PFCP_Delete_Attempt"])
    assert band == "Red" and atk == ["PFCP_Delete_Attempt"]
    # 저심각(정찰) 단독이면 주의(Yellow)
    assert viewer._classify_view(["Recon"]) == (["Recon"], "Yellow")
    # 저심각 + 상시면 주의 (상시 제거 후 저심각만 남으므로)
    assert viewer._classify_view(["Recon", "Port_5762_State"]) == (["Recon"], "Yellow")


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
    """Phase 7: load_panels emits a `recovery` panel — per-incident lifecycle
    (탐지 -> 대응 -> 집행 -> 확인 -> 회복) from ledger/worldstate.applied/view_band + a rel_alt/flight_mode
    flight series. S2-shaped run: attack(Red, alt 12) -> operator-auto enforce -> confirm/recover
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
            # tick 0 — attack visible (Red), altitude dropped to 12m under LAND injection,
            # operator-auto OPER tool executes (ledger intent + applied[rule] unconfirmed).
            # The incident member is the REAL command-hijack signature (Unauthorized_Command),
            # which is a STANDING_SIGNAL: view_band strips it to Green, so the recovery card MUST
            # source its band from the engine impact_band / incident presence (not view_band) —
            # else the flight-hijack scenario renders as 밴드 Green-to-Green (no attack). Regression
            # for the Phase 7 headline S2 deliverable.
            ("sense", {"tick_i": 1, "evidence": [_tele("rel_alt", 12), _tele("flight_mode", "LAND")],
                       "incidents": [{"members": ["Unauthorized_Command"]}]}),
            ("decide", {"decisions": [{"decision": "Graceful Degradation", "enforcement": "auto"}]}),
            ("act", {"ledger": [intent], "worldstate": applied_unconf}),
            # tick 1 — recovered: no incident (Green), alt back to 30m, effect_confirm sets confirmed
            ("sense", {"tick_i": 2, "evidence": [_tele("rel_alt", 30), _tele("flight_mode", "GUIDED")]}),
            ("decide", {"decisions": [{"decision": "Continue", "enforcement": "auto"}]}),
            ("effect_confirm", {"worldstate": applied_conf}),
        ])
        panels = viewer.load_panels(p)
        assert "recovery" in panels
        rec = panels["recovery"]
        # flight series carries rel_alt/flight_mode per tick
        alts = [f["rel_alt"] for f in rec["flight"] if f["rel_alt"] is not None]
        assert 12.0 in alts and 30.0 in alts, rec["flight"]
        assert any(f["flight_mode"] == "GUIDED" for f in rec["flight"])
        # exactly one recovery event, fully realized lifecycle
        assert len(rec["events"]) == 1, rec["events"]
        e = rec["events"][0]
        assert e["tool"] == "send_signed_mode" and e["rule"] == "signed_guided"
        assert e["enforced"] is True and e["confirmed"] is True
        assert e["operator_auto_confirmed"] is True and "OPER" in e["tier"]
        assert e["revert_cmd"] == "mode LAND"
        done = {s["label"]: s["done"] for s in e["steps"]}
        assert all(done[k] for k in ("탐지", "대응", "집행", "확인", "회복")), done
        # the 집행 step carries the sandbox auto flag; band + altitude recover
        enf = next(s for s in e["steps"] if s["label"] == "집행")
        assert enf["auto"] is True
        # the recovery card MUST show 탐지-to-회복 as a band transition even though the attack
        # signature is a STANDING signal that view_band strips to Green (the real defect).
        assert e["band_before"] == "Red" and e["band_after"] == "Green"
        assert e["alt_before"] == 12.0 and e["alt_after"] == 30.0
        # proof the fix is load-bearing: for THIS run the log's view_band is Green on the attack
        # tick (standing signal filtered) — so the recovery band cannot be sourced from view_band.
        act0 = panels["panels"]["action"][0]
        assert "Unauthorized_Command" in act0["signals"]
        assert act0["view_band"] == "Green"        # view_band hides the standing-metric attack
        assert act0["attack_signals"] == []        # (whereas the recovery band above shows Red)


def test_recovery_panel_signed_mechanism_annotations():
    """Item C: the send_signed_mode (S2 물리 복귀) recovery event renders its mechanism —
    대응(operator-select) -> 집행(gcs_c2 위임) -> 확인(rel_alt 30m) — as per-step notes, and the
    event is flagged ``signed`` so the card shows the S2 physical-return context. The base labels
    (탐지/대응/집행/확인/회복) are unchanged (presentation-only enrichment)."""
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
        # 탐지/회복 steps carry NO mechanism note (only respond/enforce/confirm annotated)
        assert note["탐지"] is None and note["회복"] is None
        # containment recoveries stay un-annotated / signed=False
        assert viewer._is_signed_recovery("nsenter_input_drop", "backdoor_drop") is False
        assert viewer._is_signed_recovery("send_signed_mode", "signed_guided") is True


def test_recovery_band_prefers_engine_impact_over_view_band():
    """Unit: `_recovery_band` uses the engine's authoritative per-tick impact_band (Green/Yellow/Red)
    when present, and falls back to incident-presence (`_detect_band`, standing signals INCLUDED)
    when it is absent — never the standing-filtered view_band."""
    # engine impact_band present -> used verbatim (even if view_band would disagree)
    assert viewer._recovery_band({"impact_band": "Red", "signals": []}) == "Red"
    assert viewer._recovery_band({"impact_band": "Green", "signals": ["Unauthorized_Command"]}) == "Green"
    # impact_band absent/invalid -> fall back to detection band that INCLUDES standing signals
    assert viewer._recovery_band({"impact_band": None, "signals": ["Unauthorized_Command"]}) == "Red"
    assert viewer._recovery_band({"signals": ["Port_5762_State"]}) == "Red"
    assert viewer._recovery_band({"signals": ["Recon"]}) == "Yellow"
    assert viewer._recovery_band({"signals": []}) == "Green"
    # _detect_band (recovery) does NOT strip standing signals the way _classify_view (log) does
    assert viewer._detect_band(["Unauthorized_Command"]) == "Red"
    assert viewer._classify_view(["Unauthorized_Command"]) == ([], "Green")


def test_recovery_panel_empty_when_no_ledger():
    """No enforcement in the run -> recovery.events empty (viewer shows a wait card, not a crash)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "run.jsonl")
        _record_to(p)                       # synthetic run has no ledger / applied / rel_alt
        rec = viewer.load_panels(p)["recovery"]
        assert rec["events"] == [] and rec["flight"] == []
        assert rec["flight_target"] == 30.0


def test_viewer_bind_loopback_only():
    """PS-8: serve() refuses 0.0.0.0 / public binds (attacker UE must not reach mgmt plane)."""
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
