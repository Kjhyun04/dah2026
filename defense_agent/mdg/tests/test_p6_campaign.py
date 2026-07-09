"""test_p6_campaign — P6 E2E campaign + honesty + artifacts self-verify (langgraph-free).

Exercises the six-attack harness end-to-end WITHOUT langgraph/network:
  - e2e.run_campaign: 6 attacks replay -> detect -> respond -> verify (DRY, operator-go)
  - 2대 불변식: 0 live executions (Backend DRY), routing via edges (numeric/bool only)
  - honest.py: disclosed limitations + banner + chapter mapping
  - artifacts.py: timeline / decisions / verifier_truth + CampaignResult -> 6-chapter report
  - PS-3: every run.jsonl is secret-free (viewer fail-closed scan passes)
  - GATE2: run.jsonl is byte-identical across runs
  - H-K: A6 telemetry-silence produces agent≠truth divergences via the independent Verifier

Run: python mdg/tests/test_p6_campaign.py   (or via pytest)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.campaign import artifacts, e2e, honest          # noqa: E402
from mdg.viewer import app as viewer                       # noqa: E402


def _run(out_dir: str):
    return e2e.run_campaign(out_dir)


def test_campaign_six_attacks_detected_and_zero_live():
    """All 6 attacks replay + detect; NO live state change (불변식2./operator-go)."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        assert c.total == 6, c.total
        assert c.detected_count == 6, "every attack must be detected"
        assert c.live_execution_count == 0, "operator-go: ZERO live executions allowed"
        for o in c.outcomes:
            assert o.live_execution is False
            assert o.incidents, f"{o.attack_id} produced no incident"
            # run.jsonl actually written
            assert os.path.exists(o.run_path), o.run_path


def test_detection_response_verification_spread():
    """The campaign shows a real detect->respond->verify spread (bands, tiers, divergence)."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        by = {o.attack_id: o for o in c.outcomes}
        # A1 command hijack (5762 ESTAB + unauth) -> command floor 71 -> Red
        assert by["A1_command_hijack_cr01"].top_impact_band == "Red"
        # A2 PFCP delete storm -> session floor -> Red, and it is a VERIFIED detection (B-1)
        assert by["A2_pfcp_teardown"].top_impact_band == "Red"
        assert by["A2_pfcp_teardown"].verified_detection is True
        # exactly 2 verified detections (telemetry D-1 + PFCP B-1), 4 unverified
        assert c.verified_count == 2, c.verified_count
        # responses that fire are OPER operator-gate (side-effect 0, operator-go): docker_pause
        responders = [o for o in c.outcomes if o.responded]
        assert responders, "at least one response must be selected"
        for o in responders:
            assert o.response_tier in ("OPER", "AUTO")
            assert o.response_dispatch in ("operator_gate", "inert_dry", "dry_argv", "escalated")
            assert o.live_execution is False


def test_A5_mission_weighted_dilution_stays_green():
    """A5 mongo/identity_access is under-weighted (w=10, conf 0.60) -> stays Green even when
    detected. This is the disclosed MISSION_WEIGHTED_DILUTION limitation, not a miss."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        a5 = next(o for o in c.outcomes if o.attack_id == "A5_mongo_dbaccess")
        assert a5.detected is True
        assert a5.top_impact_band == "Green"
        assert a5.responded is False


def test_A6_agent_not_truth_divergence():
    """H-K: telemetry-silence -> independent Verifier flags agent≠truth while agent stays
    nominal (Continue+Monitoring). The Verifier is a separate trust root (grep0)."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        a6 = next(o for o in c.outcomes if o.attack_id == "A6_telemetry_silence")
        assert a6.agent_truth_divergences >= 1, a6.truth_summary
        assert a6.verified_detection is True                # telemetry cross-tap (D-1)
        # campaign-level rollup counts the divergences
        assert c.divergence_count >= 1


def test_runjsonl_secret_free_and_byte_identical():
    """PS-3: every run.jsonl passes the viewer fail-closed secret scan. GATE2: byte-identical."""
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        c1 = _run(d1)
        c2 = _run(d2)
        for o in c1.outcomes:
            raw = open(o.run_path, encoding="utf-8").read()
            assert not viewer.scan_secrets(raw), f"{o.attack_id} run.jsonl has residual secret"
            # canonical schema {seq,node,patch}
            for ln in raw.splitlines():
                obj = json.loads(ln)
                assert set(obj) == {"seq", "node", "patch"}, obj
        # byte-identical per attack across two independent runs (deterministic clock, sort_keys)
        for o1, o2 in zip(c1.outcomes, c2.outcomes):
            b1 = open(o1.run_path, "rb").read()
            b2 = open(o2.run_path, "rb").read()
            assert b1 == b2, f"{o1.attack_id} run.jsonl not byte-identical"


def test_artifacts_timeline_decisions_verifier_truth():
    """artifacts builds the 3 reviewer artifacts purely from run.jsonl (portability pillar)."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        a1 = next(o for o in c.outcomes if o.attack_id == "A1_command_hijack_cr01")
        tl = artifacts.build_timeline(a1.run_path)
        assert tl and all("nodes" in t and "impact_band" in t for t in tl)
        # the flagship tick reaches the full response path (sense..act) or ends deterministically
        assert any("compute_impact" in t["nodes"] for t in tl)
        decs = artifacts.build_decisions(a1.run_path)
        assert decs, "A1 (Red) must record a decision"
        vt = artifacts.build_verifier_truth(a1.run_path)
        assert "summary" in vt and "per_tick" in vt


def test_report_six_chapters_and_honesty():
    """CampaignResult -> to_report yields the 6 chapters; chapter 6 carries all disclosures."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        rep = artifacts.to_report(c)
        assert set(rep["chapters"].keys()) == {"1", "2", "3", "4", "5", "6"}
        # report-role crosswalk: standalone E2E evidence report, folds into shared §7 (not a
        # top-level "6장"). Keeps the 6-chapter structure while resolving the 章 collision.
        role = rep["report_role"]
        assert role["standalone"] is True and role["chapters"] == 6
        assert role["artifact"] == "e2e_campaign_evidence_report" and role["folds_into"]
        ch1 = rep["chapters"]["1"]
        assert ch1["live_state_changes"] == 0
        assert len(ch1["invariants"]) == 2 and ch1["operating_constraints"]
        ch6 = rep["chapters"]["6"]
        keys = {l["key"] for l in ch6["limitations"]}
        assert {"V4_KEY_FORGERY_UNDETECTABLE", "PORT_5762_BLIND", "MISSION_WEIGHTED_DILUTION",
                "UNVERIFIED_RESPONSE_EFFICACY", "BLAST_RADIUS_SELF_DOS"} <= keys
        # chapter 4 surfaces blast-radius disclosures; chapter 5 the agent≠truth total
        assert rep["chapters"]["4"]["blast_radius"]
        assert "total_agent_truth_divergences" in rep["chapters"]["5"]
        # write_report_json produces valid, secret-free JSON
        path = os.path.join(d, "report.json")
        artifacts.write_report_json(c, path)
        loaded = json.load(open(path, encoding="utf-8"))
        assert not viewer.scan_secrets(json.dumps(loaded, ensure_ascii=False))


def test_honest_banner_and_chapter_mapping():
    """honest.py: banner + per-chapter mapping are consistent and self-describing."""
    b = honest.banner()
    assert b["live_state_changes"] == 0 and b["execution_mode"].startswith("DRY")
    assert b["verified_detections"] == 2 and b["total_attacks"] == 6
    # every limitation maps to a report chapter in {4,5,6}
    for lim in honest.HONEST_LIMITATIONS:
        assert lim.report_chapter in (4, 5, 6)
    # honest_note is KeyError-safe
    assert honest.honest_note("nope")["title"] == "(unknown limitation)"
    assert honest.attack_honest_keys("A4_5762_backdoor")


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
