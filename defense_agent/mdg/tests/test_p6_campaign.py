"""test_p6_campaign — P6 E2E campaign + honesty + artifacts self-verify (langgraph 무관).

langgraph/네트워크 없이 6개 공격 harness 를 end-to-end 검증한다:
  - e2e.run_campaign: 6개 공격 replay -> detect -> respond -> verify (DRY, operator-go)
  - 2대 불변식: 0 live executions (Backend DRY), edge 를 통한 라우팅 (numeric/bool 만)
  - honest.py: 공개된 한계 + banner + chapter 매핑
  - artifacts.py: timeline / decisions / verifier_truth + CampaignResult -> 6장 report
  - PS-3: 모든 run.jsonl 은 secret-free (viewer fail-closed scan 통과)
  - GATE2: run.jsonl 은 run 간 byte-identical
  - H-K: A6 telemetry-silence 는 독립 Verifier 를 통해 agent≠truth 발산을 산출

실행: python mdg/tests/test_p6_campaign.py   (또는 pytest 로)
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
    """6개 공격 전부 replay + detect; live 상태 변경 없음 (불변식2./operator-go)."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        assert c.total == 6, c.total
        assert c.detected_count == 6, "every attack must be detected"
        assert c.live_execution_count == 0, "operator-go: ZERO live executions allowed"
        for o in c.outcomes:
            assert o.live_execution is False
            assert o.incidents, f"{o.attack_id} produced no incident"
            # run.jsonl 실제로 기록됨
            assert os.path.exists(o.run_path), o.run_path


def test_detection_response_verification_spread():
    """campaign 은 실제 detect->respond->verify 스프레드를 보여줌 (밴드, tier, 발산)."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        by = {o.attack_id: o for o in c.outcomes}
        # A1 명령 탈취 (5762 ESTAB + unauth) -> command floor 71 -> Red
        assert by["A1_command_hijack_cr01"].top_impact_band == "Red"
        # A2 PFCP delete storm -> session floor -> Red, 그리고 VERIFIED detection (B-1)
        assert by["A2_pfcp_teardown"].top_impact_band == "Red"
        assert by["A2_pfcp_teardown"].verified_detection is True
        # 정확히 2개 verified detection (telemetry D-1 + PFCP B-1), 4개 unverified
        assert c.verified_count == 2, c.verified_count
        # 발동하는 대응은 OPER operator-gate (부수효과 0, operator-go): docker_pause
        responders = [o for o in c.outcomes if o.responded]
        assert responders, "at least one response must be selected"
        for o in responders:
            assert o.response_tier in ("OPER", "AUTO")
            assert o.response_dispatch in ("operator_gate", "inert_dry", "dry_argv", "escalated")
            assert o.live_execution is False


def test_A5_mission_weighted_dilution_stays_green():
    """A5 mongo/identity_access 는 저가중 (w=10, conf 0.60) -> 탐지되어도 Green 유지.
    이는 공개된 MISSION_WEIGHTED_DILUTION 한계이며, 누락이 아님."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        a5 = next(o for o in c.outcomes if o.attack_id == "A5_mongo_dbaccess")
        assert a5.detected is True
        assert a5.top_impact_band == "Green"
        assert a5.responded is False


def test_A6_agent_not_truth_divergence():
    """H-K: telemetry-silence -> 에이전트가 nominal (Continue+Monitoring) 유지하는 동안
    독립 Verifier 가 agent≠truth 를 플래그. Verifier 는 별도 trust root (grep0)."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        a6 = next(o for o in c.outcomes if o.attack_id == "A6_telemetry_silence")
        assert a6.agent_truth_divergences >= 1, a6.truth_summary
        assert a6.verified_detection is True                # telemetry cross-tap (D-1)
        # campaign 수준 rollup 이 발산을 집계
        assert c.divergence_count >= 1


def test_runjsonl_secret_free_and_byte_identical():
    """PS-3: 모든 run.jsonl 은 viewer fail-closed secret scan 을 통과. GATE2: byte-identical."""
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        c1 = _run(d1)
        c2 = _run(d2)
        for o in c1.outcomes:
            raw = open(o.run_path, encoding="utf-8").read()
            assert not viewer.scan_secrets(raw), f"{o.attack_id} run.jsonl has residual secret"
            # 정규 스키마 {seq,node,patch}
            for ln in raw.splitlines():
                obj = json.loads(ln)
                assert set(obj) == {"seq", "node", "patch"}, obj
        # 두 독립 run 간 공격별 byte-identical (결정론적 clock, sort_keys)
        for o1, o2 in zip(c1.outcomes, c2.outcomes):
            b1 = open(o1.run_path, "rb").read()
            b2 = open(o2.run_path, "rb").read()
            assert b1 == b2, f"{o1.attack_id} run.jsonl not byte-identical"


def test_artifacts_timeline_decisions_verifier_truth():
    """artifacts 는 run.jsonl 만으로 3개 reviewer artifact 를 빌드 (portability 기둥)."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        a1 = next(o for o in c.outcomes if o.attack_id == "A1_command_hijack_cr01")
        tl = artifacts.build_timeline(a1.run_path)
        assert tl and all("nodes" in t and "impact_band" in t for t in tl)
        # 대표 tick 은 전체 응답 경로 (sense..act)에 도달하거나 결정론적으로 종료
        assert any("compute_impact" in t["nodes"] for t in tl)
        decs = artifacts.build_decisions(a1.run_path)
        assert decs, "A1 (Red) must record a decision"
        vt = artifacts.build_verifier_truth(a1.run_path)
        assert "summary" in vt and "per_tick" in vt


def test_report_six_chapters_and_honesty():
    """CampaignResult -> to_report 는 6개 chapter 를 산출; chapter 6 은 모든 공개사항을 담음."""
    with tempfile.TemporaryDirectory() as d:
        c = _run(d)
        rep = artifacts.to_report(c)
        assert set(rep["chapters"].keys()) == {"1", "2", "3", "4", "5", "6"}
        # report-role 크로스워크: 독립형 E2E evidence report, 공유 §7 로 접힘 (최상위
        # "6장" 아님). 章 충돌을 해소하면서 6장 구조를 유지.
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
        # chapter 4 는 blast-radius 공개를 표출; chapter 5 는 agent≠truth 총계
        assert rep["chapters"]["4"]["blast_radius"]
        assert "total_agent_truth_divergences" in rep["chapters"]["5"]
        # write_report_json 은 유효한 secret-free JSON 을 산출
        path = os.path.join(d, "report.json")
        artifacts.write_report_json(c, path)
        loaded = json.load(open(path, encoding="utf-8"))
        assert not viewer.scan_secrets(json.dumps(loaded, ensure_ascii=False))


def test_honest_banner_and_chapter_mapping():
    """honest.py: banner + chapter 별 매핑이 일관적이고 자기 기술적."""
    b = honest.banner()
    assert b["live_state_changes"] == 0 and b["execution_mode"].startswith("DRY")
    assert b["verified_detections"] == 2 and b["total_attacks"] == 6
    # 모든 한계는 {4,5,6} 의 report chapter 에 매핑
    for lim in honest.HONEST_LIMITATIONS:
        assert lim.report_chapter in (4, 5, 6)
    # honest_note 는 KeyError-safe
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
