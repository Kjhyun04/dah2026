"""test_p3_recovery_select — Phase 3 (B2): rank_recovery emits a VISIBLE recovery tool.

Locks the two-scenario contract without any core _sort_key hardcode (tuning lives only in
recovery_priors.yaml + the closed _INCIDENT_RECOVERY candidate map):

  S1 (container isolation, LIVE posture signing=UNKNOWN):
      single-signal -> select_policy legalizes ONLY backdoor_pause (docker_pause). signed_guided
      is DOUBLE-GATED out by legality (send_signed_mode requires signing==CONFIRMED_ON), so the
      live/replay legal set is byte-identical to before Phase 3. rank -> docker_pause, MED, revocable.

  S2 (flight recovery, testbed posture signing=CONFIRMED_ON + role_verified.gcs):
      signed_guided ENTERS legal_actions as an OPER/HIGH candidate (the missing wiring — it was an
      orphan rtype). When it is the sole legal candidate it is CHOSEN (send_signed_mode). When it
      co-exists with backdoor_pause, backdoor_pause still out-ranks it (priors, no core boost), so
      admitting signed_guided never perturbs S1.

Runs offline. Executable as a script or under pytest.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core.nodes.rank_recovery import rank_recovery  # noqa: E402
from mdg.core.nodes.select_policy import _INCIDENT_RECOVERY, select_policy  # noqa: E402
from mdg.core.state import Incident  # noqa: E402
from mdg.core.worldstate import SigningObs, WorldState  # noqa: E402

CFG = "mdg-cfg-2026-07-07"


def _single_signal(target: str = "") -> Incident:
    return Incident(id="sig-0-Unauthorized_Command", kind="single-signal",
                    members=["Unauthorized_Command"], target=target)


def _world(*, signing: SigningObs, verified: dict) -> WorldState:
    return WorldState(config_version=CFG, signing=signing, role_verified=verified)


def _drive(world: WorldState) -> tuple[list, dict]:
    st = {"incidents": [_single_signal()], "worldstate": world, "config_version": CFG}
    legal = select_policy(st)["legal_actions"]
    st["legal_actions"] = legal
    return legal, rank_recovery(st)


# --------------------------------------------------------------------------- #
# candidate wiring — signed_guided is no longer an ORPHAN rtype
# --------------------------------------------------------------------------- #
def test_signed_guided_is_wired_into_single_signal_mapping():
    assert "signed_guided" in _INCIDENT_RECOVERY["single-signal"]
    assert "backdoor_pause" in _INCIDENT_RECOVERY["single-signal"]


# --------------------------------------------------------------------------- #
# S1 — LIVE posture (signing UNKNOWN): signed_guided is filtered, S1 unchanged
# --------------------------------------------------------------------------- #
def test_s1_unknown_signing_only_backdoor_pause_legal():
    # web_backend (backdoor_pause chokepoint) AND gcs_proxy (signed_guided chokepoint) BOTH
    # verified — proving it is the SIGNING gate, not a role gate, that filters signed_guided.
    world = _world(signing=SigningObs.UNKNOWN,
                   verified={"web_backend": True, "gcs_proxy": True})
    legal, out = _drive(world)
    rtypes = {a.recovery_type for a in legal}
    assert rtypes == {"backdoor_pause"}, rtypes           # signed_guided double-gated OUT
    # rank binds the VISIBLE isolation tool
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.rule == "backdoor_pause"
    assert chosen.tool_id == "docker_pause"
    assert out["chosen_action_risk"] == "MED"
    assert out["chosen_action_reversible"] is True


def test_s1_legal_set_byte_identical_to_pre_phase3():
    # the legal set under the LIVE UNKNOWN posture must be exactly the pre-Phase-3 set so replay
    # stays byte-identical (불변식1.). Only backdoor_pause — signed_guided never leaks into live.
    world = _world(signing=SigningObs.UNKNOWN, verified={"web_backend": True, "gcs_proxy": True})
    legal, _ = _drive(world)
    assert [a.recovery_type for a in legal] == ["backdoor_pause"]


# --------------------------------------------------------------------------- #
# S2 — testbed posture (signing CONFIRMED_ON): signed_guided ENTERS as candidate
# --------------------------------------------------------------------------- #
def test_s2_confirmed_signing_admits_signed_guided_candidate():
    world = _world(signing=SigningObs.CONFIRMED_ON,
                   verified={"web_backend": True, "gcs_proxy": True})
    legal, out = _drive(world)
    rtypes = {a.recovery_type for a in legal}
    assert "signed_guided" in rtypes, rtypes              # the missing wiring is now present
    assert "backdoor_pause" in rtypes
    # priors (NOT a core _sort_key boost) still rank backdoor_pause top -> S1 unperturbed even
    # with signing ON.
    assert out["chosen_action"].rule == "backdoor_pause"


def test_s2_signed_guided_chosen_when_sole_legal_candidate():
    # gcs_proxy verified but web_backend NOT -> backdoor_pause filtered, signed_guided sole legal ->
    # the VISIBLE flight-recovery tool (send_signed_mode) is chosen.
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={"gcs_proxy": True})
    legal, out = _drive(world)
    assert [a.recovery_type for a in legal] == ["signed_guided"], [a.recovery_type for a in legal]
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.rule == "signed_guided"
    assert chosen.tool_id == "send_signed_mode"
    assert out["chosen_action_risk"] == "HIGH"            # flight action -> OPER/HIGH downstream
    assert out["chosen_action_reversible"] is False


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
