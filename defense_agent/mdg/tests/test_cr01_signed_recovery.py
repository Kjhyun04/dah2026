"""test_cr01_signed_recovery — Item 2: incident -> signing-recovery legal candidate.

Locks the "command-domain incident -> send_signed_mode becomes a LEGAL recovery" wiring,
end to end through select_policy + legality + rank_recovery, with ZERO core hardcode
(tuning lives only in recovery_priors.yaml + the closed _INCIDENT_RECOVERY map). Runs
offline and fully deterministic (불변식①).

Two routes deliver send_signed_mode as a legal candidate; both are locked here:

  A) CR01 (E19 time-window correlation of PFCP_Delete_Attempt + Unauthorized_Command)
     -> _INCIDENT_RECOVERY["CR01"] = [pfcp_firewall, command_override]. command_override's
     response_tool is send_signed_mode (recovery_priors). It enters legal_actions ONLY when
     signing == CONFIRMED_ON AND role_verified[<gcs_proxy>] is True. Under the pure-CR01
     legal set pfcp_firewall CO-EXISTS (same gcs_proxy chokepoint) and DETERMINISTICALLY
     out-ranks command_override, so the autonomous chosen action is nsenter_input_drop — the
     flight uplink is offered but not auto-selected (send_signed_mode stays OPER/operator-go).

  B) command single-signal (Unauthorized_Command / Signature_Verify_Fail) -> signed_guided
     (send_signed_mode) via the _RTYPE_DOMAIN_GUARD command gate. When the container-isolation
     peer (backdoor_pause -> web_backend) is NOT verified, signed_guided is the SOLE legal
     candidate and send_signed_mode is the CHOSEN flight-recovery tool (the S2 scenario).

Fail-safe (MONOTONIC LATCH): signing UNKNOWN or CONFIRMED_OFF, or a missing role_verified
binding, MUST exclude send_signed_mode from the legal set (never fire an unconfirmed-auth
flight uplink).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.config import loader  # noqa: E402
from mdg.core.nodes.rank_recovery import rank_recovery  # noqa: E402
from mdg.core.nodes.select_policy import _INCIDENT_RECOVERY, select_policy  # noqa: E402
from mdg.core.state import Incident  # noqa: E402
from mdg.core.worldstate import SigningObs, WorldState  # noqa: E402

CFG = "mdg-cfg-2026-07-07"


def _cr01() -> Incident:
    return Incident(id="CR01-0", kind="CR01",
                    members=["PFCP_Delete_Attempt", "Unauthorized_Command"])


def _cmd_single_signal(metric: str = "Signature_Verify_Fail") -> Incident:
    return Incident(id=f"sig-0-{metric}", kind="single-signal", members=[metric])


def _world(*, signing: SigningObs, verified: dict) -> WorldState:
    return WorldState(config_version=CFG, signing=signing, role_verified=verified)


def _drive(incident: Incident, world: WorldState) -> tuple[list, dict]:
    st = {"incidents": [incident], "worldstate": world, "config_version": CFG}
    legal = select_policy(st)["legal_actions"]
    st["legal_actions"] = legal
    return legal, rank_recovery(st)


def _tools(legal) -> set:
    return {a.tool_id for a in legal}


# --------------------------------------------------------------------------- #
# mapping consistency (pure config; no core literal)
# --------------------------------------------------------------------------- #
def test_cr01_maps_to_command_override_signing_recovery():
    assert _INCIDENT_RECOVERY["CR01"] == ["pfcp_firewall", "command_override"]
    priors = loader.recovery_priors().get("recovery_priors", {})
    # the signing-recovery candidate for CR01 dispatches the flight-uplink tool
    assert priors["command_override"]["response_tool"] == "send_signed_mode"
    assert priors["command_override"]["enforce_at"] == "gcs_proxy"


# --------------------------------------------------------------------------- #
# A) CR01 legality — send_signed_mode admitted ONLY under CONFIRMED_ON + role gcs
# --------------------------------------------------------------------------- #
def test_cr01_confirmed_signing_and_role_gcs_admits_send_signed_mode():
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={"gcs_proxy": True})
    legal, _ = _drive(_cr01(), world)
    rtypes = {a.recovery_type for a in legal}
    assert "command_override" in rtypes, rtypes
    assert "send_signed_mode" in _tools(legal)


def test_cr01_unknown_signing_latch_excludes_send_signed_mode():
    # MONOTONIC LATCH fail-safe: no authoritative ON observation -> flight uplink NOT legal.
    world = _world(signing=SigningObs.UNKNOWN, verified={"gcs_proxy": True})
    legal, _ = _drive(_cr01(), world)
    assert "command_override" not in {a.recovery_type for a in legal}
    assert "send_signed_mode" not in _tools(legal)


def test_cr01_confirmed_off_excludes_send_signed_mode():
    # only CONFIRMED_ON is enforced (signing_enforced); a confirmed-OFF posture is NOT legal.
    world = _world(signing=SigningObs.CONFIRMED_OFF, verified={"gcs_proxy": True})
    legal, _ = _drive(_cr01(), world)
    assert "send_signed_mode" not in _tools(legal)


def test_cr01_missing_role_gcs_excludes_send_signed_mode():
    # role gate: gcs_proxy chokepoint binding absent -> command_override illegal (self-DoS shut).
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={})
    legal, _ = _drive(_cr01(), world)
    assert "send_signed_mode" not in _tools(legal)


# --------------------------------------------------------------------------- #
# A) CR01 ranking — DETERMINISTIC total order (pfcp_firewall out-ranks command_override)
# --------------------------------------------------------------------------- #
def test_cr01_rank_is_deterministic_pfcp_out_ranks_command_override():
    # Both legal under CONFIRMED_ON + gcs. recovery_priors scores pfcp_firewall (succ 0.80, MED)
    # above command_override (succ 0.90, HIGH) via the composite recovery_score (risk weighting),
    # with NO core _sort_key boost. Locking this pins the autonomous CR01 selection: the flight
    # uplink is a legal candidate but is NOT auto-chosen (send_signed_mode stays operator-go).
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={"gcs_proxy": True})
    legal, out = _drive(_cr01(), world)
    assert {a.recovery_type for a in legal} == {"pfcp_firewall", "command_override"}
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.rule == "pfcp_firewall"
    assert chosen.tool_id == "nsenter_input_drop"


# --------------------------------------------------------------------------- #
# B) command single-signal — send_signed_mode is the CHOSEN flight recovery (S2)
# --------------------------------------------------------------------------- #
def test_command_hijack_single_signal_chooses_send_signed_mode():
    # command-domain single-signal (Signature_Verify_Fail) admits signed_guided via the
    # _RTYPE_DOMAIN_GUARD command gate. gcs_proxy verified, web_backend NOT -> backdoor_pause
    # filtered -> signed_guided sole legal -> send_signed_mode CHOSEN (the S2 flight recovery).
    world = _world(signing=SigningObs.CONFIRMED_ON, verified={"gcs_proxy": True})
    legal, out = _drive(_cmd_single_signal("Signature_Verify_Fail"), world)
    assert [a.recovery_type for a in legal] == ["signed_guided"], [a.recovery_type for a in legal]
    chosen = out["chosen_action"]
    assert chosen is not None and chosen.tool_id == "send_signed_mode"
    assert chosen.rule == "signed_guided"
    assert out["chosen_action_risk"] == "HIGH"
    assert out["chosen_action_reversible"] is False


def test_command_single_signal_unknown_signing_no_flight_uplink():
    # LIVE posture fail-safe: UNKNOWN signing -> signed_guided double-gated out; if the isolation
    # peer is also unverified there is NO legal recovery and NO flight uplink is chosen.
    world = _world(signing=SigningObs.UNKNOWN, verified={"gcs_proxy": True})
    legal, out = _drive(_cmd_single_signal("Signature_Verify_Fail"), world)
    assert "send_signed_mode" not in _tools(legal)
    assert out["chosen_action"] is None


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
