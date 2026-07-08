#!/usr/bin/env python3
"""gcs_signed_correct.py — SIGNED recovery-correction sender (RUNS INSIDE gcs_c2 ONLY).

This asset is AUTHORED in the defense_agent repo but is NOT imported or executed by the MDG
process. The MDG mainloop DEPLOYS it into the ``gcs_c2`` container (docker cp) and MDG triggers it
via a single Backend spawn:

    docker exec gcs_c2 python3 /gcs_signed_correct.py <mode> <alt>

KEY OWNERSHIP (E11 non-proliferation): the MAVLink uplink-signing key lives ONLY inside gcs_c2
(``/sign.key``, the same key ``/gcs.py`` already uses). MDG never opens, reads, names, or copies it
— the signature is produced HERE, inside the container that already owns the key. This is why the
defense_agent codebase stays statically key-free (verify_signer_no_keyopen): the ONLY code that ever
touches the key is this in-container sender.

Behaviour (S2 physical return): open a SIGNED MAVLink2 link to the local SITL bridge
(``udpout:127.0.0.1:14550`` → ARIA cipher proxy 14555 → uav_proxy signature verify → SITL), then
  (a) DO_SET_MODE GUIDED  — take command authority back into a mode that accepts guided targets, and
  (b) return to a <alt> m RELATIVE-altitude hover over the current position
      (SET_POSITION_TARGET_GLOBAL_INT, MAV_FRAME_GLOBAL_RELATIVE_ALT_INT),
so a command-hijack (e.g. an unauthorized LAND) is physically overridden and the drone climbs back
to the ~30 m home/hover altitude. Signing uses the SAME convention as /gcs.py
(``setup_signing(bytes.fromhex(<key>), sign_outgoing=True)``).
"""
from __future__ import annotations

import sys
import time

from pymavlink import mavutil

SIGN_KEYFILE = "/sign.key"          # gcs_c2-local signing key (SAME key /gcs.py uses) — never leaves gcs_c2
LINK = "udpout:127.0.0.1:14550"     # local signed uplink → ARIA proxy → uav_proxy verify → SITL
COPTER_GUIDED_CUSTOM_MODE = 4       # ArduCopter GUIDED custom_mode

# --- blocking-time budget (LOAD-BEARING INVARIANT — pairs with signer_shim._DELEGATE_TIMEOUT_S) --
# The Backend spawn that runs this sender (``docker exec gcs_c2 python3 <sender> …``) enforces a
# HARD deadline (signer_shim._DELEGATE_TIMEOUT_S). If this sender's worst-case blocking exceeds that
# deadline the process group is SIGKILLed MID-SEQUENCE — and the S2 physical return can be silently
# truncated (GUIDED set but the 30 m reposition never issued, or issued only once). So every
# blocking call below is bounded and the WORST CASE must stay well under the spawn deadline:
#     HEARTBEAT_TIMEOUT_S + 2*(POS_TIMEOUT_S + SETTLE_S) = 5 + 2*(2 + 1) = 11s  (<< 30s deadline).
# Keep this sum and signer_shim._DELEGATE_TIMEOUT_S in lockstep if either is retuned.
HEARTBEAT_TIMEOUT_S = 5.0           # learn target_system from a heartbeat (was 10s)
POS_TIMEOUT_S = 2.0                 # best-effort current-position read, per reposition (was 5s)
SETTLE_S = 1.0                      # let the mode / guided target apply between sends


def _load_signing_key() -> bytes:
    """Read gcs_c2's own signing key (hex text, like /gcs.py). Runs ONLY inside gcs_c2."""
    with open(SIGN_KEYFILE, "r", encoding="utf-8") as fh:
        return bytes.fromhex(fh.read().strip())


def _connect_signed() -> "mavutil.mavfile":
    master = mavutil.mavlink_connection(LINK, dialect="ardupilotmega")
    # MAVLink2 + outgoing signing — identical convention to /gcs.py's setup_signing(sign_outgoing=True).
    master.setup_signing(_load_signing_key(), sign_outgoing=True)
    return master


def _wait_target(master: "mavutil.mavfile", timeout: float = HEARTBEAT_TIMEOUT_S):
    """Learn the vehicle system/component id from a heartbeat so command targets are addressed.

    Returns the HEARTBEAT msg (or None). We log LOUDLY whether telemetry actually reached this
    sender: if no heartbeat arrives, ``target_system`` stays 0 (broadcast) and the correction
    degrades to a best-effort broadcast — that must be VISIBLE in the spawn stdout (a missing
    gcs.py→client telemetry relay is otherwise silent). The sender still proceeds best-effort."""
    hb = master.wait_heartbeat(timeout=timeout)
    if hb is None or getattr(master, "target_system", 0) == 0:
        print(f"gcs_signed_correct: WARNING no HEARTBEAT within {timeout:.0f}s "
              "-> target_system=0 (broadcast); telemetry relay to this sender may be absent",
              flush=True)
    else:
        print(f"gcs_signed_correct: HEARTBEAT sys={master.target_system} "
              f"comp={master.target_component}", flush=True)
    return hb


def _set_mode_guided(master: "mavutil.mavfile", custom_mode: int) -> None:
    master.mav.command_long_send(
        master.target_system, master.target_component,
        mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, custom_mode,
        0, 0, 0, 0, 0,
    )


def _current_global(master: "mavutil.mavfile", timeout: float = POS_TIMEOUT_S):
    """Best-effort current lat/lon (1e7 int deg) so the return hover keeps the current position."""
    msg = master.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=timeout)
    if msg is None:
        print(f"gcs_signed_correct: no GLOBAL_POSITION_INT within {timeout:.0f}s "
              "-> altitude-only takeoff-to-alt fallback", flush=True)
        return None, None
    return int(msg.lat), int(msg.lon)


def _return_to_alt(master: "mavutil.mavfile", alt_m: float) -> None:
    """Command a return to ``alt_m`` RELATIVE altitude over the current position (GUIDED hold).

    type_mask enables ONLY the position fields (bits for vel/accel/yaw set to ignore). Frame is
    RELATIVE_ALT so ``alt_m`` is height above home (~30 m), matching arducopter --home=...,30."""
    lat, lon = _current_global(master)
    # 0b0000_111_111_111_000 -> use position (x,y,z), ignore vel/accel/yaw/yaw_rate.
    type_mask = 0b0000111111111000
    if lat is None or lon is None:
        # Fallback: no position fix yet — command altitude-only via a takeoff-to-alt in GUIDED.
        master.mav.command_long_send(
            master.target_system, master.target_component,
            mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0,
            0, 0, 0, 0, 0, 0, float(alt_m),
        )
        return
    master.mav.set_position_target_global_int_send(
        0, master.target_system, master.target_component,
        mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        type_mask, lat, lon, float(alt_m),
        0, 0, 0, 0, 0, 0, 0, 0,
    )


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "GUIDED"
    try:
        alt_m = float(argv[2]) if len(argv) > 2 else 30.0
    except ValueError:
        alt_m = 30.0

    master = _connect_signed()
    _wait_target(master)

    # (a) take authority back into GUIDED (only GUIDED is wired here; other modes would map similarly)
    if mode.upper() == "GUIDED":
        _set_mode_guided(master, COPTER_GUIDED_CUSTOM_MODE)
    else:
        _set_mode_guided(master, COPTER_GUIDED_CUSTOM_MODE)
    time.sleep(SETTLE_S)

    # (b) physically return to the ~30 m relative hover altitude over the current position
    _return_to_alt(master, alt_m)
    time.sleep(SETTLE_S)
    # re-issue once for reliability over lossy UDP (both are idempotent guided targets)
    _return_to_alt(master, alt_m)

    print(f"gcs_signed_correct: signed GUIDED + return-to-{alt_m:.0f}m relative issued", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
