"""test_p2_recon — P2 recon / target-resolution self-verify (runnable standalone).

Covers: DefInputSpec load (zero hardcoded IP), role->container->IP 2-stage resolve
(inspect + live tun scan, A-1), fail-closed + operator-go dry-run behaviour, pause-target
reverse map (C-3), SmfSessionTable IMSI<->tun-IP with ANSI-strip (P4-1/P4-5), and
recon_boot boot-baseline assembly (signing/NAS/ports/IP-map).

Run: ``python mdg/tests/test_p2_recon.py`` (no pytest / langgraph / grpcio needed).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.collector.log_common import ansi_strip  # noqa: E402
from mdg.collector.smf_session import (SmfSessionTable, parse_smf_line)  # noqa: E402
from mdg.core.recon import recon_boot  # noqa: E402
from mdg.core.worldstate import SigningObs  # noqa: E402
from mdg.safe_exec.backend import Backend  # noqa: E402
from mdg.targets.behavioral import (AnchorEvidence,  # noqa: E402
                                    apply_behavioral_verification,
                                    confirm_behavioral_anchor)
from mdg.targets.inputspec import DefInputSpec  # noqa: E402
from mdg.targets.resolve import (parse_ip_addr_show, resolve_targets,  # noqa: E402
                                 reverse_container_for_ip)


# --------------------------------------------------------------------------- #
# mock docker + backend
# --------------------------------------------------------------------------- #
_PIDS = {"gcs_proxy": 900, "uav_ue": 1001, "attacker_ue": 1002, "web_backend": 903}
_CELL = {"uav_ue": "10.44.0.30", "attacker_ue": "10.44.0.31"}


class _Docker:
    def inspect_pid(self, c):
        return _PIDS.get(c)

    def inspect_networks(self, c):
        ip = _CELL.get(c)
        return {"net_cellular": ip} if ip else {}


def _ipaddr(ip: str) -> str:
    return ("5: tun_srsue: <POINTOPOINT,PROMISC,NOTRAILERS,UP,LOWER_UP> mtu 1500 qdisc fq\n"
            f"    inet {ip}/32 scope global tun_srsue\n"
            "       valid_lft forever preferred_lft forever\n")


def _tun_backend() -> Backend:
    # keyed by host pid substring in the nsenter argv (--target <pid>)
    return Backend(mode="mock", mock_table={
        "1001": _ipaddr("10.45.0.2"),      # uav_ue
        "1002": _ipaddr("10.45.0.10"),     # attacker_ue
    })


# --------------------------------------------------------------------------- #
# DefInputSpec
# --------------------------------------------------------------------------- #
def test_inputspec_load_has_no_pinned_ip():
    spec = DefInputSpec.load()
    assert spec.roles and spec.ue_pool_cidr == "10.45.0.0/16"
    # zero-hardcoding: RoleSpec has no ip field at all
    r = spec.role_by_container("uav_ue")
    assert r is not None and not hasattr(r, "ip") and r.tun_iface == "tun_srsue"
    assert "uav_ue" in spec.netns_containers() and "attacker_ue" not in spec.netns_containers()
    assert {rr.container for rr in spec.tun_roles()} == {"uav_ue", "attacker_ue"}
    assert spec.initial_reach()["gcs14556"] is False
    assert spec.signing_expected is True


# --------------------------------------------------------------------------- #
# ip addr parsing + 2-stage resolve
# --------------------------------------------------------------------------- #
def test_parse_ip_addr_show():
    assert parse_ip_addr_show(_ipaddr("10.45.0.2")) == "10.45.0.2"
    assert parse_ip_addr_show("") is None
    assert parse_ip_addr_show("no inet here") is None


def test_resolve_two_stage_verifies_ue_pool():
    spec = DefInputSpec.load()
    res = resolve_targets(spec, docker=_Docker(), backend=_tun_backend())
    # UE-pool roles: stage-2 tun scan resolved + verified (IP in pool CIDR)
    uav = res.bindings["uav_ue"]
    atk = res.bindings["attacker_ue"]
    assert uav.ip == "10.45.0.2" and uav.verified and uav.provenance == "verified"
    assert atk.ip == "10.45.0.10" and atk.verified and atk.provenance == "verified"
    # infra roles: verified via inspect presence (pid), cellular IP absent for gcs/web
    assert res.bindings["gcs_proxy"].verified and res.bindings["gcs_proxy"].provenance == "inspect"
    assert res.pidmap["uav_ue"] == 1001 and res.pidmap["attacker_ue"] == 1002
    # reverse pause-target map (C-3)
    assert reverse_container_for_ip("10.45.0.10", res) == "attacker_ue"
    assert reverse_container_for_ip("10.45.0.99", res) is None      # fail-closed


def test_resolve_fail_closed_without_docker():
    spec = DefInputSpec.load()
    res = resolve_targets(spec, docker=None, backend=None)
    assert res.pidmap == {}
    assert all(not b.verified and b.provenance == "config" for b in res.bindings.values())


def test_resolve_tun_scan_is_operator_go_dry_run():
    # a non-allow_live Backend returns DRY-RUN -> tun IP unresolved -> UE role NOT verified
    spec = DefInputSpec.load()
    dry = Backend(mode="local", allow_live=False)
    res = resolve_targets(spec, docker=_Docker(), backend=dry)
    uav = res.bindings["uav_ue"]
    assert uav.ip == "" and not uav.verified          # tun scan reserved (operator-go)
    assert res.pidmap["uav_ue"] == 1001               # inspect still worked (read-only)


def test_resolve_tun_ip_outside_pool_not_verified():
    spec = DefInputSpec.load()
    be = Backend(mode="mock", mock_table={"1001": _ipaddr("10.99.0.5")})  # not in pool
    res = resolve_targets(spec, docker=_Docker(), backend=be)
    uav = res.bindings["uav_ue"]
    assert uav.ip == "10.99.0.5" and not uav.verified   # recorded but not verified


# --------------------------------------------------------------------------- #
# P2-Q1: static IMSI<->container boot map + 2-layer pause-target resolution
# --------------------------------------------------------------------------- #
def test_imsi_container_map_is_boot_constant():
    spec = DefInputSpec.load()
    m = spec.imsi_container_map()
    assert m == {"001010000000001": "uav_ue", "001010000000002": "attacker_ue"}
    # infra roles carry no imsi -> absent from the static map (fail-closed to layer 2)
    assert "gcs_proxy" not in m.values()


def test_reverse_layer1_smf_imsi_to_static_container():
    # Layer 1 (primary): IP -> IMSI (SMF table) -> container (static boot map), zero netns.
    spec = DefInputSpec.load()
    res = resolve_targets(spec, docker=None, backend=None)   # no live tun scan at all
    assert res.ip_map == {}                                  # layer-2 reverse map is empty
    t = SmfSessionTable()
    t.add("001010000000002", "10.45.0.11")                   # attacker session (dynamic IP)
    # layer 1 resolves the pause target with no tun scan / no exec / no nsenter
    assert reverse_container_for_ip("10.45.0.11", res, smf_table=t) == "attacker_ue"
    # unknown IP stays fail-closed (no invented pause target)
    assert reverse_container_for_ip("10.45.0.99", res, smf_table=t) is None
    # without an SMF table layer 1 is skipped -> layer 2 empty -> None (still fail-closed)
    assert reverse_container_for_ip("10.45.0.11", res) is None


# --------------------------------------------------------------------------- #
# SmfSessionTable (P4-1) + ANSI-strip (P4-5)
# --------------------------------------------------------------------------- #
_ANSI_CREATE = "\x1b[1;32m07/07 03:39:36.461: [smf] INFO: UE IMSI[001010000000001] IPv4[10.45.0.2]\x1b[0m"
_ANSI_REMOVE = "\x1b[1;33m07/07 03:41:10.002: [smf] INFO: Removed Session: UE IMSI:[imsi-001010000000001] APN[internet] IPv4:[10.45.0.2]\x1b[0m"


def test_ansi_strip_then_regex():
    assert "\x1b[" in _ANSI_CREATE and "\x1b[" not in ansi_strip(_ANSI_CREATE)
    ev = parse_smf_line(_ANSI_CREATE)
    assert ev and ev.op == "add" and ev.imsi == "001010000000001" and ev.ip == "10.45.0.2"
    assert ev.ts == "07/07 03:39:36.461"
    rem = parse_smf_line(_ANSI_REMOVE)
    assert rem and rem.op == "remove" and rem.ip == "10.45.0.2"
    # without ANSI-strip the raw line still parses (regex is substring), but strip is
    # required for lines where the escape sits inside the token span — assert strip idempotent
    assert parse_smf_line(ansi_strip(_ANSI_CREATE)).ip == "10.45.0.2"


def test_session_table_bidirectional_and_evict():
    t = SmfSessionTable()
    t.feed_line(_ANSI_CREATE)
    assert t.imsi_for_ip("10.45.0.2") == "001010000000001"
    assert t.ip_for_imsi("001010000000001") == "10.45.0.2"
    # re-attach same IMSI to a new IP evicts the stale ip->imsi binding
    t.add("001010000000001", "10.45.0.7")
    assert t.imsi_for_ip("10.45.0.2") is None and t.imsi_for_ip("10.45.0.7") == "001010000000001"
    # remove clears both directions + surfaces in recent_removes (P4-4 join feed)
    t.feed_line(_ANSI_REMOVE)                       # removes 10.45.0.2 (already gone) -> noop-safe
    t.remove("001010000000001", "10.45.0.7")
    assert t.ip_for_imsi("001010000000001") is None
    assert any(e.op == "remove" for e in t.recent_removes())


def test_session_table_ignores_noise():
    t = SmfSessionTable()
    assert t.feed_line("07/07 03:39:36.461: [smf] some unrelated log line") is None
    assert t.snapshot() == {}


# --------------------------------------------------------------------------- #
# P2-1: verify_anchor is LIVE-consumed -> behaviorally_verified (distinct from presence)
# --------------------------------------------------------------------------- #
def test_behavioral_anchor_consumes_verify_anchor():
    # each declared anchor is satisfied only by its matching live evidence
    assert confirm_behavioral_anchor("lo_14550_heartbeat_sys1", AnchorEvidence(heartbeat_sys=1))
    assert not confirm_behavioral_anchor("lo_14550_heartbeat_sys1", AnchorEvidence(heartbeat_sys=2))
    assert confirm_behavioral_anchor("port_5762_backdoor_attempt", AnchorEvidence(port_5762_estab=True))
    assert confirm_behavioral_anchor("signing_drop_log_uav_proxy", AnchorEvidence(signing_drop_seen=True))
    # fail-closed: unknown anchor / no evidence -> False (never crashes)
    assert not confirm_behavioral_anchor("nonexistent_anchor", AnchorEvidence(heartbeat_sys=1))
    assert not confirm_behavioral_anchor("lo_14550_heartbeat_sys1", None)
    assert not confirm_behavioral_anchor("", AnchorEvidence())


def test_behavioral_verification_distinct_from_presence():
    spec = DefInputSpec.load()
    # no evidence (boot / operator-go) -> every role behaviorally UNverified
    empty = apply_behavioral_verification(spec.roles, evidence=None)
    assert set(empty) >= {"uav_ue", "gcs_proxy", "web_backend", "uav_proxy"}
    assert not any(empty.values())
    # a live heartbeat sysid=1 on uav_ue flips ONLY uav_ue behaviorally_verified
    ev = {"uav_ue": AnchorEvidence(heartbeat_sys=1)}
    got = apply_behavioral_verification(spec.roles, evidence=ev)
    assert got["uav_ue"] is True
    assert got["gcs_proxy"] is False and got["attacker_ue"] is False


def test_recon_seeds_behavioral_false_but_presence_true():
    # presence (verified) can be True while behaviorally_verified stays False (operator-go)
    st = recon_boot(docker=_Docker(), backend=_tun_backend())
    w = st["worldstate"]
    assert w.role_verified["uav_ue"] is True                 # resolved/present
    assert w.behaviorally_verified["uav_ue"] is False        # no live anchor evidence at boot
    assert set(w.behaviorally_verified) == set(w.role_verified)  # full role set, both verdicts


# --------------------------------------------------------------------------- #
# recon_boot baseline
# --------------------------------------------------------------------------- #
def test_recon_boot_builds_baseline():
    st = recon_boot(docker=_Docker(), backend=_tun_backend())
    w = st["worldstate"]
    # ports / reach: closed vocab seeded False
    assert w.reach and all(v is False for v in w.reach.values())
    # NAS/posture baseline clean; signing observed UNKNOWN (expectation lives in spec, P2-Q2)
    assert w.signing is SigningObs.UNKNOWN and w.threat["command"] == "none"
    # IP map + role_verified from live 2-stage resolve
    assert w.role_verified["uav_ue"] is True and w.role_verified["attacker_ue"] is True
    assert w.ip_map.get("uav") == "10.45.0.2"
    assert w.ip_map.get("10.45.0.10") == "attacker_ue"      # reverse (C-3)
    assert w.pid.get("uav_ue") == 1001
    assert w.config_version and w.baseline.rtt_mdev_ms == 11.0


def test_recon_boot_inert_without_docker():
    st = recon_boot(docker=None, backend=None)
    w = st["worldstate"]
    assert w.pid == {} and not any(w.role_verified.values())
    assert w.reach and w.signing is SigningObs.UNKNOWN   # baseline still assembled (P2-Q2)


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
            import traceback
            print(f"[ERROR] {fn.__name__}: {e!r}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
