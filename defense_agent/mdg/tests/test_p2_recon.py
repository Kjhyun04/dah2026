"""test_p2_recon — P2 recon / target-resolution self-verify (독립 실행 가능).

포함: DefInputSpec 로드 (하드코딩 IP 제로), role->container->IP 2단계 resolve
(inspect + live tun scan, A-1), fail-closed + operator-go dry-run 동작, pause-target
역방향 맵 (C-3), ANSI-strip 을 동반한 SmfSessionTable IMSI<->tun-IP (P4-1/P4-5),
recon_boot boot-baseline 조립 (signing/NAS/ports/IP-map).

실행: ``python mdg/tests/test_p2_recon.py`` (pytest / langgraph / grpcio 불필요).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.collector.log_common import ansi_strip  # noqa: E402
from mdg.collector.smf_session import (SmfSessionTable, parse_smf_line)  # noqa: E402
from mdg.core.recon import recon_boot  # noqa: E402
from mdg.core.worldstate import SigningObs, WorldState  # noqa: E402
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
    # nsenter argv 의 host pid 부분문자열로 키잉 (--target <pid>)
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
    # 하드코딩 제로: RoleSpec 에는 ip 필드가 아예 없음
    r = spec.role_by_container("uav_ue")
    assert r is not None and not hasattr(r, "ip") and r.tun_iface == "tun_srsue"
    assert "uav_ue" in spec.netns_containers() and "attacker_ue" not in spec.netns_containers()
    assert {rr.container for rr in spec.tun_roles()} == {"uav_ue", "attacker_ue"}
    assert spec.initial_reach()["gcs14556"] is False
    assert spec.signing_expected is True


# --------------------------------------------------------------------------- #
# ip addr 파싱 + 2단계 resolve
# --------------------------------------------------------------------------- #
def test_parse_ip_addr_show():
    assert parse_ip_addr_show(_ipaddr("10.45.0.2")) == "10.45.0.2"
    assert parse_ip_addr_show("") is None
    assert parse_ip_addr_show("no inet here") is None


def test_resolve_two_stage_verifies_ue_pool():
    spec = DefInputSpec.load()
    res = resolve_targets(spec, docker=_Docker(), backend=_tun_backend())
    # UE-pool role: stage-2 tun scan 으로 resolve + verified (IP 가 pool CIDR 내)
    uav = res.bindings["uav_ue"]
    atk = res.bindings["attacker_ue"]
    assert uav.ip == "10.45.0.2" and uav.verified and uav.provenance == "verified"
    assert atk.ip == "10.45.0.10" and atk.verified and atk.provenance == "verified"
    # infra role: inspect presence (pid)로 verified, gcs/web 은 cellular IP 부재
    assert res.bindings["gcs_proxy"].verified and res.bindings["gcs_proxy"].provenance == "inspect"
    assert res.pidmap["uav_ue"] == 1001 and res.pidmap["attacker_ue"] == 1002
    # 역방향 pause-target 맵 (C-3)
    assert reverse_container_for_ip("10.45.0.10", res) == "attacker_ue"
    assert reverse_container_for_ip("10.45.0.99", res) is None      # fail-closed (미지의 IP)


def test_resolve_fail_closed_without_docker():
    spec = DefInputSpec.load()
    res = resolve_targets(spec, docker=None, backend=None)
    assert res.pidmap == {}
    assert all(not b.verified and b.provenance == "config" for b in res.bindings.values())


def test_resolve_tun_scan_is_operator_go_dry_run():
    # allow_live 아닌 Backend 는 DRY-RUN 반환 -> tun IP 미해석 -> UE role verified 안 됨
    spec = DefInputSpec.load()
    dry = Backend(mode="local", allow_live=False)
    res = resolve_targets(spec, docker=_Docker(), backend=dry)
    uav = res.bindings["uav_ue"]
    assert uav.ip == "" and not uav.verified          # tun scan 유보 (operator-go)
    assert res.pidmap["uav_ue"] == 1001               # inspect 은 여전히 동작 (read-only)


def test_resolve_tun_ip_outside_pool_not_verified():
    spec = DefInputSpec.load()
    be = Backend(mode="mock", mock_table={"1001": _ipaddr("10.99.0.5")})  # pool 에 없음
    res = resolve_targets(spec, docker=_Docker(), backend=be)
    uav = res.bindings["uav_ue"]
    assert uav.ip == "10.99.0.5" and not uav.verified   # 기록되었으나 verified 아님


# --------------------------------------------------------------------------- #
# P2-Q1: static IMSI<->container boot 맵 + 2계층 pause-target resolution
# --------------------------------------------------------------------------- #
def test_imsi_container_map_is_boot_constant():
    spec = DefInputSpec.load()
    m = spec.imsi_container_map()
    assert m == {"001010000000001": "uav_ue", "001010000000002": "attacker_ue"}
    # infra role 은 imsi 를 갖지 않음 -> static 맵에서 부재 (layer 2 로 fail-closed)
    assert "gcs_proxy" not in m.values()


def test_reverse_layer1_smf_imsi_to_static_container():
    # Layer 1 (주): IP -> IMSI (SMF table) -> container (static boot 맵), netns 제로.
    spec = DefInputSpec.load()
    res = resolve_targets(spec, docker=None, backend=None)   # live tun scan 전혀 없음
    assert res.ip_map == {}                                  # layer-2 역방향 맵은 비어 있음
    t = SmfSessionTable()
    t.add("001010000000002", "10.45.0.11")                   # attacker 세션 (동적 IP)
    # layer 1 은 tun scan / exec / nsenter 없이 pause target 을 resolve
    assert reverse_container_for_ip("10.45.0.11", res, smf_table=t) == "attacker_ue"
    # 미지의 IP 는 fail-closed 유지 (없는 pause target 을 지어내지 않음)
    assert reverse_container_for_ip("10.45.0.99", res, smf_table=t) is None
    # SMF table 없으면 layer 1 스킵 -> layer 2 비어 있음 -> None (여전히 fail-closed)
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
    # ANSI-strip 없이도 raw 줄은 여전히 파싱됨 (regex 는 substring), 하지만 escape 가 token span 안에
    # 있는 줄에는 strip 이 필요 — strip 이 멱등임을 단언
    assert parse_smf_line(ansi_strip(_ANSI_CREATE)).ip == "10.45.0.2"


def test_session_table_bidirectional_and_evict():
    t = SmfSessionTable()
    t.feed_line(_ANSI_CREATE)
    assert t.imsi_for_ip("10.45.0.2") == "001010000000001"
    assert t.ip_for_imsi("001010000000001") == "10.45.0.2"
    # 동일 IMSI 를 새 IP 에 재부착하면 stale 한 ip->imsi 바인딩을 축출
    t.add("001010000000001", "10.45.0.7")
    assert t.imsi_for_ip("10.45.0.2") is None and t.imsi_for_ip("10.45.0.7") == "001010000000001"
    # remove 는 양방향을 모두 clear + recent_removes 에 노출 (P4-4 join feed)
    t.feed_line(_ANSI_REMOVE)                       # 10.45.0.2 제거 (이미 사라짐) -> noop-safe
    t.remove("001010000000001", "10.45.0.7")
    assert t.ip_for_imsi("001010000000001") is None
    assert any(e.op == "remove" for e in t.recent_removes())


def test_session_table_ignores_noise():
    t = SmfSessionTable()
    assert t.feed_line("07/07 03:39:36.461: [smf] some unrelated log line") is None
    assert t.snapshot() == {}


# --------------------------------------------------------------------------- #
# P2-1: verify_anchor 는 LIVE 소비됨 -> behaviorally_verified (presence 와 구별)
# --------------------------------------------------------------------------- #
def test_behavioral_anchor_consumes_verify_anchor():
    # 선언된 각 anchor 는 매칭되는 live evidence 로만 충족됨
    assert confirm_behavioral_anchor("lo_14550_heartbeat_sys1", AnchorEvidence(heartbeat_sys=1))
    assert not confirm_behavioral_anchor("lo_14550_heartbeat_sys1", AnchorEvidence(heartbeat_sys=2))
    assert confirm_behavioral_anchor("signing_drop_log_uav_proxy", AnchorEvidence(signing_drop_seen=True))
    # fail-closed: 미지의 anchor / evidence 없음 -> False (절대 크래시 안 함)
    assert not confirm_behavioral_anchor("nonexistent_anchor", AnchorEvidence(heartbeat_sys=1))
    assert not confirm_behavioral_anchor("lo_14550_heartbeat_sys1", None)
    assert not confirm_behavioral_anchor("", AnchorEvidence())


def test_behavioral_verification_distinct_from_presence():
    spec = DefInputSpec.load()
    # evidence 없음 (boot / operator-go) -> 모든 role 이 behaviorally UNverified
    empty = apply_behavioral_verification(spec.roles, evidence=None)
    assert set(empty) >= {"uav_ue", "gcs_proxy", "web_backend", "uav_proxy"}
    assert not any(empty.values())
    # uav_ue 의 live heartbeat sysid=1 은 uav_ue 만 behaviorally_verified 로 전환
    ev = {"uav_ue": AnchorEvidence(heartbeat_sys=1)}
    got = apply_behavioral_verification(spec.roles, evidence=ev)
    assert got["uav_ue"] is True
    assert got["gcs_proxy"] is False and got["attacker_ue"] is False


def test_recon_seeds_behavioral_false_but_presence_true():
    # presence (verified)는 True 이면서 behaviorally_verified 는 False 로 남을 수 있음 (operator-go)
    st = recon_boot(docker=_Docker(), backend=_tun_backend())
    w = st["worldstate"]
    assert w.role_verified["uav_ue"] is True                 # resolve/present 됨
    assert w.behaviorally_verified["uav_ue"] is False        # boot 시 live anchor evidence 없음
    assert set(w.behaviorally_verified) == set(w.role_verified)  # 전체 role 집합, 두 판정 모두


# --------------------------------------------------------------------------- #
# recon_boot baseline
# --------------------------------------------------------------------------- #
def test_recon_boot_builds_baseline():
    st = recon_boot(docker=_Docker(), backend=_tun_backend())
    w = st["worldstate"]
    # ports / reach: 닫힌 vocab 을 False 로 시드
    assert w.reach and all(v is False for v in w.reach.values())
    # NAS/posture baseline 클린; signing 관측값 UNKNOWN (기대값은 spec 에 존재, P2-Q2)
    assert w.signing is SigningObs.UNKNOWN and w.threat["command"] == "none"
    # live 2단계 resolve 로부터 IP map + role_verified
    assert w.role_verified["uav_ue"] is True and w.role_verified["attacker_ue"] is True
    assert w.ip_map.get("uav") == "10.45.0.2"
    assert w.ip_map.get("10.45.0.10") == "attacker_ue"      # 역방향 (C-3)
    assert w.pid.get("uav_ue") == 1001
    assert w.config_version and w.baseline.rtt_mdev_ms == 11.0


def test_recon_boot_inert_without_docker():
    st = recon_boot(docker=None, backend=None)
    w = st["worldstate"]
    assert w.pid == {} and not any(w.role_verified.values())
    assert w.reach and w.signing is SigningObs.UNKNOWN   # baseline 은 여전히 조립됨 (P2-Q2)


# --------------------------------------------------------------------------- #
# P3-Q2: signing drop-line 관측이 world.signing 을 래치 (MONOTONIC, fail-safe)
# 하고 send_signed_mode legality 를 해제 (signing + role_verified.gcs)
# --------------------------------------------------------------------------- #
def _sign_ev(seq=1):
    from mdg.core.state import SensorEv
    return SensorEv(source_id="uav_signlog", seq=seq, metric="Signing_Drop", value=3,
                    band="normal", domain="command", channel="uav_proxy_signlog",
                    verified=True, tamper=False)


def _sense_with(evs, world=None):
    import queue as _q
    from mdg.core.nodes.sense import sense
    inbox = _q.Queue()
    for e in evs:
        inbox.put(e)
    st = {"worldstate": world} if world is not None else {}
    return sense(st, inbox=inbox, verify=lambda env: (True, "ok", env))


def test_signing_latch_confirmed_on_drop_observed():
    # drop-line evidence 관측됨 -> UNKNOWN 이 CONFIRMED_ON 으로 승격
    out = _sense_with([_sign_ev()])
    assert out["worldstate"].signing is SigningObs.CONFIRMED_ON


def test_signing_latch_unknown_when_no_observation():
    # 이번 tick 에 drop evidence 없음 -> UNKNOWN 유지 (fail-safe: silence/absence 는 절대 승격 안 함)
    assert _sense_with([])["worldstate"].signing is SigningObs.UNKNOWN
    # 무관한 신호 (잘못된 metric/channel)는 승격되어서는 안 됨 (래치 스푸핑 금지)
    from mdg.core.state import SensorEv
    bogus = SensorEv(source_id="x", seq=1, metric="Signing_Drop", value=1, band="normal",
                     channel="not_the_signlog", verified=True, tamper=False)
    assert _sense_with([bogus])["worldstate"].signing is SigningObs.UNKNOWN


def test_signing_latch_is_monotonic():
    # 일단 CONFIRMED_ON 이면, 관측 없는 이후 tick 도 CONFIRMED_ON 유지 (래치됨)
    w = WorldState(signing=SigningObs.CONFIRMED_ON)
    assert _sense_with([], world=w)["worldstate"].signing is SigningObs.CONFIRMED_ON


def test_send_signed_mode_legal_iff_signing_confirmed_and_gcs_verified():
    from mdg.core.legality import is_legal
    from mdg.core.state import Action
    act = Action(tool_id="send_signed_mode", params={"enforce_at": "gcs_proxy"}, risk="HIGH")
    cfg = "mdg-cfg-test"
    # CONFIRMED_ON + role_verified.gcs (enforce_at=gcs_proxy 로 resolve) -> legal
    on = WorldState(signing=SigningObs.CONFIRMED_ON, role_verified={"gcs_proxy": True},
                    config_version=cfg)
    ok, why = is_legal(act, on, cfg)
    assert ok, why
    # UNKNOWN signing -> illegal (미충족 precondition: signing) — live/boot posture
    unk = WorldState(signing=SigningObs.UNKNOWN, role_verified={"gcs_proxy": True},
                     config_version=cfg)
    ok2, _ = is_legal(act, unk, cfg)
    assert not ok2
    # CONFIRMED_ON 이지만 gcs verified 아님 -> illegal (미충족 precondition: role_verified.gcs)
    norole = WorldState(signing=SigningObs.CONFIRMED_ON, role_verified={"gcs_proxy": False},
                        config_version=cfg)
    ok3, _ = is_legal(act, norole, cfg)
    assert not ok3


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
