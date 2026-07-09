"""verify_d11_collector_disjoint — GATE1/GATE2 정적 self-DoS 가드(불변식2. E9/X1/G4/D11).

response 계층은 ``sense`` 를 먹여주는 바로 그 collector 를 절대 끊어서는 안 된다. 두 개의 독립된
절단 메커니즘이 존재하며, 각각 여기서 non-self-DoS 로 증명된다(정적 — 라이브 testbed 변경 없음):

  A. CONTAINER-LIFECYCLE 절단(docker pause / net-disconnect = collector 를 호스팅하는
     컨테이너의 완전 절단). 보장: 어떤 auto 경로도 이를 할 수 없다. effect 가
     ``container_pause`` / ``container_net_disconnect`` 인 모든 registry 도구는 tier OPER 이고(명시적
     self-impact 확인으로 operator-gate 됨), 유일한 tier-AUTO response 는 netns DROP 이다. 따라서
     collector 를 호스팅하는 컨테이너의 pause/disconnect 는 operator 확인 아래에서만 발생할 수 있고,
     결코 자율적으로 발생하지 않는다. (disjointness 요건 중 "collector 호스팅 컨테이너의 pause 는
     명시적 self-impact 노트와 함께 OPER 로 gate 된다"는 finding 의 분기를 충족한다.)

  B. NETNS-DROP 절단(유일한 AUTO response). 보장: DROP 의 match 집합은, DROP 이
     collector 를 호스팅하는 chokepoint netns 내부에서 강제되더라도, collector 의 :50051 ingest
     5-tuple / MDG mgmt CIDR 과 절대 교차할 수 없다. 구조적으로 증명됨: DROP 은 항상
     ``INPUT -s <UE-pool src> -j DROP`` — 체인은 INPUT 뿐(절대 OUTPUT/FORWARD 아님), 포트 match 없음
     (절대 :50051 / --dport / --sport 아님), 그리고 ``-s`` 소스는 검증된
     UE-pool ip map(10.45.0.0/16)에서만 해석되는데, 이는 loopback/mgmt ingest 주소와 disjoint 한 CIDR 이다.
     따라서 UE-pool 소스에 대한 INPUT 필터는 collector 의 :50051 로 향하는 OUTBOUND egress 도,
     mgmt 출처 반환 트래픽도 match 할 수 없다. 추가로 DROP 은 강제 netns 와 drop 소스가
     서로 다른(DISTINCT) 두 검증 바인딩으로 해석될 때에만 빌드된다(finding P4-2),
     따라서 결코 단일 엔티티로 붕괴할 수 없다.

실행: python mdg/verify/verify_d11_collector_disjoint.py
모든 검사는 정적/오프라인(Backend.allow_live=False DRY); 라이브 구동은 operator-go 로 유지된다.
"""
from __future__ import annotations

import ast
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.verify._util import MDG_ROOT, Report, parse, run  # noqa: E402

INGEST_PORT = "50051"
# 호스팅된 collector 를 완전히 끊는 Container-lifecycle effect — OPER 전용이어야 함.
_LIFECYCLE_EFFECTS = {"container_pause", "container_net_disconnect"}
# self-DoS-safe netns DROP 이 절대 포함해서는 안 되는 argv 리터럴.
_FORBIDDEN_ARGV = {"OUTPUT", "FORWARD", INGEST_PORT, "--dport", "--sport", "-p", "--protocol"}
# MDG mgmt / :50051 ingest 는 loopback 또는 전용 mgmt netns 에 바인딩되지(DESIGN §PS-8), 절대
# UE pool 이 아니다. drop 소스는 이들과 증명 가능하게 disjoint 해야 한다.
_MGMT_CIDRS = ["127.0.0.0/8"]


def _collector_host_containers(spec: dict) -> set[str]:
    """collector 관측점을 호스팅하는 컨테이너 집합(netns-tap 사이드카 + log-tail 소스).
    이들 중 어느 것이든 pause/net-disconnect 하거나 이들의 ingest 를 match 하는 DROP 은 sense 를 끊는다."""
    hosts: set[str] = set()
    for role in spec.get("roles", []):
        if role.get("netns") is True and role.get("container"):
            hosts.add(str(role["container"]))          # netns-tap 사이드카가 여기 함께 위치
    for cont in (spec.get("log_containers", {}) or {}).values():
        hosts.add(str(cont))                            # docker-logs tail 소스
    return hosts


# --------------------------------------------------------------------------- #
# A. container-lifecycle 절단은 OPER 전용(어떤 AUTO 도 pause/disconnect 불가)
# --------------------------------------------------------------------------- #
def _check_lifecycle_oper_gated(rep: Report) -> None:
    from mdg.core import gate as G
    from mdg.config import loader
    from mdg.tools.registry import REGISTRY

    hosts = _collector_host_containers(loader.input_spec())
    rep.check(bool(hosts), "collector-host container set is empty (spec parse failed?)")

    # 유일한 tier-AUTO 도구는 netns DROP — AUTO container-lifecycle 도구는 존재하지 않는다.
    auto_tools = {tid for tid, s in REGISTRY.items() if s.tier == "AUTO"}
    rep.check(auto_tools == {"nsenter_input_drop"},
              f"AUTO tool set must be exactly {{nsenter_input_drop}}, got {sorted(auto_tools)} "
              f"(an AUTO container-lifecycle tool could sever a collector autonomously)")

    # 모든 container-lifecycle effect 는 OPER-gate 되고, tier-2 gate 는 risk/reversible 조합
    # 전반에서 이에 대해 operator_required 를 반환한다(fail-closed self-impact 확인).
    lifecycle_tools = [tid for tid, s in REGISTRY.items() if s.effect in _LIFECYCLE_EFFECTS]
    rep.check(bool(lifecycle_tools), "no container-lifecycle tool found (registry parse failed?)")
    for tid in lifecycle_tools:
        spec = REGISTRY[tid]
        rep.check(spec.tier == "OPER",
                  f"{tid} effect={spec.effect} tier={spec.tier} — must be OPER (collector-host "
                  f"sever needs operator self-impact gate)")
        for risk in ("LOW", "MED", "HIGH"):
            for rev in (True, False):
                rep.check(G.requires_operator(tid, risk, rev),
                          f"{tid} auto-actuated at risk={risk} reversible={rev} — lifecycle sever "
                          f"must be operator-gated for ALL combos (self-DoS on a collector host)")


# --------------------------------------------------------------------------- #
# B. netns DROP match 집합은 :50051 ingest / mgmt CIDR 을 절대 건드릴 수 없음(정적 AST)
# --------------------------------------------------------------------------- #
def _check_drop_argv_shape_static(rep: Report) -> None:
    tree = parse(os.path.join(MDG_ROOT, "safe_exec", "act_host.py"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "drop_argv"), None)
    rep.check(fn is not None, "act_host.drop_argv not found (self-DoS shape unverifiable)")
    if fn is None:
        return
    # chain 기본 파라미터는 "INPUT" 이어야 함(DROP 은 chokepoint 에서 INBOUND 만 필터)
    chain_default = None
    args = fn.args
    defaults = args.defaults + [d for d in args.kw_defaults if d is not None]
    for d in defaults:
        if isinstance(d, ast.Constant) and d.value in ("INPUT", "OUTPUT", "FORWARD"):
            chain_default = d.value
    rep.check(chain_default == "INPUT",
              f"drop_argv chain default is {chain_default!r} — must be 'INPUT' (INBOUND filter only; "
              f"OUTPUT/FORWARD could match the collector's :50051 egress)")
    # 빌더 어디에도 금지 리터럴(OUTPUT/FORWARD/50051/포트 match) 없음
    consts = {n.value for n in ast.walk(fn)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    for bad in _FORBIDDEN_ARGV:
        rep.check(bad not in consts,
                  f"drop_argv contains forbidden literal '{bad}' (a port/chain match could "
                  f"intersect the :50051 ingest 5-tuple → self-DoS)")
    rep.check("-s" in consts and "DROP" in consts,
              "drop_argv must build a '-s <src> -j DROP' rule (source-only match)")


def _check_drop_argv_runtime(rep: Report) -> None:
    from mdg.safe_exec import act_host
    from mdg.config import loader

    ue_pool = ipaddress.ip_network(str(loader.input_spec().get("ue_pool_cidr", "10.45.0.0/16")))
    mgmt = [ipaddress.ip_network(c) for c in _MGMT_CIDRS]

    # UE pool(drop-source 공간)은 모든 mgmt/ingest CIDR 과 증명 가능하게 disjoint 해야 함.
    for m in mgmt:
        rep.check(not ue_pool.overlaps(m),
                  f"UE pool {ue_pool} overlaps mgmt CIDR {m} — a UE-pool -s could match the "
                  f":50051 ingest path (self-DoS)")

    # 대표적인 pool 내 소스는 ingest-port / mgmt match 가 없는 INPUT -s DROP 을 낸다.
    src = str(next(ue_pool.hosts()))                    # 첫 UE-pool 호스트(예: 10.45.0.1)
    argv = act_host.drop_argv(4242, src)
    rep.check(argv is not None, "drop_argv returned None for a resolved (pid, ue-pool src)")
    if argv is None:
        return
    rep.check("INPUT" in argv and "OUTPUT" not in argv and "FORWARD" not in argv,
              f"drop_argv chain not INPUT-only: {argv}")
    rep.check(INGEST_PORT not in argv, f"drop_argv references ingest port :{INGEST_PORT}: {argv}")
    rep.check(argv[-4:] == ["-s", src, "-j", "DROP"], f"drop_argv tail not '-s {src} -j DROP': {argv}")
    # -s 소스는 UE pool 안에 있고 어떤 mgmt CIDR 에도 속하지 않음.
    src_ip = ipaddress.ip_address(src)
    rep.check(src_ip in ue_pool, f"drop source {src} not in UE pool {ue_pool}")
    for m in mgmt:
        rep.check(src_ip not in m, f"drop source {src} falls in mgmt CIDR {m} (self-DoS)")


def _check_response_drop_src_is_verified_ue_pool(rep: Report) -> None:
    """dispatch 계층은 drop ``-s`` 를 오직 검증된 UE-pool 바인딩에서만 해석하고
    서로 다른(DISTINCT) 두 검증 endpoint 에 대해서만 DROP 을 빌드해야 한다 — mgmt/ingest 셀렉터는 무동작."""
    from mdg.core.state import Intent
    from mdg.core.worldstate import RoleBinding, WorldState
    from mdg.safe_exec.backend import Backend
    from mdg.safe_exec.response import ResponseController
    from mdg.config import loader

    ue_pool = ipaddress.ip_network(str(loader.input_spec().get("ue_pool_cidr", "10.45.0.0/16")))
    ctrl = ResponseController(backend=Backend(allow_live=False))
    ue_ip = str(next(ue_pool.hosts()))

    # (1) 서로 다른 두 검증 endpoint -> DROP 빌드됨; -s 는 UE pool 안, :50051 없음.
    w = WorldState(
        config_version="cfg", role_verified={},
        pid={"gcs_proxy": 4242, "attacker_ue": 777}, ip_map={"attacker_ue": ue_ip},
        roles={"gcs_proxy": RoleBinding(role="gcs_proxy", verified=True),
               "attacker_ue": RoleBinding(role="attacker_ue", verified=True)})
    intent = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version="cfg",
                    enforce_at="gcs_proxy", target="attacker_ue", target_kind="role")
    plan, _ = ctrl.dispatch(intent, w, 0, risk="MED", reversible=True)
    rep.check(plan.exec_request is not None,
              "two distinct verified endpoints did not build a DROP (P4-2 wiring broken)")
    if plan.exec_request is not None:
        argv = plan.exec_request.argv
        rep.check(INGEST_PORT not in argv, f"dispatched DROP references :{INGEST_PORT}: {argv}")
        si = argv.index("-s")
        rep.check(argv[si + 1] == ue_ip,
                  f"dispatched DROP -s is not the verified UE-pool ip {ue_ip}: {argv}")
        rep.check(ipaddress.ip_address(argv[si + 1]) in ue_pool,
                  f"dispatched DROP -s not inside UE pool {ue_pool}: {argv}")
        rep.check(argv[-2:] == ["-j", "DROP"], f"dispatched DROP does not end '-j DROP': {argv}")

    # (2) ip-kind 셀렉터로서의 mgmt/loopback 소스(ingest 인접)는 어떤 검증된 UE-pool
    # 바인딩과도 match 되지 않음 -> 무동작 DRY(drop -s 는 결코 ingest 주소가 될 수 없음).
    mgmt_intent = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version="cfg",
                         enforce_at="gcs_proxy", target="127.0.0.1", target_kind="ip")
    plan2, _ = ctrl.dispatch(mgmt_intent, w, 0, risk="MED", reversible=True)
    rep.check(plan2.exec_request is None,
              "a mgmt/loopback drop-source selector was NOT rejected (self-DoS surface)")


def _check() -> Report:
    rep = Report("verify_d11_collector_disjoint")
    _check_lifecycle_oper_gated(rep)                    # A
    _check_drop_argv_shape_static(rep)                  # B (정적 AST)
    _check_drop_argv_runtime(rep)                       # B (기능)
    _check_response_drop_src_is_verified_ue_pool(rep)   # B (dispatch 가드)
    return rep


if __name__ == "__main__":
    run(_check)
