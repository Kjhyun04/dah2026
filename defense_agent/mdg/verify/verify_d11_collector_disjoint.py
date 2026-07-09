"""verify_d11_collector_disjoint — GATE1/GATE2 static self-DoS guard (불변식2. E9/X1/G4/D11).

The response layer must never sever the very collectors that feed ``sense``. Two independent
severance mechanisms exist, each proven non-self-DoS here (STATIC — no live testbed change):

  A. CONTAINER-LIFECYCLE severance (docker pause / net-disconnect = a FULL sever of a
     collector-hosting container). Guarantee: NO auto path can do this. Every registry tool whose
     effect is ``container_pause`` / ``container_net_disconnect`` is tier OPER (operator-gated with
     an explicit self-impact confirmation), and the SOLE tier-AUTO response is the netns DROP. So a
     pause/disconnect of a collector-hosting container can only happen under operator confirmation,
     never autonomously. (Satisfies the finding's "pausing a collector-hosting container is gated
     OPER with an explicit self-impact note" branch of the disjointness requirement.)

  B. NETNS-DROP severance (the sole AUTO response). Guarantee: the DROP's match set can never
     intersect the collector's :50051 ingest 5-tuple / MDG mgmt CIDR, EVEN when the DROP is enforced
     inside a collector-hosting chokepoint netns. Proven structurally: the DROP is always
     ``INPUT -s <UE-pool src> -j DROP`` — chain INPUT only (never OUTPUT/FORWARD), no port match
     (never :50051 / --dport / --sport), and the ``-s`` source is resolved ONLY from the verified
     UE-pool ip map (10.45.0.0/16), a CIDR disjoint from the loopback/mgmt ingest addressing. An
     INPUT filter on a UE-pool source therefore cannot match the collector's OUTBOUND egress to
     :50051 nor the mgmt-sourced return traffic. Additionally the DROP is built ONLY when the
     enforcement netns and the drop source resolve to two DISTINCT verified bindings (finding P4-2),
     so it can never collapse onto a single entity.

Run: python mdg/verify/verify_d11_collector_disjoint.py
All checks are static/offline (Backend.allow_live=False DRY); live actuation stays operator-go.
"""
from __future__ import annotations

import ast
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.verify._util import MDG_ROOT, Report, parse, run  # noqa: E402

INGEST_PORT = "50051"
# Container-lifecycle effects that fully sever a hosted collector — must be OPER-only.
_LIFECYCLE_EFFECTS = {"container_pause", "container_net_disconnect"}
# argv literals a self-DoS-safe netns DROP must NEVER contain.
_FORBIDDEN_ARGV = {"OUTPUT", "FORWARD", INGEST_PORT, "--dport", "--sport", "-p", "--protocol"}
# The MDG mgmt / :50051 ingest binds loopback or a dedicated mgmt netns (DESIGN §PS-8), never the
# UE pool. The drop source must be provably disjoint from these.
_MGMT_CIDRS = ["127.0.0.0/8"]


def _collector_host_containers(spec: dict) -> set[str]:
    """The set of containers that HOST a collector vantage (netns-tap sidecars + log-tail sources).
    Pausing/net-disconnecting any of these, or a DROP matching their ingest, would sever sense."""
    hosts: set[str] = set()
    for role in spec.get("roles", []):
        if role.get("netns") is True and role.get("container"):
            hosts.add(str(role["container"]))          # netns-tap sidecar co-located here
    for cont in (spec.get("log_containers", {}) or {}).values():
        hosts.add(str(cont))                            # docker-logs tail source
    return hosts


# --------------------------------------------------------------------------- #
# A. container-lifecycle severance is OPER-only (no AUTO can pause/disconnect)
# --------------------------------------------------------------------------- #
def _check_lifecycle_oper_gated(rep: Report) -> None:
    from mdg.core import gate as G
    from mdg.config import loader
    from mdg.tools.registry import REGISTRY

    hosts = _collector_host_containers(loader.input_spec())
    rep.check(bool(hosts), "collector-host container set is empty (spec parse failed?)")

    # the SOLE tier-AUTO tool is the netns DROP — no AUTO container-lifecycle tool exists.
    auto_tools = {tid for tid, s in REGISTRY.items() if s.tier == "AUTO"}
    rep.check(auto_tools == {"nsenter_input_drop"},
              f"AUTO tool set must be exactly {{nsenter_input_drop}}, got {sorted(auto_tools)} "
              f"(an AUTO container-lifecycle tool could sever a collector autonomously)")

    # every container-lifecycle effect is OPER-gated, and the tier-2 gate returns operator_required
    # for it across risk/reversible combinations (fail-closed self-impact confirmation).
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
# B. netns DROP match set can never touch the :50051 ingest / mgmt CIDR (static AST)
# --------------------------------------------------------------------------- #
def _check_drop_argv_shape_static(rep: Report) -> None:
    tree = parse(os.path.join(MDG_ROOT, "safe_exec", "act_host.py"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "drop_argv"), None)
    rep.check(fn is not None, "act_host.drop_argv not found (self-DoS shape unverifiable)")
    if fn is None:
        return
    # chain default parameter must be "INPUT" (the DROP filters INBOUND at the chokepoint only)
    chain_default = None
    args = fn.args
    defaults = args.defaults + [d for d in args.kw_defaults if d is not None]
    for d in defaults:
        if isinstance(d, ast.Constant) and d.value in ("INPUT", "OUTPUT", "FORWARD"):
            chain_default = d.value
    rep.check(chain_default == "INPUT",
              f"drop_argv chain default is {chain_default!r} — must be 'INPUT' (INBOUND filter only; "
              f"OUTPUT/FORWARD could match the collector's :50051 egress)")
    # no forbidden literal (OUTPUT/FORWARD/50051/port match) anywhere in the builder
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

    # the UE pool (drop-source space) must be provably disjoint from every mgmt/ingest CIDR.
    for m in mgmt:
        rep.check(not ue_pool.overlaps(m),
                  f"UE pool {ue_pool} overlaps mgmt CIDR {m} — a UE-pool -s could match the "
                  f":50051 ingest path (self-DoS)")

    # a representative in-pool source yields an INPUT -s DROP with no ingest-port / mgmt match.
    src = str(next(ue_pool.hosts()))                    # first UE-pool host (e.g. 10.45.0.1)
    argv = act_host.drop_argv(4242, src)
    rep.check(argv is not None, "drop_argv returned None for a resolved (pid, ue-pool src)")
    if argv is None:
        return
    rep.check("INPUT" in argv and "OUTPUT" not in argv and "FORWARD" not in argv,
              f"drop_argv chain not INPUT-only: {argv}")
    rep.check(INGEST_PORT not in argv, f"drop_argv references ingest port :{INGEST_PORT}: {argv}")
    rep.check(argv[-4:] == ["-s", src, "-j", "DROP"], f"drop_argv tail not '-s {src} -j DROP': {argv}")
    # the -s source is inside the UE pool and NOT in any mgmt CIDR.
    src_ip = ipaddress.ip_address(src)
    rep.check(src_ip in ue_pool, f"drop source {src} not in UE pool {ue_pool}")
    for m in mgmt:
        rep.check(src_ip not in m, f"drop source {src} falls in mgmt CIDR {m} (self-DoS)")


def _check_response_drop_src_is_verified_ue_pool(rep: Report) -> None:
    """The dispatch layer must resolve the drop ``-s`` ONLY from a VERIFIED UE-pool binding and
    build a DROP ONLY for two DISTINCT verified endpoints — a mgmt/ingest selector goes inert."""
    from mdg.core.state import Intent
    from mdg.core.worldstate import RoleBinding, WorldState
    from mdg.safe_exec.backend import Backend
    from mdg.safe_exec.response import ResponseController
    from mdg.config import loader

    ue_pool = ipaddress.ip_network(str(loader.input_spec().get("ue_pool_cidr", "10.45.0.0/16")))
    ctrl = ResponseController(backend=Backend(allow_live=False))
    ue_ip = str(next(ue_pool.hosts()))

    # (1) two DISTINCT verified endpoints -> DROP built; -s is inside the UE pool, no :50051.
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

    # (2) a mgmt/loopback source (ingest-adjacent) as an ip-kind selector matches NO verified
    # UE-pool binding -> inert DRY (the drop -s can never become the ingest address).
    mgmt_intent = Intent(rule="pfcp_firewall", tool_id="nsenter_input_drop", config_version="cfg",
                         enforce_at="gcs_proxy", target="127.0.0.1", target_kind="ip")
    plan2, _ = ctrl.dispatch(mgmt_intent, w, 0, risk="MED", reversible=True)
    rep.check(plan2.exec_request is None,
              "a mgmt/loopback drop-source selector was NOT rejected (self-DoS surface)")


def _check() -> Report:
    rep = Report("verify_d11_collector_disjoint")
    _check_lifecycle_oper_gated(rep)                    # A
    _check_drop_argv_shape_static(rep)                  # B (static AST)
    _check_drop_argv_runtime(rep)                       # B (functional)
    _check_response_drop_src_is_verified_ue_pool(rep)   # B (dispatch guard)
    return rep


if __name__ == "__main__":
    run(_check)
