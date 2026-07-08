"""resolve — role -> container -> IP 2-stage verification (P2, H-I / A-1 / C-3).

Why 2 stages (A-1): UE-pool IPs (10.45.0.x) are re-assigned per attach and live ONLY on
the container's ``tun_srsue`` interface — they are ABSENT from ``docker inspect`` (which
shows the static cellular-net IP, 10.44.0.x). So a single inspect cannot resolve the
target; a runtime scan of the tun iface is required.

  Stage 1 (inspect, read-only): container existence + host PID (.State.Pid) + cellular-net
          IP. provenance="inspect".
  Stage 2 (tun scan, UE-pool roles only): ``ip -4 addr show <tun_iface>`` run INSIDE the
          container's net namespace, yielding the dynamic 10.45.x IP. When the scanned IP
          is in the UE-pool CIDR the binding is verified. provenance="verified".

Mechanism reconciliation (locked, P2-Q1): the gap note (A-1) phrased stage-2 as
``docker exec ... ip addr``, but PS-1 explicitly DENIES ``exec`` at the docker-socket
proxy. Only the TRANSPORT is replaced; the observation semantics are preserved. The
sanctioned equivalent is the netns entry that already backs every air-side tap:
``nsenter --target <pid> --net -- ip -4 addr show <iface>`` (nsenter_helper), routed
through the safe-exec Backend (불변식②, the sole subprocess path). This enters the
container's NETWORK namespace only (mount ns stays mdg's, so mdg's ``ip`` binary runs —
neutralising B-2) and needs no docker exec. Zero state change; a non-allow_live Backend
returns DRY-RUN so the live scan is operator-go reserved (IP stays unresolved -> inert).

Pause-target resolution is 2-layer (P2-Q1, ``reverse_container_for_ip``):
  Layer 1 (PRIMARY, zero netns entry) — IP -> IMSI [SMF session-table log, P4-1] ->
    container [static IMSI<->container boot map from ue*.conf, ``spec.imsi_container_map``].
    Closes the pause-target on whitelisted endpoints (inspect + logs) alone; needs no
    exec and no nsenter. This is the primary path (minimises the netns-entry surface).
  Layer 2 (SECONDARY, ground-truth cross-check) — the reverse ip_map built from the live
    nsenter tun scan. Used when the SMF table has no binding yet (session not created /
    rotated / idle), where the direct tun read is the only ground truth. Both layers
    coexist; layer 1 alone is insufficient, so the tun-scan is DEMOTED (not removed) from
    "unique reverse map" to "ground-truth cross-check".

Boundaries: duck-typed ``docker`` backend (``inspect_pid`` required; optional
``inspect_networks``); NO docker sdk import, NO sock/proxy URL literal here (verify_grep0).
Fail-closed: any unresolved stage leaves the binding un-verified and its downstream tap /
pause-target inert (no mis-targeted actuation; 누수-0 정합).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from ..core.worldstate import RoleBinding
from ..safe_exec.nsenter_helper import netns_prefix_for
from .inputspec import DefInputSpec, RoleSpec

# ``inet 10.45.0.2/32 scope global tun_srsue`` -> 10.45.0.2 (first IPv4 of ip-addr-show).
_INET_RE = re.compile(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})")


@dataclass
class ResolveResult:
    bindings: dict[str, RoleBinding] = field(default_factory=dict)   # container -> binding
    pidmap: dict[str, int] = field(default_factory=dict)             # container -> host pid
    ip_map: dict[str, str] = field(default_factory=dict)             # role/ip -> ip/container
    imsi_container: dict[str, str] = field(default_factory=dict)     # static IMSI -> container (P2-Q1 L1)

    def role_verified(self) -> dict[str, bool]:
        return {c: b.verified for c, b in self.bindings.items()}


def parse_ip_addr_show(text: str, iface: str = "") -> Optional[str]:
    """First IPv4 from ``ip addr show`` output, or None. ``iface`` is advisory (the
    command already targets one iface); we simply take the first ``inet`` address."""
    if not text:
        return None
    m = _INET_RE.search(text)
    return m.group(1) if m else None


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    if not ip or not cidr:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _inspect_pid(docker, container: str) -> Optional[int]:
    try:
        pid = docker.inspect_pid(container)
    except Exception:                       # one unresolved target must not abort recon
        return None
    return int(pid) if pid and int(pid) > 0 else None


def _inspect_cellular_ip(docker, container: str, network: Optional[str]) -> Optional[str]:
    """Best-effort cellular-net IP via optional duck-typed ``inspect_networks``.
    Absent method / unknown network -> None (stage-1 falls back to pid-only presence).

    Backend contract (P2-Q3, LOCK — honoured by the future ``safe_exec/docker_backend.py``):
      - SOURCE: the value comes ONLY from ``GET /containers/{id}/json`` body field
        ``.NetworkSettings.Networks`` (PS-1 whitelisted). It MUST NOT hit the docker
        ``/networks`` route — PS-1 DENIES "networks" (the method name is a misnomer trap).
      - SHAPE: ``inspect_networks(container) -> {docker_net_name: IPAddress}`` — a FLATTENED,
        PROJECTED ``dict[str,str]`` (never the raw Gateway/MacAddress/EndpointID sub-object).
        Keyed by network NAME (matches ``RoleSpec.cellular_network``); empty IPAddress omitted.
      - SECRET HYGIENE (load-bearing, PS-3): the backend parses ONLY ``.State.Pid`` and
        ``.NetworkSettings.Networks[*].{name,IPAddress}`` and drops ``.Config.Env`` / ``.Mounts``
        / labels AT PARSE TIME — a sibling inspect legitimately carries API keys in Env.
      - SINGLE-SNAPSHOT: pid AND networks derive from ONE inspect body per (container, pass).
      - DEGRADE: absent method / 4xx / malformed -> None; the cellular IP is ADVISORY (infra
        address + pause diagnosis), never a verification predicate. infra role_verified stays
        (pid is not None); UE-pool verify is the stage-2 tun-scan, so pid-only degrade is safe."""
    if not network or not hasattr(docker, "inspect_networks"):
        return None
    try:
        nets = docker.inspect_networks(container) or {}
    except Exception:
        return None
    ip = nets.get(network)
    return str(ip) if ip else None


def _tun_scan(role: RoleSpec, pid: int, backend) -> Optional[str]:
    """Stage-2: ``nsenter --target <pid> --net -- ip -4 addr show <tun>`` via Backend.
    None on: no backend / DRY-RUN (operator-go) / non-zero / no inet parsed."""
    if backend is None:
        return None
    prefix = netns_prefix_for(pid)
    if prefix is None:
        return None
    from ..safe_exec.backend import ExecRequest
    argv = list(prefix) + ["ip", "-4", "addr", "show", role.tun_iface or ""]
    res = backend.run(ExecRequest(argv=argv, timeout_s=6.0, read_only=True))
    if res is None or getattr(res, "dry_run", False) or not getattr(res, "ok", False):
        return None
    return parse_ip_addr_show(res.stdout or "", role.tun_iface or "")


def resolve_role(role: RoleSpec, docker, backend, ue_pool_cidr: str = "") -> tuple[RoleBinding, Optional[int]]:
    """Resolve ONE role -> (RoleBinding, host pid|None). Fail-closed per stage."""
    rb = RoleBinding(role=role.role, container=role.container, provenance="config")
    if docker is None:
        return rb, None

    # -- stage 1: inspect (existence + pid + cellular IP) ------------------ #
    pid = _inspect_pid(docker, role.container)
    cellular_ip = _inspect_cellular_ip(docker, role.container, role.cellular_network)
    if pid is not None or cellular_ip:
        rb.provenance = "inspect"

    # -- stage 2: tun scan (UE-pool roles only, A-1) ---------------------- #
    if role.is_ue_pool and pid is not None:
        tun_ip = _tun_scan(role, pid, backend)
        if tun_ip and _ip_in_cidr(tun_ip, ue_pool_cidr):
            rb.ip = tun_ip
            rb.verified = True                 # both stages passed (inspect + tun in pool)
            rb.provenance = "verified"
        elif tun_ip:                           # scanned but outside the pool CIDR
            rb.ip = tun_ip                     # record for diagnosis; not verified
    else:
        # infra role (no tun): inspect presence IS the verification; cellular IP is the addr
        if cellular_ip:
            rb.ip = cellular_ip
        rb.verified = pid is not None
    return rb, pid


def resolve_targets(spec: DefInputSpec, docker=None, backend=None) -> ResolveResult:
    """Resolve every role in the spec. container-keyed bindings/pidmap + a mixed ip_map
    (role->ip forward and ip->container reverse for pause-target C-3)."""
    result = ResolveResult(imsi_container=spec.imsi_container_map())   # static L1 boot map (P2-Q1)
    for role in spec.roles:
        rb, pid = resolve_role(role, docker, backend, spec.ue_pool_cidr)
        result.bindings[role.container] = rb
        if pid is not None:
            result.pidmap[role.container] = pid
        if rb.ip:
            result.ip_map[role.role] = rb.ip          # forward: role -> ip
            result.ip_map[rb.ip] = role.container      # reverse: ip -> container (C-3)
    return result


def reverse_container_for_ip(ip: str, result: ResolveResult, smf_table=None) -> Optional[str]:
    """docker pause target resolution (C-3): UE-pool source IP -> container. 2-layer (P2-Q1).

    Layer 1 (PRIMARY, zero netns entry): IP -> IMSI [``smf_table.imsi_for_ip``, SMF log
    P4-1] -> container [static ``result.imsi_container`` boot map]. Preferred because it
    closes the target on whitelisted endpoints (inspect + logs) alone.

    Layer 2 (SECONDARY, ground-truth cross-check): the reverse ip_map from the live nsenter
    tun scan + an explicit binding scan. Used when the SMF table has no binding yet.

    ``smf_table`` is any object exposing ``imsi_for_ip(ip) -> imsi|None`` (SmfSessionTable);
    absent -> layer 1 is skipped and layer 2 is authoritative. Returns None when neither
    layer resolves (fail-closed: no pause target invented)."""
    if not ip:
        return None
    # -- layer 1: SMF-log IMSI -> static container map (primary) ----------- #
    if smf_table is not None and result.imsi_container:
        try:
            imsi = smf_table.imsi_for_ip(ip)
        except Exception:                              # a lookup fault must not abort resolution
            imsi = None
        if imsi:
            cand = result.imsi_container.get(imsi)
            if cand:
                return cand
    # -- layer 2: live tun-scan reverse map + binding scan (secondary) ----- #
    cand = result.ip_map.get(ip)
    if cand:
        return cand
    for container, rb in result.bindings.items():      # explicit binding scan fallback
        if rb.ip and rb.ip == ip:
            return container
    return None
