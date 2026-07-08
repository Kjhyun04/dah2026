"""act_host — minimal-privilege actuation host for the 3 non-signing response tools
(owner ``act_host`` in the closed registry: nsenter_input_drop / docker_pause /
docker_net_disconnect).

Mechanism split (PS-1 권한분리):
  - ``nsenter_input_drop`` (AUTO)  : a netns INPUT DROP applied INSIDE the target's network
    namespace via ``nsenter --target <pid> --net -- iptables ...`` (C-1). Because ``--net``
    alone keeps mdg's mount ns, the mdg-image ``iptables`` binary runs inside the target netns
    (B-2 neutralised). This is the ONLY response that may auto-actuate.
  - ``docker_pause`` / ``docker_net_disconnect`` (OPER) : go through a DUCK-TYPED docker backend
    (the sock-proxy-backed safe-exec docker backend, PS-1 — POST /pause is the sole state-change
    the proxy whitelist allows). This module holds NO docker sdk import and NO sock/proxy literal;
    a ``None`` backend yields an operator-go DRY dict.

Boundaries (불변식②): this module NEVER imports subprocess. It BUILDS an ``ExecRequest`` (argv
list) and hands it to ``Backend.run`` — the sole spawn site. Minimal privilege: the netns DROP
needs only CAP_NET_ADMIN (+CAP_SYS_ADMIN for the nsenter re-associate); ONLY this helper is granted
them, never core/signer. Live actuation is operator-go RESERVED: ``Backend(allow_live=False)``
returns DRY-RUN, so nothing changes the testbed until an operator flips the flag.
"""
from __future__ import annotations

from typing import Optional

from .backend import Backend, ExecRequest, ExecResult
from .nsenter_helper import netns_prefix_for

# iptables invoked with -w so a busy xtables lock waits instead of racing (idempotent apply/delete).
_IPT = ["iptables", "-w"]


def drop_argv(pid: Optional[int], src_ip: str, *, revert: bool = False,
              chain: str = "INPUT") -> Optional[list[str]]:
    """Build the netns iptables DROP (or its -D revert) argv, prefixed with the nsenter entry.

    Returns None when the target PID is unresolved (inert — no mis-targeted live tap/DROP,
    누수-0 정합). ``-I`` inserts the DROP; ``revert=True`` emits the matching ``-D`` delete.
    """
    prefix = netns_prefix_for(pid)
    if prefix is None:                     # unresolved target -> inert (sentinel None)
        return None
    op = "-D" if revert else "-I"
    return [*prefix, *_IPT, op, chain, "-s", src_ip, "-j", "DROP"]


def drop_revert_cmd(pid: Optional[int], src_ip: str, *, chain: str = "INPUT") -> str:
    """String form of the -D revert (recorded to the ledger BEFORE apply, G3)."""
    argv = drop_argv(pid, src_ip, revert=True, chain=chain)
    return " ".join(argv) if argv else f"revert:input_drop:{src_ip}"


class ActHost:
    """Dispatches the 3 non-signing response tools over safe-exec backends.

    ``backend`` = the single subprocess owner (Backend.run) for the netns DROP.
    ``docker``  = duck-typed sock-proxy docker backend for pause/net-disconnect (optional;
                  None -> operator-go DRY). Expected methods: pause/unpause/net_disconnect/
                  net_connect(container[, network]).
    """

    def __init__(self, backend: Optional[Backend] = None, docker=None):
        self.backend = backend or Backend(allow_live=False)   # operator-go 유보 default
        self.docker = docker

    # -- AUTO: netns INPUT DROP ------------------------------------------- #
    def apply_input_drop(self, pid: Optional[int], src_ip: str,
                         *, timeout_s: float = 8.0) -> ExecResult:
        """Insert a DROP for ``src_ip`` inside the target netns via Backend.run (DRY unless
        allow_live). Unresolved PID -> inert DRY result (no spawn)."""
        argv = drop_argv(pid, src_ip)
        if argv is None:
            return ExecResult(ok=True, code=0, dry_run=True,
                              note=f"INERT: unresolved netns pid for input_drop src={src_ip}")
        req = ExecRequest(argv=argv, timeout_s=timeout_s,
                          revert_cmd=drop_revert_cmd(pid, src_ip), reversible=True)
        return self.backend.run(req)

    def revert_input_drop(self, pid: Optional[int], src_ip: str,
                          *, timeout_s: float = 8.0) -> ExecResult:
        argv = drop_argv(pid, src_ip, revert=True)
        if argv is None:
            return ExecResult(ok=True, code=0, dry_run=True,
                              note=f"INERT: unresolved netns pid for revert src={src_ip}")
        return self.backend.run(ExecRequest(argv=argv, timeout_s=timeout_s, reversible=True))

    # -- OPER: docker pause / net-disconnect (duck-typed sock-proxy) ------- #
    def _docker_call(self, method: str, *args) -> dict:
        """Call the duck-typed docker backend; None or a missing method -> operator-go DRY."""
        fn = getattr(self.docker, method, None) if self.docker is not None else None
        if fn is None:
            return {"ok": True, "dry_run": True,
                    "note": f"operator-go 유보: docker.{method}{args} (no live docker backend)"}
        try:
            res = fn(*args)
        except Exception as exc:                       # never leak; degrade to dry note
            return {"ok": False, "dry_run": True, "note": f"docker.{method} error: {exc!r}"}
        return {"ok": True, "dry_run": getattr(res, "dry_run", False), "result": res}

    def pause(self, container: str) -> dict:
        return self._docker_call("pause", container)

    def unpause(self, container: str) -> dict:
        return self._docker_call("unpause", container)

    def net_disconnect(self, container: str, network: str) -> dict:
        return self._docker_call("net_disconnect", container, network)

    def net_connect(self, container: str, network: str) -> dict:
        return self._docker_call("net_connect", container, network)
