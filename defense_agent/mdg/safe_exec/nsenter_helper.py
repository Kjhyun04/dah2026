"""nsenter_helper — pure net-namespace entry-prefix builder + PID resolution (P1-netns).

Canonical netns entry = ``nsenter --target <host-pid> --net --`` (net namespace ONLY).
Rationale (P1 panel, locked):
  - ``ip netns exec <container>`` is REJECTED: docker does not register a container's
    netns under ``/var/run/netns``, so it would require a boot-time symlink
    (``ln -s /proc/<pid>/ns/net /var/run/netns/<name>`` = a state change, 운영제약 저촉).
    ``nsenter --target <pid>`` reaches ``/proc/<pid>/ns/net`` directly, zero state change.
  - ``--net`` ALONE: the mount namespace stays mdg's, so tcpdump/ss/pymavlink resolve
    to mdg-image binaries. This neutralises B-2 (the air image lacks curl/nc): we never
    use the target's binaries, only mdg's, executed inside the target's network ns.

Boundaries: this module holds NO docker sdk import and NO sock/proxy URL literal
(verify_grep0 / PS-1). It consumes a duck-typed ``docker`` backend exposing
``inspect_pid(container) -> int | None`` (the sock-proxy-backed safe-exec docker backend,
PS-1/§5). Fail-closed: a container whose host PID cannot be resolved is omitted from the
map and its collector runs inert (no mis-targeted live tap; 누수-0 정합).
"""
from __future__ import annotations

from typing import Optional


def netns_prefix_for(pid: Optional[int]) -> Optional[list[str]]:
    """Canonical net-namespace entry prefix for a resolved host PID, or None.

    None => unresolved target => collector runs inert (returns []). ``--net`` alone keeps
    mdg's mount ns so mdg-image tools run inside the target netns (B-2). Sentinel triad:
    ``None`` = unresolved(inert) · ``[]`` = run in current netns · non-empty = enter target.
    """
    if not pid or int(pid) <= 0:
        return None
    return ["nsenter", "--target", str(int(pid)), "--net", "--"]


def resolve_netns_targets(docker, containers: list[str]) -> dict[str, int]:
    """container -> host PID via sock-proxy inspect (.State.Pid), read-only.

    Containers that fail to resolve are omitted from the map (fail-closed). ``docker`` is
    the safe-exec docker backend (duck-typed ``inspect_pid``); None yields an empty map.
    """
    out: dict[str, int] = {}
    if docker is None:
        return out
    for c in containers:
        try:
            pid = docker.inspect_pid(c)
        except Exception:                      # a single unresolved target must not abort recon
            pid = None
        if pid and int(pid) > 0:
            out[c] = int(pid)
    return out


def build_netns_prefix_map(pidmap: dict[str, int]) -> dict[str, list[str]]:
    """Launcher bridge: container -> nsenter prefix, dropping unresolved (None) entries.

    Feeds ``build_collectors(..., netns_prefix_map=...)``; the ``.get(container)`` there
    returns None for any container absent here, so that collector runs inert.
    """
    m: dict[str, list[str]] = {}
    for c, pid in (pidmap or {}).items():
        pref = netns_prefix_for(pid)
        if pref is not None:
            m[c] = pref
    return m
