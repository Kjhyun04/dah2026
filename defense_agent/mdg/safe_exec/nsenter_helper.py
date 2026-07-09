"""nsenter_helper — 순수 net-namespace 진입 prefix 빌더 + PID 해석 (P1-netns).

표준 netns 진입 = ``nsenter --target <host-pid> --net --`` (net namespace 전용).
근거 (P1 패널, locked):
  - ``ip netns exec <container>`` 는 거부: docker 는 컨테이너의 netns 를
    ``/var/run/netns`` 아래에 등록하지 않으므로, boot 시점 symlink
    (``ln -s /proc/<pid>/ns/net /var/run/netns/<name>`` = 상태 변경, 운영제약 저촉)이 필요해진다.
    ``nsenter --target <pid>`` 는 ``/proc/<pid>/ns/net`` 에 직접 도달, 상태 변경 0.
  - ``--net`` 단독: mount namespace 는 mdg 의 것으로 유지되어 tcpdump/ss/pymavlink 가
    mdg-image 바이너리로 해석된다. 이는 B-2 (air 이미지에 curl/nc 부재)를 무력화한다: 대상의
    바이너리는 절대 쓰지 않고 오직 mdg 의 것을 대상의 network ns 안에서 실행한다.

경계: 이 모듈은 docker sdk import 도, sock/proxy URL 리터럴도 보유하지 않는다
(verify_grep0 / PS-1). ``inspect_pid(container) -> int | None`` 를 노출하는 duck-typed
``docker`` 백엔드를 소비한다 (sock-proxy 기반 safe-exec docker 백엔드, PS-1/§5). Fail-closed:
host PID 를 해석할 수 없는 컨테이너는 맵에서 제외되고 해당 collector 는 inert 로 동작한다
(오조준 live tap 없음; 누수-0 정합).
"""
from __future__ import annotations

from typing import Optional


def netns_prefix_for(pid: Optional[int]) -> Optional[list[str]]:
    """해석된 host PID 에 대한 표준 net-namespace 진입 prefix, 또는 None.

    None => 미해석 대상 => collector 는 inert 로 동작 (returns []). ``--net`` 단독은
    mdg 의 mount ns 를 유지하여 mdg-image 도구가 대상 netns 안에서 실행되게 한다 (B-2). Sentinel 3종:
    ``None`` = 미해석(inert) · ``[]`` = 현재 netns 에서 실행 · non-empty = 대상 진입.
    """
    if not pid or int(pid) <= 0:
        return None
    return ["nsenter", "--target", str(int(pid)), "--net", "--"]


def resolve_netns_targets(docker, containers: list[str]) -> dict[str, int]:
    """sock-proxy inspect (.State.Pid) 를 통한 container -> host PID, read-only.

    해석에 실패한 컨테이너는 맵에서 제외된다 (fail-closed). ``docker`` 는
    safe-exec docker 백엔드 (duck-typed ``inspect_pid``); None 이면 빈 맵을 반환한다.
    """
    out: dict[str, int] = {}
    if docker is None:
        return out
    for c in containers:
        try:
            pid = docker.inspect_pid(c)
        except Exception:                      # 단일 미해석 대상이 recon 을 중단시켜선 안 된다
            pid = None
        if pid and int(pid) > 0:
            out[c] = int(pid)
    return out


def build_netns_prefix_map(pidmap: dict[str, int]) -> dict[str, list[str]]:
    """Launcher 브리지: container -> nsenter prefix, 미해석 (None) 항목은 제외.

    ``build_collectors(..., netns_prefix_map=...)`` 에 공급된다; 거기의 ``.get(container)`` 는
    여기 없는 컨테이너에 대해 None 을 반환하므로 해당 collector 는 inert 로 동작한다.
    """
    m: dict[str, list[str]] = {}
    for c, pid in (pidmap or {}).items():
        pref = netns_prefix_for(pid)
        if pref is not None:
            m[c] = pref
    return m
