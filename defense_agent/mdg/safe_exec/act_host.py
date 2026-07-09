"""act_host — 서명 없는 3개 대응 도구를 위한 최소 권한 집행 호스트
(닫힌 레지스트리의 소유자 ``act_host``: nsenter_input_drop / docker_pause /
docker_net_disconnect).

메커니즘 분리(PS-1 권한분리):
  - ``nsenter_input_drop`` (AUTO)  : ``nsenter --target <pid> --net -- iptables ...``로
    대상의 network namespace 안에 적용되는 netns INPUT DROP(C-1). ``--net``만으로는
    mdg의 mount ns를 유지하므로, mdg-image ``iptables`` 바이너리가 대상 netns 안에서 실행된다
    (B-2 무력화). 이것이 자동 집행이 허용되는 유일한 대응이다.
  - ``docker_pause`` / ``docker_net_disconnect`` (OPER) : DUCK-TYPED docker backend를 거친다
    (sock-proxy 기반 safe-exec docker backend, PS-1 — POST /pause가 프록시 화이트리스트가
    허용하는 유일한 상태 변경). 이 모듈은 docker sdk import도, sock/proxy 리터럴도 갖지 않는다;
    ``None`` backend는 operator-go DRY dict를 반환한다.

경계(불변식2.): 이 모듈은 절대 subprocess를 import하지 않는다. ``ExecRequest``(argv
리스트)를 만들어 유일한 spawn 지점인 ``Backend.run``에 넘긴다. 최소 권한: netns DROP은
CAP_NET_ADMIN만(+nsenter 재연결을 위한 CAP_SYS_ADMIN) 필요하다; 오직 이 헬퍼에만 부여되며,
core/signer에는 절대 부여하지 않는다. Live 집행은 operator-go 유보다: ``Backend(allow_live=False)``는
DRY-RUN을 반환하므로, 운영자가 플래그를 뒤집기 전까지 테스트베드를 아무것도 바꾸지 않는다.
"""
from __future__ import annotations

from typing import Optional

from .backend import Backend, ExecRequest, ExecResult
from .nsenter_helper import netns_prefix_for

# iptables는 -w로 호출되어 busy xtables lock이 경쟁 대신 대기한다(멱등 apply/delete).
_IPT = ["iptables", "-w"]


def drop_argv(pid: Optional[int], src_ip: str, *, revert: bool = False,
              chain: str = "INPUT") -> Optional[list[str]]:
    """nsenter 진입으로 접두된 netns iptables DROP(또는 그 -D revert) argv를 만든다.

    대상 PID가 미해결이면 None을 반환한다(불활성 — 잘못 겨냥된 live tap/DROP 없음,
    누수-0 정합). ``-I``는 DROP을 삽입한다; ``revert=True``는 대응하는 ``-D`` 삭제를 방출한다.
    """
    prefix = netns_prefix_for(pid)
    if prefix is None:                     # 미해결 대상 -> 불활성(sentinel None)
        return None
    op = "-D" if revert else "-I"
    return [*prefix, *_IPT, op, chain, "-s", src_ip, "-j", "DROP"]


def drop_revert_cmd(pid: Optional[int], src_ip: str, *, chain: str = "INPUT") -> str:
    """-D revert의 문자열 형태(apply 전에 ledger에 기록됨, G3)."""
    argv = drop_argv(pid, src_ip, revert=True, chain=chain)
    return " ".join(argv) if argv else f"revert:input_drop:{src_ip}"


class ActHost:
    """서명 없는 3개 대응 도구를 safe-exec backend로 디스패치한다.

    ``backend`` = netns DROP을 위한 단일 subprocess 소유자(Backend.run).
    ``docker``  = pause/net-disconnect를 위한 duck-typed sock-proxy docker backend(선택;
                  None -> operator-go DRY). 기대 메서드: pause/unpause/net_disconnect/
                  net_connect(container[, network]).
    """

    def __init__(self, backend: Optional[Backend] = None, docker=None):
        self.backend = backend or Backend(allow_live=False)   # operator-go 유보 default
        self.docker = docker

    # -- AUTO: netns INPUT DROP ------------------------------------------- #
    def apply_input_drop(self, pid: Optional[int], src_ip: str,
                         *, timeout_s: float = 8.0) -> ExecResult:
        """Backend.run으로 대상 netns 안에 ``src_ip``에 대한 DROP을 삽입한다(allow_live가
        아니면 DRY). 미해결 PID -> 불활성 DRY 결과(spawn 없음)."""
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
        """duck-typed docker backend를 호출한다; None 또는 없는 메서드 -> operator-go DRY."""
        fn = getattr(self.docker, method, None) if self.docker is not None else None
        if fn is None:
            return {"ok": True, "dry_run": True,
                    "note": f"operator-go 유보: docker.{method}{args} (no live docker backend)"}
        try:
            res = fn(*args)
        except Exception as exc:                       # 절대 누출 금지; dry note로 강등
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
