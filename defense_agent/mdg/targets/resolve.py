"""resolve — role -> container -> IP 2단계 검증(P2, H-I / A-1 / C-3).

2단계인 이유(A-1): UE-pool IP(10.45.0.x)는 attach 마다 재할당되며 컨테이너의
tun_srsue 인터페이스에만(ONLY) 존재한다 — docker inspect(정적 cellular-net
IP 10.44.0.x 를 보여줌)에는 없다(ABSENT). 따라서 단일 inspect 로는 대상을 해석할 수
없다; tun iface 의 런타임 스캔이 필요하다.

  Stage 1 (inspect, read-only): 컨테이너 존재 + 호스트 PID(.State.Pid) + cellular-net
          IP. provenance="inspect".
  Stage 2 (tun scan, UE-pool 역할 전용): 컨테이너 net 네임스페이스 안에서(INSIDE) 실행되는
          ip -4 addr show <tun_iface>, 동적 10.45.x IP 를 산출. 스캔된 IP 가
          UE-pool CIDR 안에 있으면 바인딩이 검증됨. provenance="verified".

메커니즘 정합(locked, P2-Q1): 갭 노트(A-1)는 stage-2 를
docker exec ... ip addr 로 표현했으나, PS-1 은 docker-socket 프록시에서 exec 를
명시적으로 거부한다(DENIES). TRANSPORT 만 교체되고 관측 의미는 보존된다.
승인된 등가물은 모든 air 측 탭을 이미 뒷받침하는 netns 진입이다:
nsenter --target <pid> --net -- ip -4 addr show <iface>(nsenter_helper), safe-exec
Backend(불변식2., 유일한 subprocess 경로)를 통해 라우팅됨. 이것은 컨테이너의
NETWORK 네임스페이스에만 진입하고(mount ns 는 mdg 것 유지, 따라서 mdg 의 ip 바이너리 실행 —
B-2 무력화) docker exec 가 필요 없다. 상태변경 0; non-allow_live Backend 는
DRY-RUN 을 반환하므로 라이브 스캔은 operator-go 유보다(IP 미해석 유지 -> inert).

pause-target 해석은 2계층(P2-Q1, reverse_container_for_ip):
  Layer 1 (PRIMARY, netns 진입 0) — IP -> IMSI [SMF session-table log, P4-1] ->
    container [ue*.conf 의 static IMSI<->container boot 맵, spec.imsi_container_map].
    화이트리스트 엔드포인트(inspect + logs)만으로 pause-target 을 닫는다; exec 도
    nsenter 도 필요 없다. 이것이 주 경로다(netns 진입 표면 최소화).
  Layer 2 (SECONDARY, ground-truth 교차검증) — 라이브 nsenter tun 스캔으로 만든
    역방향 ip_map. SMF 테이블에 아직 바인딩이 없을 때(세션 미생성 /
    회전 / idle) 사용되며, 직접 tun 읽기가 유일한 ground truth 다. 두 계층은
    공존한다; layer 1 만으로는 불충분하므로 tun-scan 은 "고유 역방향 맵"에서
    "ground-truth 교차검증"으로 격하됨(제거 아님, DEMOTED).

경계: duck-typed docker 백엔드(inspect_pid 필수; inspect_networks 선택);
docker sdk import 없음, 여기 sock/proxy URL 리터럴 없음(verify_grep0).
Fail-closed: 미해석 단계는 바인딩을 미검증으로 남기고 그 하류 탭 /
pause-target 을 inert 로 둔다(오조준 작동 없음; 누수-0 정합).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from ..core.worldstate import RoleBinding
from ..safe_exec.nsenter_helper import netns_prefix_for
from .inputspec import DefInputSpec, RoleSpec

# inet 10.45.0.2/32 scope global tun_srsue -> 10.45.0.2 (ip-addr-show 의 첫 IPv4).
_INET_RE = re.compile(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})")


@dataclass
class ResolveResult:
    bindings: dict[str, RoleBinding] = field(default_factory=dict)   # container -> binding
    pidmap: dict[str, int] = field(default_factory=dict)             # container -> host pid
    ip_map: dict[str, str] = field(default_factory=dict)             # role/ip -> ip/container
    imsi_container: dict[str, str] = field(default_factory=dict)     # static IMSI -> container(P2-Q1 L1)

    def role_verified(self) -> dict[str, bool]:
        return {c: b.verified for c, b in self.bindings.items()}


def parse_ip_addr_show(text: str, iface: str = "") -> Optional[str]:
    """ip addr show 출력의 첫 IPv4, 없으면 None. iface 는 참고용이며(명령이
    이미 하나의 iface 를 대상으로 함); 단순히 첫 inet 주소를 취한다."""
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
    except Exception:                       # 하나의 미해석 대상이 recon 을 중단시켜선 안 됨
        return None
    return int(pid) if pid and int(pid) > 0 else None


def _inspect_cellular_ip(docker, container: str, network: Optional[str]) -> Optional[str]:
    """선택적 duck-typed inspect_networks 를 통한 best-effort cellular-net IP.
    메서드 부재 / 미지 네트워크 -> None(stage-1 은 pid-only 존재로 폴백).

    Backend 계약(P2-Q3, LOCK — 향후 safe_exec/docker_backend.py 가 준수):
      - SOURCE: 값은 오직(ONLY) GET /containers/{id}/json 바디 필드
        .NetworkSettings.Networks(PS-1 화이트리스트)에서 온다. docker
        /networks 라우트를 쳐선 안 된다(MUST NOT) — PS-1 은 "networks" 를 거부(DENIES)(메서드명이 misnomer 함정).
      - SHAPE: inspect_networks(container) -> {docker_net_name: IPAddress} — FLATTENED,
        PROJECTED dict[str,str](raw Gateway/MacAddress/EndpointID 서브객체 절대 아님).
        네트워크 NAME 으로 키잉됨(RoleSpec.cellular_network 와 일치); 빈 IPAddress 는 생략.
      - SECRET HYGIENE (load-bearing, PS-3): 백엔드는 오직(ONLY) .State.Pid 와
        .NetworkSettings.Networks[*].{name,IPAddress} 만 파싱하고 .Config.Env / .Mounts
        / 라벨을 파싱 시점에(AT PARSE TIME) 버린다 — 형제 inspect 는 정당하게 Env 에 API 키를 담는다.
      - SINGLE-SNAPSHOT: pid 와 networks 는 (container, pass) 당 하나의(ONE) inspect 바디에서 파생.
      - DEGRADE: 메서드 부재 / 4xx / malformed -> None; cellular IP 는 참고용(ADVISORY)(infra
        주소 + pause 진단)이며 검증 술어가 절대 아니다. infra role_verified 는 유지됨
        (pid is not None); UE-pool 검증은 stage-2 tun-scan 이므로 pid-only 격하는 안전하다."""
    if not network or not hasattr(docker, "inspect_networks"):
        return None
    try:
        nets = docker.inspect_networks(container) or {}
    except Exception:
        return None
    ip = nets.get(network)
    return str(ip) if ip else None


def _tun_scan(role: RoleSpec, pid: int, backend) -> Optional[str]:
    """Stage-2: Backend 를 통한 nsenter --target <pid> --net -- ip -4 addr show <tun>.
    None 인 경우: 백엔드 없음 / DRY-RUN(operator-go) / non-zero / inet 미파싱."""
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
    """하나의(ONE) 역할 해석 -> (RoleBinding, host pid|None). 단계별 fail-closed."""
    rb = RoleBinding(role=role.role, container=role.container, provenance="config")
    if docker is None:
        return rb, None

    # -- stage 1: inspect (존재 + pid + cellular IP) ---------------------- #
    pid = _inspect_pid(docker, role.container)
    cellular_ip = _inspect_cellular_ip(docker, role.container, role.cellular_network)
    if pid is not None or cellular_ip:
        rb.provenance = "inspect"

    # -- stage 2: tun 스캔 (UE-pool 역할 전용, A-1) ---------------------- #
    if role.is_ue_pool and pid is not None:
        tun_ip = _tun_scan(role, pid, backend)
        if tun_ip and _ip_in_cidr(tun_ip, ue_pool_cidr):
            rb.ip = tun_ip
            rb.verified = True                 # 두 단계 모두 통과(inspect + 풀 내 tun)
            rb.provenance = "verified"
        elif tun_ip:                           # 스캔했으나 풀 CIDR 밖
            rb.ip = tun_ip                     # 진단용 기록; 미검증
    else:
        # infra 역할(tun 없음): inspect 존재가 곧 검증; cellular IP 가 주소
        if cellular_ip:
            rb.ip = cellular_ip
        rb.verified = pid is not None
    return rb, pid


def resolve_targets(spec: DefInputSpec, docker=None, backend=None) -> ResolveResult:
    """spec 의 모든 역할 해석. container 로 키잉된 bindings/pidmap + 혼합 ip_map
    (role->ip 순방향, pause-target C-3 용 ip->container 역방향)."""
    result = ResolveResult(imsi_container=spec.imsi_container_map())   # static L1 boot 맵(P2-Q1)
    for role in spec.roles:
        rb, pid = resolve_role(role, docker, backend, spec.ue_pool_cidr)
        result.bindings[role.container] = rb
        if pid is not None:
            result.pidmap[role.container] = pid
        if rb.ip:
            result.ip_map[role.role] = rb.ip          # 순방향: role -> ip
            result.ip_map[rb.ip] = role.container      # 역방향: ip -> container(C-3)
    return result


def reverse_container_for_ip(ip: str, result: ResolveResult, smf_table=None) -> Optional[str]:
    """docker pause 대상 해석(C-3): UE-pool 소스 IP -> container. 2계층(P2-Q1).

    Layer 1 (PRIMARY, netns 진입 0): IP -> IMSI [smf_table.imsi_for_ip, SMF log
    P4-1] -> container [static result.imsi_container boot 맵]. 화이트리스트
    엔드포인트(inspect + logs)만으로 대상을 닫으므로 선호됨.

    Layer 2 (SECONDARY, ground-truth 교차검증): 라이브 nsenter tun 스캔의 역방향 ip_map
    + 명시적 binding 스캔. SMF 테이블에 아직 바인딩이 없을 때 사용.

    smf_table 은 imsi_for_ip(ip) -> imsi|None 을 노출하는 임의 객체(SmfSessionTable);
    부재 -> layer 1 은 건너뛰고 layer 2 가 권위적. 어느 계층도 해석하지 못하면
    None 반환(fail-closed: pause 대상을 지어내지 않음)."""
    if not ip:
        return None
    # -- layer 1: SMF-log IMSI -> static container 맵 (primary) ----------- #
    if smf_table is not None and result.imsi_container:
        try:
            imsi = smf_table.imsi_for_ip(ip)
        except Exception:                              # 조회 결함이 해석을 중단시켜선 안 됨
            imsi = None
        if imsi:
            cand = result.imsi_container.get(imsi)
            if cand:
                return cand
    # -- layer 2: 라이브 tun-scan 역방향 맵 + binding 스캔 (secondary) ----- #
    cand = result.ip_map.get(ip)
    if cand:
        return cand
    for container, rb in result.bindings.items():      # 명시적 binding 스캔 폴백
        if rb.ip and rb.ip == ip:
            return container
    return None
