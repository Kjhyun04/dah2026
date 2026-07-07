"""core.modules.resolve — 타깃 해석·IP 추출·역할 확정 (문서 13 §5 · 14).

P2 정찰의 '타깃해석' 절반. recon(reach/unauth/signing/seid)이 **무엇에 닿나**를
채운다면, 이 모듈은 **어디에 닿나**(role→컨테이너→IP:port)를 런타임에 해석한다.

2단계 원칙(14 §0):
  ① 해석(init)     : owner-side. role→컨테이너→IP·port (docker inspect / docker exec).
  ② 확정 측정(runtime): attacker-observable. 5762 HEARTBEAT 로 역할 서명 확인
                        (sysid==1 ∧ type==QUADROTOR) → prov=verified. 실패 시 미바인딩.

동적 IP 대응(13 §0·§5):
  - config 는 **컨테이너 이름**(하드코딩 0) + 논리 포트. IP 는 런타임 해석.
  - bridge net IP = `docker inspect <name>` (.NetworkSettings.Networks).
  - UE풀 tun IP(10.45.x)는 srsue 가 만들어 inspect 에 안 보임 → `docker exec <name>
    ip -br addr show tun_srsue` 로 추출.
  - route_net(vantage, role): 벤티지가 라우팅되는 net 선택(14 §3 표) → 어느 소스 IP 를 쓸지.

★ 실행은 **backend.run 경유만** — 직접 docker/ssh subprocess 호출 코드 없음(종료계약·R6
  일관). ExecRequest(sidecar='host', on_host=True) 로 호스트 CLI(docker inspect/exec)를,
  sidecar='ue' 로 tools_ue 의 식별 프로브를 태운다.
★ 이 워크플로우는 **완전 오프라인** — 아래 async 메서드는 테스트베드에 실행되지 않는다.
  코드+결정론 파서만 제공하며, 실제 inspect/probe 는 런북(배포 게이트1)으로 위임한다.
★ 하드코딩 0: 컨테이너 이름·net 이름·포트·iface 는 전부 주입(InputSpec.tgt/exec.vantage).
★ grep0: 감독/ground-truth 미참조 — 공격자-관측(inspect 권한 + 5762 백도어)만.
작성 2026-07-06.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Mapping, Optional

from core.modules.backends import (
    Backend,
    CRSError,
    Err,
    ExecOutput,
    ExecRequest,
    Ok,
    Result,
)

# ═══════════════════════════════════════════════════════════════════════════
# 0. 상수 — 식별 서명(14 §2) · 기본 iface (전부 참조/기본값; 하드코딩 아님·주입 가능)
# ═══════════════════════════════════════════════════════════════════════════

# MAVLink 식별 서명(14 §2). 값 정합은 pymavlink MAV_TYPE_QUADROTOR==2, UAV SYSID==1.
UAV_SYSID: int = 1
MAV_TYPE_QUADROTOR: int = 2

# UE풀 tun iface 기본명(srsue). 인스턴스가 다르면 생성자에서 주입(하드코딩 0).
_DEFAULT_TUN_IFACE: str = "tun_srsue"
# 논리 포트 기본(14 §1: SITL 시리얼 백도어). 미지정 role 은 config port 로 주입.
_DEFAULT_UAV_PORT: int = 5762


# 실행 발판(13 §3). resolver 는 host(inspect/exec)와 ue(식별 프로브)만 사용.
type Vantage = Literal["ue", "core", "sgi", "host"]


class Net(str, Enum):
    """도달 net 부류 (13 §0 실측). route_net 이 벤티지→net 을 고른다.

    값 = docker network **논리 이름의 기본값**(inspect Networks 키와 매칭). 인스턴스별
    실제 net 이름이 다르면 TargetResolver(net_names=...) 로 재매핑(하드코딩 0).
    """

    CELLULAR = "net_cellular"  # UE eth0 직결(mongo·sgwu)
    CORE = "net_core"          # 코어망(pivot 후 pfcp)
    SGI = "net_sgi"            # SGi C2 앱계층(oracle·web)
    UE_POOL = "ue_pool"        # tun_srsue 10.45.x (inspect 미노출 → exec 추출)


# ═══════════════════════════════════════════════════════════════════════════
# 1. route_net — 벤티지가 라우팅되는 net 선택 (14 §3 표. 결정론.)
# ═══════════════════════════════════════════════════════════════════════════

# (vantage) → (role → Net). 실측 근거(13 §0·14 §3). role 키 = TgtSpec 어휘(config).
#   UE 벤티지: uav5762=UE풀(UE-to-UE), mongo/s1u/pivot=net_cellular(eth0 직결),
#              oracle/web/cipher=net_sgi(gcs_proxy 앱계층 라우팅).
#   SGi 벤티지: C2 앱 전부 net_sgi 로컬.
#   core 벤티지(pivot 후): pfcp/pivot=net_core.
_ROUTE: dict[str, dict[str, Net]] = {
    "ue": {
        "uav5762": Net.UE_POOL,
        "mongo": Net.CELLULAR,
        "s1u": Net.CELLULAR,
        "pivot": Net.CELLULAR,
        "oracle": Net.SGI,
        "web": Net.SGI,
        "cipher": Net.SGI,
    },
    "sgi": {
        "oracle": Net.SGI,
        "web": Net.SGI,
        "cipher": Net.SGI,
        "uav_proxy": Net.SGI,
    },
    "core": {
        "pfcp_upf": Net.CORE,
        "pivot": Net.CORE,
    },
}


def route_net(vantage: str, role: str) -> Net:
    """(벤티지, role) → 도달에 쓸 Net (14 §3 실측 규칙). 미정의 조합은 CRSError.

    ★ 정직성: 라우팅 근거 없는 (벤티지,role) 은 임의 추정하지 않고 실패시킨다
      (하드코딩 fallback 금지). host 벤티지는 net 개념 없음 → 호출 부적절(CRSError).
    """
    table = _ROUTE.get(vantage)
    if table is None:
        raise CRSError(
            f"route_net: no routing for vantage {vantage!r}",
            extra={"known_vantages": sorted(_ROUTE)},
        )
    net = table.get(role)
    if net is None:
        raise CRSError(
            f"route_net: role {role!r} not routable from vantage {vantage!r}",
            extra={"known_roles": sorted(table)},
        )
    return net


# ═══════════════════════════════════════════════════════════════════════════
# 1-B. args_template IP placeholder → role (닫힌 주입면. safeexec 러너가 소비)
# ═══════════════════════════════════════════════════════════════════════════

# 닫힌 placeholder→role 맵(임의 주입면 차단; role 은 _ROUTE/TgtSpec 어휘와 정합).
#   registry.py INJECT tool 의 args_template 이 쓰는 IP placeholder 만 여기 등록한다.
#   미등록 field(예: mode)는 IP 로 취급 안 함 → resolver 미개입(planner ParamSpec 영역).
IP_PLACEHOLDER_ROLES: dict[str, str] = {"oracle_ip": "oracle", "cipher_ip": "cipher"}
# (web8080 역경로 대비 "web_ip":"web" 는 후속 확장 슬롯; 지금은 미등록=미노출.)

# render_argv 의 format_map 과 동일 파싱규약(string.Formatter). 재사용(1 인스턴스).
_FORMATTER = string.Formatter()


def target_ip_fields(args_template: str) -> tuple[str, ...]:
    """args_template 에서 IP placeholder field 만 추출(순수·결정론·오프라인).

    "{oracle_ip}:14556 mode {mode}" -> ("oracle_ip",);  "mode {mode}" -> ();  "" -> ().
    IP_PLACEHOLDER_ROLES 에 등록된 field 만, 등장 순서 보존·dedup. mode 등 비-IP field 는 무시.
    render_argv 의 format_map(_StrMap) 과 동일한 Formatter().parse 규약을 따른다.
    """
    out: list[str] = []
    for _lit, field_name, _spec, _conv in _FORMATTER.parse(args_template or ""):
        if field_name is None:
            continue
        if field_name in IP_PLACEHOLDER_ROLES and field_name not in out:
            out.append(field_name)
    return tuple(out)


# ═══════════════════════════════════════════════════════════════════════════
# 2. 결정론 파서 — inspect Networks · ip -br addr · HEARTBEAT (raw→fact)
#    (오프라인: 아래 파서만으로 로컬 검증 가능. 실행 없이 순수 함수.)
# ═══════════════════════════════════════════════════════════════════════════


def parse_inspect_networks(stdout: str) -> dict[str, str]:
    """`docker inspect -f '{{json .NetworkSettings.Networks}}'` → {net_name: ip}.

    입력 JSON: {"net_cellular": {"IPAddress": "10.44.0.31", ...}, ...}.
    빈 IPAddress(연결됐지만 미할당)는 제외(보수: 확실한 것만). 파싱 실패 → {}.
    """
    s = (stdout or "").strip()
    if not s:
        return {}
    try:
        obj = json.loads(s)
    except (ValueError, TypeError):
        return {}
    if not isinstance(obj, dict):
        return {}
    out: dict[str, str] = {}
    for net_name, spec in obj.items():
        if not isinstance(spec, dict):
            continue
        ip = spec.get("IPAddress")
        if isinstance(ip, str) and _looks_ipv4(ip):
            out[str(net_name)] = ip
    return out


def parse_br_addr(stdout: str, iface: str = _DEFAULT_TUN_IFACE) -> Optional[str]:
    """`ip -br addr show <iface>` → 첫 IPv4 주소(프리픽스 제거). 없으면 None.

    출력 예: `tun_srsue  UNKNOWN  10.45.0.3/16` → '10.45.0.3'. iface 토큰 유무 무관하게
    라인에서 dotted-quad/CIDR 토큰을 결정론 추출(브리핑 포맷 `-br`).
    """
    if not stdout:
        return None
    for line in stdout.splitlines():
        toks = line.split()
        if not toks:
            continue
        # iface 지정 조회이므로 통상 첫 토큰이 iface — 그래도 토큰 전체를 스캔(견고).
        for tok in toks:
            addr = tok.split("/", 1)[0]
            if _looks_ipv4(addr):
                return addr
    return None


@dataclass(frozen=True, slots=True)
class HeartbeatObs:
    """5762 HEARTBEAT 관측(확정 측정 입력, 14 §2). 공격자-가시 백도어 시리얼."""

    sysid: Optional[int] = None
    mav_type: Optional[int] = None

    @property
    def is_uav(self) -> bool:
        """진짜 UAV 판정(14 §2): sysid==1 ∧ type==QUADROTOR(2). GCS(255)/기타 배제."""
        return self.sysid == UAV_SYSID and self.mav_type == MAV_TYPE_QUADROTOR


def parse_heartbeat(stdout: str) -> HeartbeatObs:
    """식별 프로브의 HEARTBEAT JSON → HeartbeatObs. 키 별칭 허용(스크립트 규약 흡수).

    수용 키: sysid|srcSystem|src_system, type|mav_type|mavtype. 값은 int 강제(실패=None).
    파싱 실패/빈 입력 → 빈 관측(is_uav=False, 보수: 확정 못 하면 미바인딩).
    """
    s = (stdout or "").strip()
    if not s:
        return HeartbeatObs()
    try:
        d = json.loads(s)
    except (ValueError, TypeError):
        return HeartbeatObs()
    if not isinstance(d, dict):
        return HeartbeatObs()
    sysid = _first_int(d, ("sysid", "srcSystem", "src_system"))
    mav_type = _first_int(d, ("type", "mav_type", "mavtype"))
    return HeartbeatObs(sysid=sysid, mav_type=mav_type)


def _first_int(d: Mapping[str, object], keys: tuple[str, ...]) -> Optional[int]:
    for k in keys:
        if k in d:
            v = d[k]
            if isinstance(v, bool):
                return None
            try:
                return int(v)  # type: ignore[arg-type]
            except (ValueError, TypeError):
                return None
    return None


def _looks_ipv4(s: str) -> bool:
    """결정론 IPv4 dotted-quad 형태 검사(경량, 파싱 게이트용)."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if not (0 <= int(p) <= 255):
            return False
    return True


# ═══════════════════════════════════════════════════════════════════════════
# 3. ResolvedTarget — 해석 결과(KB reach 바인딩 재료, prov 포함)
# ═══════════════════════════════════════════════════════════════════════════


type Provenance = Literal["config", "signature-discovered", "runtime-verified"]


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """role → (ip, port, net) 해석 1건 + 출처(14 §5). verified 만 완전 신뢰."""

    role: str
    ip: str
    port: int
    net: Net
    prov: Provenance = "config"
    verified: bool = False  # §2 확정 측정 통과(현재는 uav 만 해당)


# ═══════════════════════════════════════════════════════════════════════════
# 4. TargetResolver — role→IP 해석 + 확정 측정 (전부 backend.run 경유)
# ═══════════════════════════════════════════════════════════════════════════


class TargetResolver:
    """컨테이너 이름 기반 타깃맵을 런타임에 해석(동적 UE풀 IP 흡수).

    tgt          : role → 컨테이너 **이름**(config.InputSpec.tgt. IP 아님·하드코딩 0).
    ports        : role → 논리 포트(config). 미지정 role 은 uav_port 등 기본 사용.
    net_names    : Net → 실제 docker network 이름 재매핑(기본=Net.value). 인스턴스 흡수.
    backend      : 실행 경유(host inspect/exec · ue 식별 프로브). 직접 docker 호출 금지.
    tun_iface    : UE풀 tun iface 명(기본 tun_srsue, 주입 가능).
    docker_bin   : docker CLI(기본 'docker', 주입 가능).
    identify_script: tools_ue 식별 프로브 경로(VENDOR SLOT·baked). 5762 HEARTBEAT→JSON.

    ★ 오프라인: async 메서드는 테스트베드 무실행. 커맨드 조립 + 파서만 제공.
    """

    def __init__(
        self,
        *,
        backend: Backend,
        tgt: Mapping[str, str],
        ports: Optional[Mapping[str, int]] = None,
        net_names: Optional[Mapping[Net, str]] = None,
        tun_iface: str = _DEFAULT_TUN_IFACE,
        docker_bin: str = "docker",
        uav_port: int = _DEFAULT_UAV_PORT,
        identify_script: str = "dah_exec/R4_UE_ENTRY/identify_uav.py",
    ) -> None:
        self._backend = backend
        # role→name (빈/None 값 제거 — 미제공 role 은 해석 대상 아님).
        self._tgt: dict[str, str] = {r: n for r, n in dict(tgt).items() if n}
        self._ports: dict[str, int] = dict(ports or {})
        self._net_names: dict[Net, str] = dict(net_names or {})
        self._tun_iface = tun_iface
        self._docker = docker_bin
        self._uav_port = uav_port
        self._identify_script = identify_script

    # ── 이름/포트/net 이름 해석(하드코딩 0) ──────────────────────────────
    def container_of(self, role: str) -> str:
        name = self._tgt.get(role)
        if not name:
            raise CRSError(
                f"resolve: no container name for role {role!r}",
                extra={"configured_roles": sorted(self._tgt)},
            )
        return name

    def port_of(self, role: str) -> int:
        if role in self._ports:
            return self._ports[role]
        if role == "uav5762":
            return self._uav_port
        raise CRSError(f"resolve: no port for role {role!r} (config.port 필요)")

    def net_name(self, net: Net) -> str:
        """Net → 실제 docker network 이름(재매핑 없으면 enum 기본값)."""
        return self._net_names.get(net, net.value)

    # ── 커맨드 조립(전부 ExecRequest — backend.run 경유) ──────────────────
    def _inspect_req(self, name: str) -> ExecRequest:
        """호스트 `docker inspect -f '{{json .NetworkSettings.Networks}}' <name>`."""
        argv = (
            self._docker,
            "inspect",
            "-f",
            "{{json .NetworkSettings.Networks}}",
            name,
        )
        return ExecRequest(sidecar="host", argv=argv, on_host=True, tool_id="resolve:inspect")

    def _tun_req(self, name: str) -> ExecRequest:
        """호스트 `docker exec <name> ip -br addr show <tun_iface>` (UE풀 tun 추출)."""
        argv = (
            self._docker,
            "exec",
            name,
            "ip",
            "-br",
            "addr",
            "show",
            self._tun_iface,
        )
        return ExecRequest(sidecar="host", argv=argv, on_host=True, tool_id="resolve:tun")

    def _identify_req(self, ip: str, port: int) -> ExecRequest:
        """tools_ue 식별 프로브: 5762 HEARTBEAT 1개 읽어 {sysid,type} JSON(RO, 14 §2).

        argv[0]=baked 식별 스크립트, argv[1]=`tcp:<ip>:<port>`(pymavlink 연결 문자열).
        비밀 없음(secret_params 무관). ue 벤티지(netns=attacker_ue) 로 실행.
        """
        argv = (self._identify_script, f"tcp:{ip}:{port}")
        return ExecRequest(sidecar="ue", argv=argv, tool_id="resolve:identify")

    # ── 실행 헬퍼(오프라인: 미실행) ──────────────────────────────────────
    async def _run(self, req: ExecRequest) -> Result[ExecOutput]:
        """backend.run 위임. 예외 누출 금지(Result 봉투)."""
        try:
            return await self._backend.run(req)
        except CRSError as e:
            return Err(e)
        except Exception as e:  # noqa: BLE001
            return Err(CRSError(f"resolve run failed: {type(e).__name__}", extra={"tool": req.tool_id}))

    # ── ① 해석(bridge/tun IP) ────────────────────────────────────────────
    async def resolve_ip(self, role: str, vantage: str) -> Result[str]:
        """role@vantage → IP 문자열만 해석(port 불요). backend.run 경유(직접 docker 0).

        net==UE풀 → tun(docker exec ip addr) IP, 그 외 → inspect bridge[net] IP.
        미바인딩(IP 미추출/실행실패) → Err(봉쇄, 14 §5 정직). safeexec IP 주입의 단일 소스.
        """
        try:
            name = self.container_of(role)
            net = route_net(vantage, role)
        except CRSError as e:
            return Err(e)

        if net == Net.UE_POOL:
            match await self._run(self._tun_req(name)):
                case Err() as e:
                    return e
                case Ok(out):
                    ip = parse_br_addr(out.stdout, self._tun_iface)
        else:
            match await self._run(self._inspect_req(name)):
                case Err() as e:
                    return e
                case Ok(out):
                    nets = parse_inspect_networks(out.stdout)
                    ip = nets.get(self.net_name(net))

        if not ip:
            return Err(
                CRSError(
                    f"resolve: could not extract IP for {role!r} on {net.value}",
                    extra={"role": role, "vantage": vantage, "net": net.value},
                )
            )
        return Ok(ip)

    async def resolve(self, role: str, vantage: str) -> Result[ResolvedTarget]:
        """role@vantage → ResolvedTarget (14 §3 알고리즘). backend.run 경유.

        외부계약(ResolvedTarget 필드/시그니처/prov) 불변. 내부는 resolve_ip 위임으로 리팩터.
        포트는 config(port_of). prov=config(측정 전). UAV 는 verify_uav 로 승격.
        """
        try:
            port = self.port_of(role)
            net = route_net(vantage, role)
        except CRSError as e:
            return Err(e)
        match await self.resolve_ip(role, vantage):
            case Err() as e:
                return e
            case Ok(ip):
                return Ok(
                    ResolvedTarget(role=role, ip=ip, port=port, net=net, prov="config")
                )
        return Err(CRSError("resolve: resolve_ip contract violation"))  # pragma: no cover

    # ── ② 확정 측정(UAV 서명) ────────────────────────────────────────────
    async def verify_uav(self, target: ResolvedTarget) -> Result[ResolvedTarget]:
        """5762 HEARTBEAT 로 진짜 UAV 확정(14 §2). 통과 시 prov=runtime-verified.

        측정 실패/불일치 → Err(미바인딩 → 해당 계층 봉쇄, 14 §5 정직). backend.run 경유.
        """
        match await self._run(self._identify_req(target.ip, target.port)):
            case Err() as e:
                return e
            case Ok(out):
                obs = parse_heartbeat(out.stdout)
        if not obs.is_uav:
            return Err(
                CRSError(
                    "verify_uav: HEARTBEAT signature mismatch (not sysid=1 ∧ quad)",
                    extra={"sysid": obs.sysid, "type": obs.mav_type},
                )
            )
        return Ok(
            ResolvedTarget(
                role=target.role,
                ip=target.ip,
                port=target.port,
                net=target.net,
                prov="runtime-verified",
                verified=True,
            )
        )


__all__ = [
    "Net",
    "Vantage",
    "Provenance",
    "route_net",
    "IP_PLACEHOLDER_ROLES",
    "target_ip_fields",
    "parse_inspect_networks",
    "parse_br_addr",
    "parse_heartbeat",
    "HeartbeatObs",
    "ResolvedTarget",
    "TargetResolver",
    "UAV_SYSID",
    "MAV_TYPE_QUADROTOR",
]
