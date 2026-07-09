"""DefInputSpec — 방어 에이전트의 입력 사양(P2, pydantic v2).

ZERO 하드코딩 계약: 이 모듈은 인라인 테스트베드 값을 전혀 담지 않는다(고정 IP 없음,
컨테이너명 리터럴 없음). 모든 값은 config 에서 로드된다(``loader.input_spec()``
-> ``input_spec.yaml`` 오버라이드 또는 ``defaults.INPUT_SPEC``). 클래스는 순수
구조 + 검증 + 편의 접근자이므로, A-1 실패 모드(이미 라이브에서 틀린
상수화된 ``10.45.0.3``)는 구조적으로 불가능하다.

STABLE 식별자(컨테이너/네트워크명, 포트, NF 엔드포인트, 풀 CIDR)만
config 에 선언된다. UE별 동적 tun IP 는 절대 선언되지 않는다 — ``resolve.py`` stage-2 가
라이브로 해석한다.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from ..config import loader


class RoleSpec(BaseModel):
    """한 역할의 stable 기술자. ``ip`` 는 의도적으로 ABSENT — 라이브로 해석됨."""
    role: str
    container: str
    netns: bool = False                     # netns collector 탭이 이 컨테이너에 합류하는가?
    cellular_network: Optional[str] = None  # RAN 측 IP 를 노출하는 docker net(inspect)
    tun_iface: Optional[str] = None         # stage-2 tun 스캔용 UE-pool iface(예: tun_srsue)
    imsi: Optional[str] = None              # static IMSI<->container BOOT CONSTANT(P2-Q1 layer-1).
    #                                         ue.conf/ue2.conf 호스트 bind-mount 소스에서 읽음
    #                                         (exec/nsenter 아님); 동적 tun IP 는 절대 고정 안 함.
    verify_anchor: str = ""                 # 행위 role_verified anchor(라이브 관측됨)
    reach: list[str] = Field(default_factory=list)

    @property
    def is_ue_pool(self) -> bool:
        """UE-pool 역할: tun iface 보유 -> 2단계(inspect + tun-scan) 검증 필요."""
        return bool(self.tun_iface)


class DefInputSpec(BaseModel):
    config_version: str = ""
    signing_expected: bool = False          # §9-B 정책 기대치(별도로 관측됨)
    ue_pool_cidr: str = ""                   # 동적 UE 풀; 멤버십 검사, 고정 아님
    ran_cidr: str = ""
    roles: list[RoleSpec] = Field(default_factory=list)
    nf_endpoints: dict[str, str] = Field(default_factory=dict)
    log_containers: dict[str, str] = Field(default_factory=dict)
    ports: dict[str, int] = Field(default_factory=dict)
    reach_targets: list[str] = Field(default_factory=list)

    # -- construction ------------------------------------------------------ #
    @classmethod
    def load(cls, cfg: Optional[dict] = None) -> "DefInputSpec":
        """config(loader.input_spec) 또는 명시적 dict(테스트)로부터 구성. 리터럴 없음."""
        return cls.model_validate(cfg if cfg is not None else loader.input_spec())

    # -- accessors --------------------------------------------------------- #
    def role_by_container(self, container: str) -> Optional[RoleSpec]:
        return next((r for r in self.roles if r.container == container), None)

    def role_by_name(self, role: str) -> Optional[RoleSpec]:
        return next((r for r in self.roles if r.role == role), None)

    def netns_containers(self) -> list[str]:
        """collector 탭이 netns 에 합류하는 컨테이너들(recon->collector 브리지 집합)."""
        return [r.container for r in self.roles if r.netns]

    def tun_roles(self) -> list[RoleSpec]:
        """stage-2 라이브 tun-IP 스캔이 필요한 역할들(UE-pool, A-1)."""
        return [r for r in self.roles if r.is_ue_pool]

    def imsi_container_map(self) -> dict[str, str]:
        """Static IMSI -> container 맵(P2-Q1 layer-1). ue*.conf bind-mount 에서 온
        boot 상수; netns 진입 없이(WITHOUT) IP->IMSI(SMF log)->container pause-target
        해석을 가능하게 함. 어떤 역할도 ``imsi`` 를 선언하지 않으면 비어 있음(layer-2 로 fail-closed)."""
        return {r.imsi: r.container for r in self.roles if r.imsi}

    def initial_reach(self) -> dict[str, bool]:
        """False 로 시딩된 닫힌 reach 어휘(이후 collector 가 True 로 관측)."""
        return {k: False for k in self.reach_targets}
