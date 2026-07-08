"""DefInputSpec — the defense agent's input specification (P2, pydantic v2).

ZERO hardcoding contract: this module carries NO inline testbed value (no pinned IP,
no container name literal). Every value is loaded from config (``loader.input_spec()``
-> ``input_spec.yaml`` override or ``defaults.INPUT_SPEC``). The class is pure
structure + validation + convenience accessors, so the A-1 failure mode (a
constant-ised ``10.45.0.3`` that is already wrong live) is structurally impossible.

Only STABLE identifiers (container/network names, ports, NF endpoints, pool CIDRs)
are declared in config. Per-UE dynamic tun IPs are never declared — they are resolved
live by ``resolve.py`` stage-2.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from ..config import loader


class RoleSpec(BaseModel):
    """One role's stable descriptor. ``ip`` is deliberately ABSENT — resolved live."""
    role: str
    container: str
    netns: bool = False                     # does a netns collector tap join this container?
    cellular_network: Optional[str] = None  # docker net exposing the RAN-side IP (inspect)
    tun_iface: Optional[str] = None         # UE-pool iface for stage-2 tun scan (e.g. tun_srsue)
    imsi: Optional[str] = None              # static IMSI<->container BOOT CONSTANT (P2-Q1 layer-1).
    #                                         Read from the ue.conf/ue2.conf host bind-mount source
    #                                         (NOT exec/nsenter); the dynamic tun IP is NEVER pinned.
    verify_anchor: str = ""                 # behavioural role_verified anchor (live-observed)
    reach: list[str] = Field(default_factory=list)

    @property
    def is_ue_pool(self) -> bool:
        """UE-pool role: has a tun iface -> needs the 2-stage (inspect + tun-scan) verify."""
        return bool(self.tun_iface)


class DefInputSpec(BaseModel):
    config_version: str = ""
    signing_expected: bool = False          # §9-B policy expectation (observed separately)
    ue_pool_cidr: str = ""                   # dynamic UE pool; membership-checked, not pinned
    ran_cidr: str = ""
    roles: list[RoleSpec] = Field(default_factory=list)
    nf_endpoints: dict[str, str] = Field(default_factory=dict)
    log_containers: dict[str, str] = Field(default_factory=dict)
    ports: dict[str, int] = Field(default_factory=dict)
    reach_targets: list[str] = Field(default_factory=list)

    # -- construction ------------------------------------------------------ #
    @classmethod
    def load(cls, cfg: Optional[dict] = None) -> "DefInputSpec":
        """Build from config (loader.input_spec) or an explicit dict (tests). No literals."""
        return cls.model_validate(cfg if cfg is not None else loader.input_spec())

    # -- accessors --------------------------------------------------------- #
    def role_by_container(self, container: str) -> Optional[RoleSpec]:
        return next((r for r in self.roles if r.container == container), None)

    def role_by_name(self, role: str) -> Optional[RoleSpec]:
        return next((r for r in self.roles if r.role == role), None)

    def netns_containers(self) -> list[str]:
        """Containers whose netns a collector tap joins (recon->collector bridge set)."""
        return [r.container for r in self.roles if r.netns]

    def tun_roles(self) -> list[RoleSpec]:
        """Roles requiring the stage-2 live tun-IP scan (UE-pool, A-1)."""
        return [r for r in self.roles if r.is_ue_pool]

    def imsi_container_map(self) -> dict[str, str]:
        """Static IMSI -> container map (P2-Q1 layer-1). Boot constant from ue*.conf
        bind-mount; enables IP->IMSI(SMF log)->container pause-target resolution WITHOUT
        netns entry. Empty when no role declares an ``imsi`` (fail-closed to layer-2)."""
        return {r.imsi: r.container for r in self.roles if r.imsi}

    def initial_reach(self) -> dict[str, bool]:
        """Closed reach vocabulary seeded to False (observed True later by collectors)."""
        return {k: False for k in self.reach_targets}
