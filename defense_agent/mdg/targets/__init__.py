"""targets/ — P2 reconnaissance / target resolution.

DefInputSpec (config-sourced, zero hardcoded IPs) drives role->container->IP
resolution (resolve.py). Both are consumed by ``core.recon.recon_boot`` to build the
boot baseline (signing / NAS / ports / IP map) and by ``docker pause`` target
resolution (C-3). No subprocess here beyond the injected safe-exec Backend (불변식②);
no docker sdk / sock literal (PS-1 / verify_grep0 boundary).
"""
from __future__ import annotations

from .inputspec import DefInputSpec, RoleSpec
from .resolve import (ResolveResult, parse_ip_addr_show, resolve_targets,
                      reverse_container_for_ip)

__all__ = [
    "DefInputSpec", "RoleSpec",
    "ResolveResult", "resolve_targets", "parse_ip_addr_show",
    "reverse_container_for_ip",
]
