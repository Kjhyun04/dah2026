"""MissionConfigCollector — config 로부터 도출한 mission context (M1~M3/M8).

sensor collector 들과 달리 wire/log 를 관측하지 않는다: canonical
mission_profile config 를 읽어 저빈도 mission-context heartbeat 를 emit 하여
pipeline 이 현재 phase/priority 를 evidence 로 실어 나르게 한다. 순수 config 읽기 —
subprocess 도 network 도 없다. mission context 가 바뀔 때(edge-triggered)와
주기적 refresh 시에만 emit 하므로 queue 를 넘치게 하지 않는다.
"""
from __future__ import annotations

from typing import Optional

from ..config import loader
from .base import BaseCollector


class MissionConfigCollector(BaseCollector):
    source_id = "mission_config"
    domain = "mission"

    def __init__(self, *args, profile: Optional[dict] = None, refresh_every: int = 30, **kw):
        # mission 은 느리게 변한다; 기본값을 긴 interval 로 둔다.
        kw.setdefault("interval_s", 10.0)
        super().__init__(*args, **kw)
        self._profile = profile
        self.refresh_every = refresh_every
        self._last_sig: Optional[tuple] = None
        self._cycles = 0

    def _load(self) -> dict:
        return self._profile if self._profile is not None else loader.mission_profile()

    def collect(self) -> list[dict]:
        prof = self._load()
        sig = (prof.get("mission_type"), prof.get("mission_phase"), prof.get("mission_priority"))
        self._cycles += 1
        changed = sig != self._last_sig
        periodic = (self._cycles % max(1, self.refresh_every)) == 0
        if not (changed or periodic):
            return []
        self._last_sig = sig
        return [{
            "metric": "mission_context", "value": prof.get("mission_priority", "High"),
            "band": "normal", "domain": "mission", "channel": "mission_profile",
            "confidence": 1.0,
            "mission_type": prof.get("mission_type"),
            "mission_phase": prof.get("mission_phase"),
            "config_version": prof.get("config_version"),
        }]
