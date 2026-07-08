"""MissionConfigCollector — config-derived mission context (M1~M3/M8).

Unlike the sensor collectors this observes no wire/log: it reads the canonical
mission_profile config and emits a low-frequency mission-context heartbeat so the
pipeline carries current phase/priority as evidence. Pure config read — no subprocess,
no network. It only emits when the mission context changes (edge-triggered) plus a
periodic refresh, so it does not flood the queue.
"""
from __future__ import annotations

from typing import Optional

from ..config import loader
from .base import BaseCollector


class MissionConfigCollector(BaseCollector):
    source_id = "mission_config"
    domain = "mission"

    def __init__(self, *args, profile: Optional[dict] = None, refresh_every: int = 30, **kw):
        # mission changes slowly; default to a long interval.
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
