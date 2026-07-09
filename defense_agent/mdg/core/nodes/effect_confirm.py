"""effect_confirm (PA-2) — 그래프 내 결정론적 post-act 델타 (Verifier 아님).

관측 델타(ss/pcap/:9090 s5c_rx_deletesession diff / 14560 HB /
uav_ue lo:14550 cross-tap, D-1)를 기록하고 worldstate.applied[rule].confirmed를 설정. 실행을
게이트하지 않음 (되돌릴 수 있는 AUTO는 이미 실행됨, D-3). effect_confirm -> END;
다음 tick의 sense가 재관측. 이것은 그래프 내 effect-confirm; 그래프 외
Verifier(JSONL replay만)는 별도 프로세스이며 여기서 절대 import되지 않는다.
"""
from __future__ import annotations

from ..state import MDGState
from ..worldstate import WorldState


def effect_confirm(state: MDGState, observe=None) -> dict:
    """observe(rule)->bool 주입 (ss/metric 델타 읽음). 기본값: unconfirmed
    (다음 tick 재관측). applied[rule].confirmed + 델타 노트만 반환."""
    world: WorldState = state.get("worldstate") or WorldState()
    if not world.applied:
        return {}

    updated = world.model_copy(deep=True)
    for rule, applied in updated.applied.items():
        if applied.confirmed:
            continue
        confirmed = bool(observe(rule)) if observe is not None else False
        applied.confirmed = confirmed
        if confirmed:
            # before/after 델타 노트 (audit/viewer 전용 — exec gate 아님): read-only
            # effect observer가 관측한 unconfirmed->confirmed 전이를 기록.
            applied.confirm_note = f"effect_confirm: {rule} unconfirmed->confirmed (observe=True)"
    return {"worldstate": updated}
