"""bundle.py — 원자적 응답 번들 · 멱등 applied()-skip · N-tick debounce ·
de-escalation (결정론, secret-free — 불변식1.).

강제된 응답은 ATOMIC BUNDLE(recovery op + 선택적 attack-path block, X4/X6)이다:
번들 수준 risk = max(atomic risk), reversible = all(atomic reversible) — ``rank_recovery`` 가
routing 필드로 승격시키는 바로 그 집계(PA-4). 이 모듈은 act 노드와 driver 의 de-escalation sweep 이
WorldState + 틱 카운터 에서만 읽는 세 가지 구동-규율 술어를 추가한다(in-graph clock 없음, LLM 없음,
subprocess 없음):

  1. 멱등 skip        — 이미 적용되고 effect-confirm 된(그리고 revert 되지 않은) 규칙은
                         no-op; 재적용은 중복 부작용이 된다. ``act`` 가 건너뛴다.
  2. N-tick debounce   — 마지막 적용으로부터 ``min_ticks`` 이내에 재선택된 물리 규칙은
                         보류된다(X5), flap 방지. ``AppliedRule.applied_tick`` 사용.
  3. de-escalation     — 적용+confirm 되고 ``quiet_s`` 동안 조용한 규칙은 revert
                         후보가 된다(X5/E15). driver 가 대역외(out-of-band)로 revert 한다(live 는
                         operator-go). ``FLIGHT_ACTION_AUTO_REVERT`` 는 False 유지(flight 는 절대 자동 revert 안 함).

모든 함수는 순수하다: 동일 (world, tick) -> 동일 verdict, 따라서 replay 는 byte-stable 하다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import defaults as D
from .state import Action, Intent
from .worldstate import AppliedRule, WorldState

_RISK_ORDER = {"LOW": 0, "MED": 1, "HIGH": 2}


@dataclass
class Bundle:
    """원자적 응답 번들. risk = max(op risk), reversible = all(op reversible)."""
    rule: str
    ops: list[Action] = field(default_factory=list)
    revert_cmd: str = ""

    @property
    def risk(self) -> str:
        if not self.ops:
            return "LOW"
        return max(self.ops, key=lambda a: _RISK_ORDER.get(a.risk, 0)).risk

    @property
    def reversible(self) -> bool:
        return all(a.reversible for a in self.ops)


def build_bundle(intent: Intent, extra_ops: list[Action] | None = None) -> Bundle:
    """선택된 Intent 에 대한 원자적 번들을 조립한다(단일 recovery op + 선택적
    attack-path-block op). risk/reversible 은 ``Bundle`` 프로퍼티(max/all)로 집계된다 —
    routing 필드가 지니는 것과 동일한 보수적 집계(PA-4)."""
    primary = Action(
        tool_id=intent.tool_id,
        params={"recovery_type": intent.rule},
        risk="MED", reversible=True, recovery_type=intent.rule,
    )
    ops = [primary] + list(extra_ops or [])
    revert = intent.revert_cmd or f"revert:{intent.rule}"
    return Bundle(rule=intent.rule, ops=ops, revert_cmd=revert)


def _live_applied(world: WorldState, rule: str) -> AppliedRule | None:
    """``rule`` 이 현재 유효(revert 되지 않음)하면 그 AppliedRule 을 반환한다."""
    ap = (world.applied or {}).get(rule)
    if ap is None or getattr(ap, "reverted", False):
        return None
    return ap


def already_applied(world: WorldState, rule: str) -> bool:
    """멱등 skip 술어: 규칙이 이미 적용되고 effect-confirm 되었으므로(PA-2)
    재적용은 중복 부작용이다. 적용됐지만 미확인인 규칙은 건너뛰지 않는다
    (effect_confirm 이 아직 delta 를 증명하지 않음; 다음 apply 가 여전히 필요할 수 있음)."""
    ap = _live_applied(world, rule)
    return ap is not None and bool(ap.confirmed)


def debounce_blocked(world: WorldState, rule: str, now_tick: int,
                     min_ticks: int | None = None) -> bool:
    """N-tick debounce (X5): 규칙이 ``min_ticks`` 틱 미만 이전에 적용됐을 때만 True.

    ``AppliedRule.applied_tick`` 을 읽는다(State-carried -> replay-safe). 한 번도 적용되지 않은
    규칙(부재)은 차단되지 않는다. min_ticks 기본값은 DEBOUNCE_PHYSICAL_MIN_TICKS.
    """
    m = D.DEBOUNCE_PHYSICAL_MIN_TICKS if min_ticks is None else int(min_ticks)
    ap = _live_applied(world, rule)
    if ap is None:
        return False
    delta = int(now_tick) - int(ap.applied_tick)
    return 0 <= delta < m


def deescalation_due(world: WorldState, now_ts: float,
                     quiet_s: int | None = None) -> list[AppliedRule]:
    """>= quiet_s 동안 조용한 적용+confirm 규칙을 반환한다(revert 후보, X5/E15).

    FLIGHT_ACTION_AUTO_REVERT(기본 False)가 아니면 flight action 은 제외된다: flight-mode
    revert 는 절대 자동이 아니다. driver 가 대역외로 revert 를 수행한다(live 는 operator-go).
    """
    q = D.DEESCALATION_REVERT_QUIET_S if quiet_s is None else int(quiet_s)
    out: list[AppliedRule] = []
    for rule, ap in (world.applied or {}).items():
        if getattr(ap, "reverted", False) or not ap.confirmed:
            continue
        is_flight = rule.startswith("signed_") or rule == "command_override"
        if is_flight and not D.FLIGHT_ACTION_AUTO_REVERT:
            continue
        if ap.ts and (now_ts - ap.ts) >= q:
            out.append(ap)
    return out


def min_debounce_ticks() -> int:
    return int(D.DEBOUNCE_PHYSICAL_MIN_TICKS)
