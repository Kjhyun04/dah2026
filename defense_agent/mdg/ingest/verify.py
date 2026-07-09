"""IngestVerifier — PS-2 소비 계층 인증(HMAC/seq/ts 드롭).

``sense`` 는 큐를 drain 하며 DRAIN 시점에(전송 시점이 아니라) ``verify(env)`` 를 호출한다.
HMAC + 재전송 방지 seq(PS-6) + ts 시계 편차를 통과한 envelope 만 병합되고, 위조본은 드롭되어
tamper Incident(sense 가 생성)로 표면화된다. 두 전송 경로(gRPC :50051 와 in-proc collector 큐)
모두 이 동일한 소비 게이트를 거치므로, 침해된 sidecar 가 in-proc 큐에 주입해도 인증을
우회할 수 없다(핵심 PS-2 위협).

이 모듈은 ``collector.ingest`` 의 잠긴 프리미티브(SensorEnvelope, verify_envelope,
envelope_to_ev)를 조합하며 — HMAC 계약을 중복하지 않음 — 프리미티브 계층이 보유하지 않는
Clock 이 필요한 ts 시계 편차 band 를 추가한다.
"""
from __future__ import annotations

from typing import Optional

from ..collector.ingest import (Keyring, SensorEnvelope, envelope_to_ev,
                                 verify_envelope)
from ..config import defaults as D
from ..core.clock import Clock, RealClock
from ..core.state import SensorEv
from ..ledger.intent_ledger import SeqWatermark


class IngestVerifier:
    def __init__(self, keyring: Keyring, seqwm: SeqWatermark, *,
                 clock: Optional[Clock] = None, ts_skew_s: float = float(D.TS_SKEW_S)):
        self.keyring = keyring
        self.seqwm = seqwm
        self.clock: Clock = clock or RealClock()
        self.ts_skew_s = ts_skew_s

    def _ts_ok(self, env: SensorEnvelope) -> bool:
        # ts 가 로컬 시계의 ±W 초 이내(PS-6). ts==0(미설정)은 replay/offline fixture 를
        # 사용 가능하게 유지하기 위해 허용된다. 이 band 는 HMAC 검증 이후에만 도달하므로
        # (verify() 참조), 미설정-ts 허용은 인증되지 않은 위조본이 악용할 수 없다 — 그런
        # envelope 은 ts 가 무엇이든 HMAC 에서 먼저 거부된다. ts 자체가 HMAC canonical 의
        # 일부이므로 live ts 는 위조될 수 없다.
        if not env.ts:
            return True
        return abs(self.clock.now() - env.ts) <= self.ts_skew_s

    def verify(self, env: SensorEnvelope) -> tuple[bool, str, SensorEv]:
        """graph deps['verify'] 로 주입되는 callable. (ok, reason, ev) 를 반환한다.
        ok 가 False 일 때 ev.tamper 가 설정되어 하위 provenance 게이트가 이를 배제한다.

        인증(HMAC + 재전송 방지 seq)이 먼저 검증되고, ts 시계 편차 band 는 이미 인증된
        envelope 에만 적용된다. 이 순서 덕분에 _ts_ok 의 ts==0 offline-fixture 허용이 live
        경로와 혼동될 수 없다: 인증되지 않은 envelope 은 결코 ts 검사에 도달하지 않는다."""
        ok, reason = verify_envelope(env, self.keyring, self.seqwm)
        if not ok:
            return False, reason, envelope_to_ev(env, verified=False)
        if not self._ts_ok(env):
            return False, "ts skew", envelope_to_ev(env, verified=False)
        return True, reason, envelope_to_ev(env, verified=True)

    def __call__(self, env: SensorEnvelope) -> tuple[bool, str, SensorEv]:
        return self.verify(env)
