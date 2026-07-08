"""IngestVerifier — PS-2 consumption-layer authentication (HMAC/seq/ts drop).

``sense`` drains the queue and calls ``verify(env)`` at the DRAIN moment (not at
transport). Only envelopes that pass HMAC + anti-replay seq (PS-6) + ts clock-skew are
merged; forgeries are dropped and surface as a tamper Incident (built by sense). Both
transport paths (gRPC :50051 and in-proc collector queue) go through this identical
consumption gate, so a compromised sidecar injecting into the in-proc queue cannot
bypass authentication (the core PS-2 threat).

This composes the locked primitives in ``collector.ingest`` (SensorEnvelope,
verify_envelope, envelope_to_ev) — no duplication of the HMAC contract — and adds the
ts clock-skew band that needs a Clock the primitive layer does not hold.
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
        # ts within ±W seconds of local clock (PS-6). ts==0 (unset) is allowed to keep
        # replay/offline fixtures usable. This band is only reached AFTER HMAC verifies
        # (see verify()), so the unset-ts allowance can never be exploited by an
        # UNauthenticated forgery — such an envelope is rejected by HMAC first, whatever
        # its ts. ts itself is part of the HMAC canonical, so a live ts cannot be forged.
        if not env.ts:
            return True
        return abs(self.clock.now() - env.ts) <= self.ts_skew_s

    def verify(self, env: SensorEnvelope) -> tuple[bool, str, SensorEv]:
        """The callable injected as graph deps['verify']. Returns (ok, reason, ev).
        ev.tamper is set when ok is False so downstream provenance gates exclude it.

        Authentication (HMAC + anti-replay seq) is verified FIRST; the ts clock-skew band
        is applied only to already-authenticated envelopes. This ordering ensures the
        ts==0 offline-fixture allowance in _ts_ok cannot be conflated with the live path:
        an unauthenticated envelope never reaches the ts check."""
        ok, reason = verify_envelope(env, self.keyring, self.seqwm)
        if not ok:
            return False, reason, envelope_to_ev(env, verified=False)
        if not self._ts_ok(env):
            return False, "ts skew", envelope_to_ev(env, verified=False)
        return True, reason, envelope_to_ev(env, verified=True)

    def __call__(self, env: SensorEnvelope) -> tuple[bool, str, SensorEv]:
        return self.verify(env)
