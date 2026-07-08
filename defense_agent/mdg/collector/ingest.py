"""SensorEnvelope + verify_envelope — consumption-layer ingest auth (PS-2).

Both gRPC (:50051) and in-proc queue collectors enqueue this envelope. ``sense``
verifies HMAC + seq at the DRAIN moment (not transport layer) before any WorldState
merge. Failure -> discard payload + emit tamper Incident (fail-closed for forgery),
drain continues (fail-open for empty). Keyring holds current+previous kid (PS-5).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field

from ..core.state import SensorEv
from ..ledger.intent_ledger import SeqWatermark


@dataclass
class SensorEnvelope:
    payload: dict
    source_id: str
    kid: str
    seq: int
    ts: float
    nonce: str
    hmac: str = ""


def _canonical(payload: dict, source_id: str, seq: int, ts: float, nonce: str) -> bytes:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{body}|{source_id}|{seq}|{ts}|{nonce}".encode("utf-8")


def compute_hmac(env: SensorEnvelope, key: bytes) -> str:
    msg = _canonical(env.payload, env.source_id, env.seq, env.ts, env.nonce)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


@dataclass
class Keyring:
    """Per-kid HMAC keys (current+previous, PS-5). Keys live here only — NOT in State."""
    keys: dict[str, bytes] = field(default_factory=dict)

    def get(self, kid: str) -> bytes | None:
        return self.keys.get(kid)


def verify_envelope(env: SensorEnvelope, keyring: Keyring, seqwm: SeqWatermark) -> tuple[bool, str]:
    """Return (ok, reason). ok=False -> tamper (discard + tamper Incident)."""
    key = keyring.get(env.kid)
    if key is None:
        return False, f"unknown kid: {env.kid}"
    expected = compute_hmac(env, key)
    if not hmac.compare_digest(expected, env.hmac):
        return False, "hmac mismatch"
    if not seqwm.accept(env.source_id, env.seq):
        return False, "seq replay"
    return True, "ok"


def envelope_to_ev(env: SensorEnvelope, verified: bool) -> SensorEv:
    p = env.payload
    return SensorEv(
        source_id=env.source_id, kid=env.kid, seq=env.seq, ts=env.ts, nonce=env.nonce,
        metric=str(p.get("metric", "")), value=p.get("value"),
        band=str(p.get("band", "normal")), domain=p.get("domain"),
        channel=str(p.get("channel", "")), confidence=float(p.get("confidence", 0.9)),
        source=str(p.get("source") or p.get("ip") or p.get("imsi") or p.get("remote") or ""),
        verified=verified, tamper=not verified,
    )
