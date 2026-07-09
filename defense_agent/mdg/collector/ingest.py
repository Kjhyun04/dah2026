"""SensorEnvelope + verify_envelope — 소비 계층 ingest 인증 (PS-2).

gRPC(:50051)와 in-proc queue collector 모두 이 envelope를 enqueue한다. ``sense``는
WorldState merge 이전에 DRAIN 시점(전송 계층이 아님)에 HMAC + seq를 검증한다. 실패 시
-> payload 폐기 + tamper Incident emit(위조에 대해 fail-closed), drain은 계속된다
(비어 있음에 대해 fail-open). Keyring은 current+previous kid를 보유한다 (PS-5).
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
    """kid별 HMAC 키(current+previous, PS-5). 키는 여기에만 존재 — State에는 없음."""
    keys: dict[str, bytes] = field(default_factory=dict)

    def get(self, kid: str) -> bytes | None:
        return self.keys.get(kid)


def verify_envelope(env: SensorEnvelope, keyring: Keyring, seqwm: SeqWatermark) -> tuple[bool, str]:
    """(ok, reason)을 반환한다. ok=False -> tamper (폐기 + tamper Incident)."""
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
