"""Operator approval ledger (PS-9 / P4-Q3) — durable, secret-free anti-replay.

DECISION (P4-Q3, locked): the signed approval TOKEN (the HMAC output) is NEVER persisted
(NOT-PERSIST). Persisting a bearer credential only widens the at-rest capture surface and buys
zero replay defense (replay is stopped by the single-use nonce + short TTL, not by keeping the
token). What DOES need to survive a crash is the CONSUMED-NONCE set: ``OperatorGate._seen_nonces``
is an in-memory set, so without durability a reboot re-opens the replay window for a captured,
still-unexpired token (the same defect PS-6 fixed for seq high-watermarks).

So this ledger stores a secret-free ``OperatorApprovalReceipt`` (command-binding metadata +
lifecycle verdict) and exposes the consumed-nonce set for boot recovery. It holds NO token / hmac
/ key field — structurally secret-free (PS-3), so ``verify_replay_leak0`` passes by construction.
It is a SEPARATE durable ledger from the intent ledger (actuation/G3); both are 0600, owner-only,
non-shared volumes, distinct from the checkpointer (FRAMEWORK §2.2, PS-9 #3).
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass
from typing import Optional

_LOCK = threading.Lock()

# lifecycle verdicts (no token/secret anywhere in the receipt)
_VERDICTS = ("ISSUED", "GRANTED", "DENIED", "EXPIRED", "REPLAY_REJECTED")


@dataclass
class OperatorApprovalReceipt:
    """Secret-free approval receipt — the command binding + lifecycle, NEVER the token/key."""
    decision_id: str
    command_digest: str
    nonce: str
    expiry: float
    verdict: str = "ISSUED"          # one of _VERDICTS
    kid: str = ""
    issued_ts: float = 0.0
    consumed_ts: Optional[float] = None
    # NOTE: no ``token`` / ``hmac`` / ``key`` field exists here by design (PS-3, structural).


class OperatorLedger:
    """Append-only JSONL of OperatorApprovalReceipts (0600, owner-only, non-shared volume).

    Drives durable single-use anti-replay: ``consumed_nonces()`` returns every nonce that reached
    a consuming verdict, and ``recover_on_boot()`` reloads that set so the gate re-seeds its
    ``_seen_nonces`` BEFORE the first verify is accepted (order fence, like SeqWatermark).
    """

    _CONSUMED = frozenset({"GRANTED", "EXPIRED", "REPLAY_REJECTED"})

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def record(self, *, decision_id: str, command_digest: str, nonce: str, expiry: float,
               verdict: str = "ISSUED", kid: str = "", issued_ts: float = 0.0,
               consumed_ts: Optional[float] = None) -> OperatorApprovalReceipt:
        """Append a secret-free receipt (fsync). Rejects an unknown verdict (fail-closed)."""
        if verdict not in _VERDICTS:
            raise ValueError(f"unknown operator receipt verdict: {verdict!r}")
        rcpt = OperatorApprovalReceipt(
            decision_id=decision_id, command_digest=command_digest, nonce=nonce, expiry=expiry,
            verdict=verdict, kid=kid, issued_ts=issued_ts, consumed_ts=consumed_ts,
        )
        line = json.dumps(asdict(rcpt), ensure_ascii=False)
        with _LOCK:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            # tighten perms owner-only (best-effort; no-op where unsupported, e.g. Windows).
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        return rcpt

    def scan(self) -> list[OperatorApprovalReceipt]:
        if not os.path.exists(self.path):
            return []
        out: list[OperatorApprovalReceipt] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    out.append(OperatorApprovalReceipt(**json.loads(ln)))
        return out

    def consumed_nonces(self) -> set[str]:
        """Every nonce that reached a consuming verdict (single-use is durable across reboot)."""
        return {r.nonce for r in self.scan() if r.verdict in self._CONSUMED and r.nonce}

    def recover_on_boot(self) -> set[str]:
        """Reload the consumed-nonce set (call BEFORE the gate accepts any verify). Returns the
        set so ``OperatorGate(ledger=...)`` can seed ``_seen_nonces`` at construction."""
        return self.consumed_nonces()
