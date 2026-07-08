"""Intent ledger (G3, PA-6) + SeqWatermark (PS-6).

record_intent writes the Intent to a durable JSONL BEFORE any side effect (guard
밖) and returns a channel update so the graph's ``ledger`` accumulator also holds
it. recover_on_boot scans prior runs and reverts leaked side effects. SeqWatermark
persists per-source HWM + window bitmap so replay windows don't re-open on crash.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field

from ..config import defaults as D
from ..core.state import Intent

_LOCK = threading.Lock()


class IntentLedger:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def record_intent(self, intent: Intent) -> dict:
        """Append to durable JSONL (fsync) BEFORE side effect; return {'ledger':[intent]}
        for the graph accumulator (operator.add)."""
        line = json.dumps(intent.model_dump(), ensure_ascii=False)
        with _LOCK:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return {"ledger": [intent]}

    def scan(self) -> list[Intent]:
        if not os.path.exists(self.path):
            return []
        out: list[Intent] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    out.append(Intent(**json.loads(ln)))
        return out

    def recover_on_boot(self, revert_fn=None) -> list[Intent]:
        """Scan prior run; for each recorded reversible intent with a revert_cmd,
        call revert_fn (safe-exec) to clean leaks (G3). revert is operator-go for
        live; here we return the set that WOULD be reverted."""
        intents = self.scan()
        pending = [i for i in intents if i.revert_cmd and not i.operator_gate]
        if revert_fn is not None:
            for it in pending:
                revert_fn(it)
        return pending


@dataclass
class SeqWatermark:
    """Per-source monotonic seq + sliding window W high-watermark (PS-6).

    accept: seq>HWM (advance) OR (HWM-W < seq <= HWM AND not seen). reject
    (replay): seq <= HWM-W (too old) OR already seen. Bitmap bounded by W (DoS cap).
    """
    window: int = D.SEQ_WINDOW
    hwm: dict[str, int] = field(default_factory=dict)
    seen: dict[str, set] = field(default_factory=dict)
    path: str = ""

    def accept(self, source_id: str, seq: int) -> bool:
        hwm = self.hwm.get(source_id, -1)
        seen = self.seen.setdefault(source_id, set())
        if seq > hwm:
            self.hwm[source_id] = seq
            seen.add(seq)
            # evict below window
            lo = seq - self.window
            self.seen[source_id] = {s for s in seen if s > lo}
            self._persist()
            return True
        if seq <= hwm - self.window:
            return False                       # too old -> replay
        if seq in seen:
            return False                       # already seen -> replay
        seen.add(seq)
        self._persist()
        return True

    def _persist(self) -> None:
        if not self.path:
            return
        # Persist HWM AND the compact seen-bitmap per source (PS-6). Persisting only
        # the HWM would re-open the replay window at the boundary: after a crash the
        # in-window seen set is lost, so seq==HWM (already consumed) would be accepted
        # again. The bitmap is bounded by the window W (DoS cap), so it stays compact.
        with _LOCK:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump({"hwm": self.hwm,
                           "seen": {k: sorted(v) for k, v in self.seen.items()}}, fh)
                fh.flush()
                os.fsync(fh.fileno())

    def recover_on_boot(self) -> None:
        """Reload per-source HWM + seen-bitmap BEFORE sense drain begins (PS-6). The
        bitmap reload is what keeps the replay window CLOSED across a crash."""
        if self.path and os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.hwm = {k: int(v) for k, v in data.get("hwm", {}).items()}
            self.seen = {k: set(int(s) for s in v) for k, v in data.get("seen", {}).items()}


def boot_recover(ledger: "IntentLedger", seqwm: "SeqWatermark", backend=None,
                 revert_fn=None, op_ledger=None) -> dict:
    """Ordered boot recovery (G3 + PS-6 + P4-Q3 + R4):
      1. reload seq HWM BEFORE any sense drain (replay window stays closed, PS-6),
      1b. reload the consumed-nonce set from the operator-ledger (P4-Q3) BEFORE the gate
          accepts any verify (durable single-use anti-replay across a crash),
      2. R4 reap: kill any labelled leftover process from a crashed prior run,
      3. revert pending recorded intents (leak cleanup; live revert is operator-go).
    Returns a summary dict {reaped, reverted, op_nonces}. Pure orchestration — no graph state.
    The gate itself re-seeds ``_seen_nonces`` from ``OperatorGate(ledger=op_ledger)``; this call
    just fences the reload before sense drain and surfaces the count.
    """
    seqwm.recover_on_boot()
    op_nonces: set[str] = set()
    if op_ledger is not None:
        try:
            op_nonces = op_ledger.recover_on_boot()
        except Exception:
            op_nonces = set()
    reaped: list[int] = []
    if backend is not None:
        try:
            reaped = backend.teardown()
        except Exception:
            reaped = []
    reverted = ledger.recover_on_boot(revert_fn=revert_fn)
    return {"reaped": reaped, "reverted": [i.rule for i in reverted],
            "op_nonces": len(op_nonces)}
