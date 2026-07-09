"""record.py (PA-7 · PS-3) — canonical node-I/O JSONL recorder.

Records each LangGraph node update (``graph.stream(inp, cfg, stream_mode='updates')``)
as one JSONL line. Four locked properties:

  1. stream_mode='updates' — the stream IS the execution (1 tick = 1 stream pass); each
     yielded update is ``{node: partial_state}``, recorded per node in execution order.
  2. Virtual-clock injection — replay determinism comes from a ``VirtualClock`` (core.clock)
     injected into the graph deps at build time; this module exposes ``ts_stream()`` /
     ``build_virtual_clock()`` so a recorded run's ts sequence drives that clock on replay.
     time.* is never called here.
  3. secret-free — every patch is projected through ``state.to_record`` (allow-field,
     default-deny) and ``driver.redact`` (residual-secret scrub) BEFORE serialization,
     and the whole serialized line is re-scrubbed to seal the json ``default=str`` bypass
     (PS-3 / verify_leak0). The 3 secret classes have no field in MDGState (structural).
  4. byte-identical — serialization is canonical (``sort_keys=True``, compact separators),
     so re-recording the same run yields byte-identical bytes (``canonical_line`` is pure).

Canonical line schema (one node update per line):
    {"seq": <int>, "node": <str>, "patch": {<projected+redacted state delta>}}

The recorder is the SINGLE redact contract: it reuses ``driver.redact`` / ``driver._scrub_str``
and ``state.to_record`` rather than forking them (DRY). It is core-side (recording pipeline),
so importing core here is allowed; the Verifier consumes the emitted JSONL and imports nothing.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Iterator, Optional

# Single redact/projection contract — reuse, do not fork (driver imports neither
# langgraph nor fastapi, so this is import-safe in any environment).
from ..core.clock import VirtualClock
from ..core.driver import _scrub_str, redact
from ..core.state import to_record

__all__ = [
    "canonical_line", "record_update", "record_stream",
    "ts_stream", "build_virtual_clock",
]


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys + compact separators so re-recording the same
    run is byte-identical regardless of dict insertion order. default=str is a
    last-resort stringifier for any object to_record missed; the returned line is
    re-scrubbed by the caller so default=str cannot leak a secret via __str__."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def canonical_line(seq: int, node: str, patch: Any) -> str:
    """Project + redact + canonically serialize ONE node update into a JSONL line.

    Pure function (no I/O, no clock) => byte-identical for identical inputs. patch is a
    node's returned partial-state dict; a non-dict patch degrades to an empty projection.
    """
    projected = to_record(patch) if isinstance(patch, dict) else {}
    safe = {"seq": int(seq), "node": str(node), "patch": redact(projected)}
    # Final scrub over the SERIALIZED line (seals json default=str bypass, PS-3/PP-2).
    # [REDACTED] injects no quotes/backslashes, so JSON validity is preserved.
    return _scrub_str(_canonical_json(safe))


def record_update(fh, seq: int, update: dict) -> int:
    """Write every (node, patch) pair in ONE streamed update to ``fh``. Returns the next
    seq. A streamed update is normally single-node; multi-node updates are recorded in
    sorted node order for byte-stability. Recording never raises through to the driver."""
    for node in sorted(update.keys()):
        try:
            fh.write(canonical_line(seq, node, update[node]) + "\n")
        except Exception:
            # recording must never crash the run (불변식2.: side effects already happened)
            pass
        seq += 1
    return seq


def record_stream(graph, inp: Any, cfg: dict, path: str, *, seq_start: int = 0) -> int:
    """Drive EXACTLY ONE graph execution via stream_mode='updates' and record each node
    update to ``path`` (append). Returns the next seq (carry across ticks for a monotonic
    index). The single stream pass is the execution — there is no separate invoke (that
    would double the act side effect, 불변식2.). Requires ``graph`` to expose ``.stream``.
    """
    seq = seq_start
    fh = None
    try:
        fh = open(path, "a", encoding="utf-8")
    except Exception:
        fh = None
    try:
        for update in graph.stream(inp, cfg, stream_mode="updates"):
            if isinstance(update, dict):
                if fh is not None:
                    seq = record_update(fh, seq, update)
                else:
                    seq += len(update)
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
    return seq


# --------------------------------------------------------------------------- #
# Virtual-clock injection (replay determinism, PA-7)
# --------------------------------------------------------------------------- #
def ts_stream(records: Iterable[dict]) -> list[float]:
    """Extract the monotonic ts sequence from recorded evidence (ordered as recorded).

    Evidence envelopes carry the authoritative ts (HMAC-canonical, PS-2); the sequence of
    those ts values drives a VirtualClock so a replayed run advances time exactly as the
    live run did (no time.* on replay). Ticks with no evidence contribute no ts.

    A ts of 0.0 (SensorEv.ts default, or a real epoch-relative zero) is a LEGITIMATE value
    and MUST be kept — a truthiness guard would silently drop it and shrink the clock stream.
    Only non-numeric/absent ts and bool (JSON true/false coerces to 1/0) are excluded.
    """
    out: list[float] = []
    for rec in records:
        patch = rec.get("patch") if isinstance(rec, dict) else None
        if not isinstance(patch, dict):
            continue
        for ev in patch.get("evidence", []) or []:
            if not isinstance(ev, dict):
                continue
            ts = ev.get("ts")
            if isinstance(ts, (int, float)) and not isinstance(ts, bool):
                out.append(float(ts))
    return out


def build_virtual_clock(records: Iterable[dict], start: float = 0.0) -> VirtualClock:
    """Build the replay VirtualClock from a recorded run's ts stream (PA-7). Inject the
    returned clock into graph deps (deps['clock']) to re-execute deterministically."""
    return VirtualClock(ts_stream(records), start=start)


def iter_jsonl(path: str) -> Iterator[dict]:
    """Yield parsed JSON objects from a JSONL file (skips blank/corrupt lines)."""
    with open(path, "r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                yield json.loads(ln)
            except Exception:
                continue
