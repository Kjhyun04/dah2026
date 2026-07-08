"""play.py (H-J) — offline replay: reconstruct the tick timeline from run.jsonl.

The portability pillar (V3 §8): a reviewer with NO testbed drives the Viewer/Verifier
from ``run.jsonl`` alone. This module re-executes NOTHING (no graph, no testbed, no
subprocess) — it is a pure stdlib reader that normalizes recorded node updates into a
per-tick timeline. It tolerates two on-disk schemas:

  - canonical (record.py):  {"seq": n, "node": "sense", "patch": {...}}
  - legacy (core.driver):   {"sense": {...}, ...}   (one or more node->patch keys)

Tick boundary = a ``sense`` node update (sense is the graph entry, PA-1: 1 tick starts at
sense). Patches within a tick are merged (last-writer-wins per channel; accumulators are
concatenated) into a read-only TickView the Viewer/Verifier consume.

Optionally builds the replay VirtualClock (record.build_virtual_clock) and, if the
standalone Verifier is present, emits truth.jsonl — but re-execution stays out of scope.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

_ACCUMULATORS = ("ledger", "decisions", "incidents")
_ORDER = ["sense", "correlate", "compute_trust", "compute_impact", "orient",
          "select_policy", "rank_recovery", "decide", "act", "effect_confirm", "escalate"]
_ORDER_IX = {n: i for i, n in enumerate(_ORDER)}


# --------------------------------------------------------------------------- #
# Load + normalize
# --------------------------------------------------------------------------- #
def load_run(path: str) -> list[dict]:
    """Read run.jsonl into a list of canonical records {"seq","node","patch"}.

    Legacy driver lines ({node: patch}) are expanded to one canonical record per node,
    preserving on-disk order (seq synthesized when absent). Blank/corrupt lines skipped.
    """
    out: list[dict] = []
    seq = 0
    with open(path, "r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            if "node" in obj and "patch" in obj:
                rec = {"seq": int(obj.get("seq", seq)), "node": str(obj["node"]),
                       "patch": obj.get("patch") if isinstance(obj.get("patch"), dict) else {}}
                out.append(rec)
                seq = rec["seq"] + 1
            else:
                # legacy {node: patch[, node2: patch2]} — expand in a stable order
                for node in sorted(obj.keys(), key=lambda n: _ORDER_IX.get(n, 99)):
                    patch = obj[node]
                    out.append({"seq": seq, "node": str(node),
                                "patch": patch if isinstance(patch, dict) else {}})
                    seq += 1
    return out


@dataclass
class TickView:
    """Merged read-only view of one tick (all node patches folded together)."""
    index: int
    nodes: list[str] = field(default_factory=list)          # nodes that ran this tick
    tick_i: Optional[int] = None
    config_version: str = ""
    worldstate: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    impact: dict = field(default_factory=dict)
    trust: dict = field(default_factory=dict)
    decisions: list = field(default_factory=list)           # accumulated this tick
    incidents: list = field(default_factory=list)
    ledger: list = field(default_factory=list)
    goal_reached: bool = False

    def last_decision(self) -> Optional[dict]:
        return self.decisions[-1] if self.decisions else None


def _fold(view: TickView, node: str, patch: dict) -> None:
    view.nodes.append(node)
    for k, v in patch.items():
        if k in _ACCUMULATORS:
            cur = getattr(view, k)
            if isinstance(v, list):
                cur.extend(v)
        elif k == "evidence" and isinstance(v, list):
            view.evidence = v                       # sense replaces the snapshot
        elif k == "worldstate" and isinstance(v, dict):
            view.worldstate = v
        elif k == "impact" and isinstance(v, dict):
            view.impact = v
        elif k == "trust" and isinstance(v, dict):
            view.trust = v
        elif k == "config_version":
            view.config_version = str(v)
        elif k == "tick_i":
            view.tick_i = v
        elif k == "goal_reached":
            view.goal_reached = bool(v)


def reconstruct_ticks(records: list[dict]) -> list[TickView]:
    """Group canonical records into per-tick TickViews. A new tick opens on each ``sense``
    node update (PA-1 entry). Records before the first sense (rare/none) form tick 0."""
    ticks: list[TickView] = []
    cur: Optional[TickView] = None
    for rec in records:
        node = rec.get("node", "")
        patch = rec.get("patch") or {}
        if node == "sense" or cur is None:
            cur = TickView(index=len(ticks))
            ticks.append(cur)
        _fold(cur, node, patch)
    return ticks


def load_timeline(path: str) -> list[TickView]:
    return reconstruct_ticks(load_run(path))


# --------------------------------------------------------------------------- #
# Replay VirtualClock (re-export so the driver can inject it on re-execution)
# --------------------------------------------------------------------------- #
def build_virtual_clock(records: list[dict], start: float = 0.0):
    from .record import build_virtual_clock as _bvc  # local import (keeps play stdlib-first)
    return _bvc(records, start=start)


# --------------------------------------------------------------------------- #
# CLI: python -m mdg.replay.play run.jsonl [--truth truth.jsonl]
# --------------------------------------------------------------------------- #
def _summarize(ticks: list[TickView]) -> str:
    lines = [f"replay: {len(ticks)} tick(s)"]
    for t in ticks:
        dec = t.last_decision()
        d = dec.get("decision") if dec else "-"
        nev = len(t.evidence)
        band = (t.impact or {}).get("band", "-")
        lines.append(f"  tick {t.index} (tick_i={t.tick_i}): nodes={'>'.join(t.nodes)} "
                     f"evidence={nev} impact={band} decision={d} "
                     f"incidents={len(t.incidents)} ledger={len(t.ledger)}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m mdg.replay.play <run.jsonl> [--truth <out.jsonl>]")
        return 2
    path = argv[0]
    truth_out = None
    if "--truth" in argv:
        i = argv.index("--truth")
        truth_out = argv[i + 1] if i + 1 < len(argv) else "truth.jsonl"
    ticks = load_timeline(path)
    print(_summarize(ticks))
    if truth_out:
        try:
            # standalone Verifier (stdlib, does not import core) computes independent truth
            from mdg.verifier import verifier as V
            verdicts = V.verify_run(path)
            V.write_truth(verdicts, truth_out)
            print(f"truth: wrote {len(verdicts)} verdict(s) -> {truth_out}")
        except Exception as exc:  # pragma: no cover
            print(f"truth: skipped ({exc})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
