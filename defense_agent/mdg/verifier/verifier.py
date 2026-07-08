"""verifier.py (PA-2 · grep0 · FRAMEWORK §2.3) — the out-of-graph, independent trust root.

The Verifier is a SEPARATE PROCESS with its own logic. It consumes ONLY the replay JSONL
(``run.jsonl``) — it never imports ``mdg.core.*`` (no decider, no verdict channel), never
touches the testbed, and is DETERMINISTIC (pure function of the JSONL bytes; no time.*, no
randomness, no network). This is the ``verify_grep0`` boundary: the core cannot import the
Verifier's verdict, and the Verifier cannot import the core's decision logic — so the
Viewer can honestly show *agent ≠ truth* (H-K).

Independent truth is computed from the RAW recorded evidence + observed worldstate, NOT
from the agent's decisions. Four signals (locked to the live testbed, §P / D-1 / B-4):

  1. cross-root link health = liveness on TWO independent PLANES, conjoined (∧):
       - comm/drone root: ``Link_Heartbeat`` on the plaintext MAVLink tap (uav_ue lo:14550, D-1)
       - command root   : gcs_proxy chokepoint REACHABLE/PRESENT (14556 command-plane)
     Truly-alive requires BOTH. One-sided => cross-root INCONSISTENT.
     ANTI-SPOOF is ASYMMETRIC (P5-Q3 lock): the anti-MITM property rests on the COMM/drone
     root — a forged network downlink cannot also fabricate the drone's own loopback lo:14550
     heartbeat. The command root is only a COARSE presence confirm: it has NO negative/silence
     detector (AirCommandTap idle=0 is the healthy baseline), so a MITM that keeps the
     gcs_proxy container present while forging the command plane will NOT by itself trip
     CROSS_ROOT_INCONSISTENT. Do not read gcs_proxy_alive=True as behavioural command health.
  2. telemetry-silence detection = the tap ran but observed NO heartbeat, for a run of
     ``SILENCE_TICKS`` consecutive ticks => TELEMETRY_SILENCE (link/drone lost).
  3. gcs_proxy presence = command-plane chokepoint REACHABLE/PRESENT (role_verified, a live
     14556 tap, or a positive behavioural anchor) — coarse presence, not a spoof detector.
  4. agent≠truth divergence = the agent's decision is NOMINAL (Continue / Continue+Monitoring)
     while independent truth says SILENCE or cross-root INCONSISTENT — the honest-note the
     Viewer surfaces so the agent's posture is never mistaken for ground truth.

Self-contained by design: it re-implements a tiny JSONL/tick reader rather than importing
``mdg.replay.play`` or ``mdg.core`` (trust-root isolation > DRY here). Tolerates both the
canonical record schema and the legacy driver ``{node: patch}`` schema.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

# --- FIXED verdict thresholds (verifier-OWNED constants; P5-Q1 lock) ---
# Deterministic, no live source. These are defensible defaults, NOT doc-sourced constants, and
# are deliberately kept HERE rather than relocated to core config/thresholds.yaml: the grep0
# Verifier is a separate trust root and must not share a constants file with the core it
# independently checks (test isolation > DRY). Move only if a canonical doc value ever appears.
SILENCE_TICKS = 2          # consecutive silent ticks -> TELEMETRY_SILENCE
_NOMINAL_DECISIONS = {"Continue", "Continue+Monitoring"}  # agent≠truth divergence trigger set
_NODE_ORDER = ["sense", "correlate", "compute_trust", "compute_impact", "orient",
               "select_policy", "rank_recovery", "decide", "act", "effect_confirm", "escalate"]
_NODE_IX = {n: i for i, n in enumerate(_NODE_ORDER)}
_ACCUMULATORS = ("ledger", "decisions", "incidents")

# Truth verdict labels
LINK_HEALTHY = "LINK_HEALTHY"
TELEMETRY_SILENCE = "TELEMETRY_SILENCE"
CROSS_ROOT_INCONSISTENT = "CROSS_ROOT_INCONSISTENT"
DEGRADED = "DEGRADED"
UNKNOWN = "UNKNOWN"


# --------------------------------------------------------------------------- #
# JSONL -> per-tick views (self-contained; no core/replay import)
# --------------------------------------------------------------------------- #
def _iter_records(path: str):
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
                patch = obj.get("patch")
                yield str(obj["node"]), (patch if isinstance(patch, dict) else {})
            else:
                for node in sorted(obj.keys(), key=lambda n: _NODE_IX.get(n, 99)):
                    patch = obj[node]
                    yield str(node), (patch if isinstance(patch, dict) else {})
            seq += 1


@dataclass
class _Tick:
    index: int
    nodes: list = field(default_factory=list)
    tick_i: Optional[int] = None
    worldstate: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    incidents: list = field(default_factory=list)
    decisions: list = field(default_factory=list)
    ledger: list = field(default_factory=list)      # act/escalate emit a ledger patch; _ACCUMULATORS folds it


def _reconstruct(path: str) -> list[_Tick]:
    ticks: list[_Tick] = []
    cur: Optional[_Tick] = None
    for node, patch in _iter_records(path):
        if node == "sense" or cur is None:
            cur = _Tick(index=len(ticks))
            ticks.append(cur)
        cur.nodes.append(node)
        for k, v in patch.items():
            if k == "evidence" and isinstance(v, list):
                cur.evidence = v
            elif k == "worldstate" and isinstance(v, dict):
                cur.worldstate = v
            elif k == "tick_i":
                cur.tick_i = v
            elif k in _ACCUMULATORS and isinstance(v, list):
                getattr(cur, k).extend(v)
    return ticks


# --------------------------------------------------------------------------- #
# Independent truth verdict
# --------------------------------------------------------------------------- #
@dataclass
class Truth:
    """One independent per-tick verdict (secret-free; derived only from recorded evidence)."""
    tick: int
    tick_i: Optional[int]
    verdict: str
    telemetry_alive: Optional[bool]        # None = tap did not run this tick (unknown)
    telemetry_silent: bool
    gcs_proxy_alive: Optional[bool]
    cross_root_consistent: Optional[bool]  # None when a root is unknown
    silence_streak: int
    agent_decision: Optional[str]
    agent_truth_divergence: bool
    reason: str = ""


def _telemetry(evidence: list) -> tuple[Optional[bool], bool]:
    """Return (telemetry_alive, telemetry_silent) from the plaintext MAVLink tap evidence.

    alive  = a Link_Heartbeat (untampered) was observed (drone-side lo:14550 / 14560).
    silent = the tap RAN but produced no heartbeat (Packet_Loss on the tap channel).
    alive=None => the tap was inert this tick (no telemetry evidence at all) => unknown.

    P5-Q2 lock (telemetry-infra consistency): 14560 (network downlink) and uav_ue lo:14550
    (drone loopback) are NOT separable in recorded evidence — AirTelemetryTap runs a single
    tcpdump and emits ONE dict (source_id="air_telemetry_tap", channel="plaintext_mavlink_tap").
    So the telemetry root is matched here by metric ALONE, and the anti-spoof '∧' is realized
    CROSS-PLANE in verify_run() (comm heartbeat ∧ command-plane gcs_proxy), not within telemetry.
    FORWARD GUARD (do NOT implement yet): only WHEN a future collector split emits two DISTINCT
    source_ids for 14560 vs lo:14550 should this tighten to require BOTH heartbeats AND switch
    the root match from metric-only to source_id-scoped. No separable evidence exists to exercise
    that branch today, so pre-emptive refactoring would add untested paths.
    """
    hb = False
    tap_ran = False
    for ev in evidence:
        if not isinstance(ev, dict) or ev.get("tamper"):
            continue
        metric = ev.get("metric")
        channel = ev.get("channel", "")
        if metric == "Link_Heartbeat":
            hb = True
            tap_ran = True
        elif metric == "Packet_Loss" and channel == "plaintext_mavlink_tap":
            tap_ran = True
    if not tap_ran:
        return None, False
    return (True, False) if hb else (False, True)


def _gcs_proxy_alive(world: dict, evidence: list) -> Optional[bool]:
    """Command-plane chokepoint REACHABLE/PRESENT (coarse presence, NOT a spoof detector).

    role_verified is the primary predicate because it is the only signal that can supply a
    NEGATIVE verdict: for the infra gcs_proxy role recon sets role_verified from docker inspect
    .State.Pid, so role_verified['gcs_proxy']==False literally means the container Pid is gone =
    chokepoint down. Layered (P5-Q3 lock):
      1. role_verified['gcs_proxy'] is True                  -> True (RESOLVED/PRESENT)
      2. POSITIVE-only upgrades (raw packet / behavioural anchor override a stale inspect):
           - untampered air_command_tap OR command-domain plaintext_mavlink_tap evidence
           - behaviorally_verified['gcs_proxy'] is True (live command-plane anchor observed)
         Their absence/False is NEVER read as a downgrade: AirCommandTap idle=0 is the healthy
         baseline (silence cannot witness a dead chokepoint), and behavioural anchors boot
         all-False under operator-go taps (UNKNOWN != OFF, MEMORY 오판 가드).
      3. role_verified['gcs_proxy'] present-but-False and no positive evidence -> False
      4. gcs_proxy absent from role_verified                 -> None (unknown)

    ANTI-SPOOF ASYMMETRY (documented, not patched): because the command root has no negative/
    silence detector, a MITM that keeps the gcs_proxy container present while forging the
    command plane reads alive=True and will NOT trip CROSS_ROOT_INCONSISTENT. The verifier's
    real anti-spoof guarantee rests on the TELEMETRY root's drone-side lo:14550 cross-tap (D-1)
    — see the module docstring. gcs_proxy_alive is a presence confirm, not command-plane health.
    """
    rv = world.get("role_verified")
    if isinstance(rv, dict) and rv.get("gcs_proxy"):
        return True
    # POSITIVE-only upgrades (tier: raw evidence + behavioural anchor). None of these may
    # downgrade a present-but-False role_verified; only role_verified itself yields False.
    for ev in evidence:
        if isinstance(ev, dict) and ev.get("source_id") == "air_command_tap" and not ev.get("tamper"):
            return True
        if isinstance(ev, dict) and ev.get("channel") == "plaintext_mavlink_tap" \
                and ev.get("domain") == "command" and not ev.get("tamper"):
            return True
    bv = world.get("behaviorally_verified")          # .get guard: legacy JSONL w/o the key
    if isinstance(bv, dict) and bv.get("gcs_proxy"):  # degrades to role_verified/None path
        return True
    if isinstance(rv, dict) and "gcs_proxy" in rv:
        return bool(rv["gcs_proxy"])
    return None


def _agent_decision(tick: _Tick) -> Optional[str]:
    if not tick.decisions:
        return None
    last = tick.decisions[-1]
    return last.get("decision") if isinstance(last, dict) else None


def verify_run(path: str) -> list[Truth]:
    """Deterministically fold ``run.jsonl`` into a list of independent Truth verdicts.

    Pure function of the file bytes (grep0: no core import, no testbed, no clock)."""
    ticks = _reconstruct(path)
    out: list[Truth] = []
    silence_streak = 0
    for t in ticks:
        alive, silent = _telemetry(t.evidence)
        gcs = _gcs_proxy_alive(t.worldstate, t.evidence)

        if silent or alive is False:
            silence_streak += 1
        elif alive is True:
            silence_streak = 0
        # alive is None (unknown) leaves the streak unchanged (do not credit silence)

        # cross-root consistency (∧): both roots must be known AND agree on "up"
        if alive is None or gcs is None:
            cross = None
        else:
            cross = ((alive is True) and (gcs is True)) or ((alive is False) and (gcs is False))

        # verdict precedence: silence(run) > cross-root inconsistent > healthy > degraded > unknown
        if silence_streak >= SILENCE_TICKS:
            verdict, reason = TELEMETRY_SILENCE, f"no heartbeat for {silence_streak} consecutive tick(s)"
        elif cross is False:
            verdict, reason = CROSS_ROOT_INCONSISTENT, \
                f"telemetry_alive={alive} but gcs_proxy_alive={gcs} (roots disagree)"
        elif alive is True and gcs is True:
            verdict, reason = LINK_HEALTHY, "cross-root heartbeat: drone lo:14550 ∧ gcs_proxy 14556"
        elif alive is None and gcs is None:
            verdict, reason = UNKNOWN, "no telemetry/command root observed this tick"
        else:
            verdict, reason = DEGRADED, f"partial link (alive={alive}, gcs={gcs}, silent={silent})"

        decision = _agent_decision(t)
        divergence = bool(
            decision in _NOMINAL_DECISIONS
            and verdict in (TELEMETRY_SILENCE, CROSS_ROOT_INCONSISTENT)
        )
        if divergence:
            reason = f"AGENT≠TRUTH: agent='{decision}' while truth='{verdict}' — {reason}"

        out.append(Truth(
            tick=t.index, tick_i=t.tick_i, verdict=verdict,
            telemetry_alive=alive, telemetry_silent=silent, gcs_proxy_alive=gcs,
            cross_root_consistent=cross, silence_streak=silence_streak,
            agent_decision=decision, agent_truth_divergence=divergence, reason=reason,
        ))
    return out


def summarize(verdicts: list[Truth]) -> dict:
    """Run-level independent summary (deterministic)."""
    return {
        "ticks": len(verdicts),
        "healthy": sum(1 for v in verdicts if v.verdict == LINK_HEALTHY),
        "silence": sum(1 for v in verdicts if v.verdict == TELEMETRY_SILENCE),
        "cross_root_inconsistent": sum(1 for v in verdicts if v.verdict == CROSS_ROOT_INCONSISTENT),
        "degraded": sum(1 for v in verdicts if v.verdict == DEGRADED),
        "unknown": sum(1 for v in verdicts if v.verdict == UNKNOWN),
        "agent_truth_divergences": sum(1 for v in verdicts if v.agent_truth_divergence),
    }


def write_truth(verdicts: list[Truth], path: str) -> None:
    """Persist the independent verdict stream to truth.jsonl (secret-free by construction)."""
    with open(path, "w", encoding="utf-8") as fh:
        for v in verdicts:
            fh.write(json.dumps(asdict(v), ensure_ascii=False, sort_keys=True,
                                separators=(",", ":")) + "\n")


def _utf8_stdout() -> None:
    """Best-effort: allow Unicode (∧/≠/⚠) in CLI output on legacy consoles (e.g. cp949)."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass


def main(argv: Optional[list[str]] = None) -> int:
    _utf8_stdout()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m mdg.verifier.verifier <run.jsonl> [--out truth.jsonl]")
        return 2
    path = argv[0]
    if not os.path.exists(path):
        print(f"no such run.jsonl: {path}")
        return 2
    verdicts = verify_run(path)
    summary = summarize(verdicts)
    print("verifier (independent trust root) —", json.dumps(summary, ensure_ascii=False))
    for v in verdicts:
        flag = "  ⚠ AGENT≠TRUTH" if v.agent_truth_divergence else ""
        print(f"  tick {v.tick}: {v.verdict}{flag}  ({v.reason})")
    if "--out" in argv:
        i = argv.index("--out")
        out = argv[i + 1] if i + 1 < len(argv) else "truth.jsonl"
        write_truth(verdicts, out)
        print(f"wrote {len(verdicts)} verdict(s) -> {out}")
    return 1 if summary["agent_truth_divergences"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
