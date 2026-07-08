"""live_autorun (P2) — the production autonomous live launcher.

Replaces the scratchpad throwaway script with a real module that OWNS the observer
lifecycle. The sequence is exactly:

    recon_boot  (out-of-graph: read-only role/IP resolve + seq/ledger boot recovery)
      -> build_collectors(start)  (the standard 6-set, netns-bridged from recon PIDs)
      -> build_graph              (deterministic StateGraph; LLM advisory, checkpointer)
      -> run_driver               (the out-of-graph tick loop; per-tick run.jsonl)

and a try/finally that ALWAYS reclaims the observers on the way out (audit P2: 종료 시
관측자 미회수). ``_shutdown`` stops every collector, joins them (bounded), then calls
``Backend.teardown()`` to reap any labelled crash-orphan subprocess (R4). Each step is
individually guarded so one failure cannot strand the rest -> shutdown leak-0 (불변식②).

Invariant discipline:
  - 불변식② (누수-0): the ONLY subprocess path is the injected ``Backend`` (safe-exec R1~R6).
    This module spawns nothing directly — even the boot ``docker inspect`` used to resolve
    netns PIDs is routed through ``Backend.run`` (``_SafeExecDocker``), so there is exactly
    one spawn site. On exit ``_shutdown`` guarantees collectors are stopped/joined and any
    labelled orphan is reaped.
  - operator-go (allow_live 기본 False): ``allow_live`` comes from ``MDG_ALLOW_LIVE`` and
    defaults False (운영 제약 유보). A non-allow_live Backend keeps every state-changing
    actuation DRY; ``docker inspect`` (not on the read-only fast-path) likewise stays DRY,
    so netns taps that need a resolved PID run inert until an operator flips the flag. The
    netns-agnostic collectors (NetworkMetric :9090 httpx / Mongo ``docker logs`` / Mission)
    still observe under allow_live=False.

Entry point: ``python -m mdg.live_autorun --out <dir> --run-id <id> [--max-iters N]``.
langgraph is imported LAZILY (inside ``build_graph`` and the saver factory) so this module —
and its unit tests — import without langgraph present.
"""
from __future__ import annotations

import argparse
import os
import queue as _queue
import secrets
import sys
import time
from typing import Any, Callable, Optional

from .collector import build_collectors, build_epc_collectors, build_source_domains
from .collector.ingest import Keyring, envelope_to_ev, verify_envelope
from .core.clock import Clock, RealClock
from .core.driver import run_driver
from .core.graph import build_graph
from .core.recon import recon_boot
from .ledger.intent_ledger import IntentLedger, SeqWatermark
from .safe_exec.backend import Backend, ExecRequest
from .safe_exec.nsenter_helper import build_netns_prefix_map

# bounded observation queue (DoS cap: collectors drop-on-Full, never grow — base.py push()).
_QUEUE_MAX = 20000
# env truthy vocabulary for MDG_ALLOW_LIVE (operator-go flip).
_TRUE = frozenset({"1", "true", "yes", "on"})


def parse_allow_live(env) -> bool:
    """operator-go gate: allow_live is True ONLY when MDG_ALLOW_LIVE is an explicit truthy
    token. Absent/blank/anything-else -> False (운영 제약 유보 default). Never inferred."""
    return str(env.get("MDG_ALLOW_LIVE", "")).strip().lower() in _TRUE


def _make_keyring(run_id: str) -> tuple[Keyring, str]:
    """Ephemeral per-run HMAC keyring. Collectors sign and ``verify`` verifies in the SAME
    process, so a fresh random key needs no persistence and never touches source or State
    (PS-3: keys live in the Keyring only). A hardcoded key would be a checked-in secret."""
    kid = f"live-{run_id}"
    return Keyring(keys={kid: secrets.token_bytes(32)}), kid


def _make_verify(keyring: Keyring, seqwm: SeqWatermark) -> Callable[[Any], tuple[bool, str, Any]]:
    """Build the ``verify(env) -> (ok, reason, SensorEv)`` closure ``sense`` calls at drain:
    HMAC+seq check (ingest.verify_envelope) then project to a SensorEv (tamper=not ok)."""
    def verify(env):
        ok, reason = verify_envelope(env, keyring, seqwm)
        return ok, reason, envelope_to_ev(env, ok)
    return verify


class _SafeExecDocker:
    """Duck-typed ``docker`` backend (``inspect_pid`` / ``inspect_networks``) routed through
    the safe-exec ``Backend`` so this launcher keeps ZERO direct subprocess sites (불변식②).

    ``docker inspect`` is a READ-ONLY docker-daemon metadata read (resolve.py stage-1: container
    existence + ``.State.Pid`` + cellular IP — NOT a netns entry, NOT a state change), so it is sent
    with ``read_only=True`` and runs under allow_live=False (recon resolves pids -> the netns
    collectors observe = read-only detection works without operator-go). This mirrors the ss/tcpdump
    collectors (also read-only). The stage-2 tun-scan (``ip -4 addr show`` via nsenter) stays
    operator-go (NOT whitelisted) so UE-pool role_verified — and therefore the DROP decision — still
    require the allow_live window. It spawns via the single ``Backend._spawn`` site (R1~R6 teardown).
    Parses ONLY ``.State.Pid`` / ``.NetworkSettings.Networks[*].IPAddress`` (PS-3: never ``.Config.Env``).
    """

    def __init__(self, backend: Backend):
        self.backend = backend

    def _inspect(self, container: str, fmt: str) -> Optional[str]:
        try:
            res = self.backend.run(ExecRequest(
                argv=["docker", "inspect", "-f", fmt, container], timeout_s=8.0, read_only=True))
        except Exception:
            return None
        if res is None or getattr(res, "dry_run", False) or not getattr(res, "ok", False):
            return None                                  # operator-go DRY / failure -> inert
        return (res.stdout or "").strip()

    def inspect_pid(self, container: str) -> Optional[int]:
        out = self._inspect(container, "{{.State.Pid}}")
        if out and out.lstrip("-").isdigit() and int(out) > 0:
            return int(out)
        return None

    def inspect_networks(self, container: str) -> dict[str, str]:
        fmt = "{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}"
        out = self._inspect(container, fmt)
        if not out:
            return {}
        return {t.split("=", 1)[0]: t.split("=", 1)[1] for t in out.split() if "=" in t}


def _default_saver():
    """LangGraph checkpointer for the driver's per-tick threads (imported lazily so this
    module loads without langgraph). InMemorySaver is the current name; MemorySaver is the
    older alias — fall back, and to None if langgraph is absent (build_graph would then be
    the failing site with its own clear ImportError)."""
    try:
        from langgraph.checkpoint.memory import InMemorySaver
        return InMemorySaver()
    except Exception:
        try:
            from langgraph.checkpoint.memory import MemorySaver
            return MemorySaver()
        except Exception:
            return None


def _shutdown(collectors, backend, join_timeout: float = 10.0) -> None:
    """Exception-safe observer reclamation (audit P2, 불변식② 종료 누수-0).

    Order: stop() EVERY collector first (signal the whole roster before waiting, so total
    wait is ~max(interval) not the sum), then join() each with a bounded timeout, then
    Backend.teardown() to reap any labelled crash-orphan subprocess (R4 — gated only on
    mode=='mock', so it runs even under allow_live=False where read-only observers really
    spawn). Every step is individually guarded: a raising/never-started collector cannot
    prevent the others from stopping or the backend from being torn down."""
    for c in collectors or []:
        try:
            c.stop()
        except Exception:
            pass
    for c in collectors or []:
        try:
            c.join(timeout=join_timeout)                 # join on a never-started thread raises -> guarded
        except Exception:
            pass
    if backend is not None:
        try:
            backend.teardown()
        except Exception:
            pass


def run(out_dir: str, run_id: str, *, allow_live: bool = False, docker=None,
        backend: Optional[Backend] = None, max_iters: Optional[int] = None,
        clock: Optional[Clock] = None, keyring: Optional[Keyring] = None,
        kid: Optional[str] = None, seqwm: Optional[SeqWatermark] = None,
        ledger=None, join_timeout: float = 10.0,
        collector_builder: Callable = build_collectors,
        epc_builder: Optional[Callable] = build_epc_collectors,
        graph_builder: Callable = build_graph,
        driver_fn: Callable = run_driver,
        saver_factory: Callable = _default_saver,
        source_domains_fn: Callable = build_source_domains) -> Any:
    """Boot -> collectors(start) -> graph -> driver, with a try/finally that ALWAYS reclaims
    the observers (P2). Returns the driver's final state. The ``*_builder``/``*_fn``/factory
    seams default to the real functions and exist so the lifecycle (incl. the shutdown path)
    is unit-testable without langgraph or live threads."""
    run_out = os.path.join(out_dir, run_id)
    os.makedirs(run_out, exist_ok=True)
    jsonl_path = os.path.join(run_out, "run.jsonl")

    clock = clock or RealClock()
    if backend is None:
        backend = Backend(allow_live=allow_live, mode="local")
    if keyring is None:
        keyring, kid = _make_keyring(run_id)
    if seqwm is None:
        seqwm = SeqWatermark(path=os.path.join(run_out, "seqwm.json"))
    if ledger is None:
        ledger = IntentLedger(os.path.join(run_out, "intents.jsonl"))

    # -- boot (out-of-graph): role/IP resolve (read-only) + seq/ledger recovery (PS-6/G3) -- #
    state0 = recon_boot(cfg=None, seqwm=seqwm, ledger=ledger, docker=docker, backend=backend)
    world = state0.get("worldstate")
    pidmap = dict(getattr(world, "pid", {}) or {})
    netns_prefix_map = build_netns_prefix_map(pidmap)     # container -> nsenter prefix (inert if unresolved)

    inbox = _queue.Queue(maxsize=_QUEUE_MAX)
    verify_fn = _make_verify(keyring, seqwm)
    collectors = collector_builder(inbox, keyring, kid, backend=backend, clock=clock,
                                   netns_prefix_map=netns_prefix_map)
    # P4: EPC log-tail (SmfSession) supplies the LIVE SmfSessionTable so the act-path stale-binding
    # guard's (b) cross-check re-attributes a drop-source IP to its IMSI at ENFORCEMENT time (a
    # reassigned UE-pool IP -> inert, no innocent-UE self-DoS). Read-only docker-logs tail. Fail-safe:
    # if the EPC builder is absent/raises, smf_table stays None -> guard degrades to best-effort (a).
    smf_table = None
    if epc_builder is not None:
        try:
            epc_collectors, smf_table = epc_builder(inbox, keyring, kid, backend=backend, clock=clock)
            collectors = list(collectors) + list(epc_collectors)
        except Exception:
            smf_table = None
    deps = {
        "inbox": inbox, "verify": verify_fn, "clock": clock, "backend": backend,
        "ledger": ledger, "observe": None, "gate": None,
        "llm_orient": None, "llm_decide": None,           # LLM advisory OFF -> deterministic core (불변식①)
        "smf_table": smf_table,                           # P4 stale-binding guard (b) live re-attribution
        "source_domains": source_domains_fn(collectors),  # {source_id -> domain} for liveness (P3-Q5)
        "checkpointer": saver_factory(),                  # per-tick threads; driver prunes t-1 (P3)
    }

    # collectors are thread OBJECTS here (not yet running); everything from graph build through
    # the driver runs under the finally so an exception anywhere still reclaims observers.
    try:
        graph = graph_builder(deps)
        for c in collectors:
            c.start()
        return driver_fn(graph, run_id, state0=state0, jsonl_path=jsonl_path,
                         max_iters=max_iters)
    finally:
        _shutdown(collectors, backend, join_timeout)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="mdg.live_autorun",
        description="MDG autonomous live launcher (recon -> collectors -> graph -> driver).")
    p.add_argument("--out", default="./live_out", help="output root dir (run dir = <out>/<run-id>)")
    p.add_argument("--run-id", default=None, help="run id (default: run-<UTC timestamp>)")
    p.add_argument("--max-iters", type=int, default=None, help="driver tick budget (default: config)")
    args = p.parse_args(argv)

    run_id = args.run_id or time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    allow_live = parse_allow_live(os.environ)             # operator-go: default False

    backend = Backend(allow_live=allow_live, mode="local")
    docker = _SafeExecDocker(backend)                     # boot netns resolution via the single spawn site
    run(args.out, run_id, allow_live=allow_live, docker=docker, backend=backend,
        max_iters=args.max_iters)
    return 0


if __name__ == "__main__":
    sys.exit(main())
