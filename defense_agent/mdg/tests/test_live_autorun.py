"""test_live_autorun — P2 production launcher lifecycle (shutdown leak-0, operator-go).

Pins the audit-P2 fix: the launcher OWNS the observer lifecycle and ALWAYS reclaims it.
No langgraph / live threads needed — the ``run`` seams are injected with fakes so the
try/finally shutdown path is exercised deterministically.

Covers:
  (a) parse_allow_live: operator-go default False; only explicit truthy tokens flip it.
  (b) _shutdown: stop() + join() every collector then Backend.teardown(), and one raising
      collector cannot strand the rest or the teardown (exception-safe).
  (c) run(): on a driver EXCEPTION the finally still stops/joins collectors and tears the
      backend down (종료 누수-0), and the exception propagates.
  (d) run(): happy path returns the driver result and still shuts everything down.

Run: ``python mdg/tests/test_live_autorun.py`` (no pytest / langgraph needed).
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg import live_autorun  # noqa: E402


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #
class _FakeCollector:
    def __init__(self, name="c", stop_raises=False):
        self.name = name
        self.stopped = False
        self.joined = False
        self.started = False
        self._stop_raises = stop_raises
        # attrs read by build_source_domains (absent domain -> omitted)
        self.source_id = name
        self.domain = None

    def start(self):
        self.started = True

    def stop(self):
        if self._stop_raises:
            raise RuntimeError("stop boom")
        self.stopped = True

    def join(self, timeout=None):
        self.joined = True


class _FakeBackend:
    def __init__(self):
        self.torn_down = False

    def teardown(self):
        self.torn_down = True
        return []


class _FakeSeqWm:
    def recover_on_boot(self):
        pass


class _FakeLedger:
    def recover_on_boot(self, revert_fn=None):
        return []


# --------------------------------------------------------------------------- #
# (a) parse_allow_live
# --------------------------------------------------------------------------- #
def test_parse_allow_live_default_false():
    assert live_autorun.parse_allow_live({}) is False
    assert live_autorun.parse_allow_live({"MDG_ALLOW_LIVE": ""}) is False
    assert live_autorun.parse_allow_live({"MDG_ALLOW_LIVE": "0"}) is False
    assert live_autorun.parse_allow_live({"MDG_ALLOW_LIVE": "false"}) is False
    assert live_autorun.parse_allow_live({"MDG_ALLOW_LIVE": "nope"}) is False


def test_parse_allow_live_truthy():
    for v in ("1", "true", "TRUE", "Yes", "on"):
        assert live_autorun.parse_allow_live({"MDG_ALLOW_LIVE": v}) is True


# --------------------------------------------------------------------------- #
# (b) _shutdown
# --------------------------------------------------------------------------- #
def test_shutdown_stops_joins_and_teardown():
    cols = [_FakeCollector("a"), _FakeCollector("b")]
    be = _FakeBackend()
    live_autorun._shutdown(cols, be, join_timeout=0.1)
    assert all(c.stopped and c.joined for c in cols)
    assert be.torn_down is True


def test_shutdown_is_exception_safe():
    # first collector raises in stop(); the rest must still stop/join and backend still tears down.
    bad = _FakeCollector("bad", stop_raises=True)
    good = _FakeCollector("good")
    be = _FakeBackend()
    live_autorun._shutdown([bad, good], be, join_timeout=0.1)
    assert bad.stopped is False        # it raised
    assert bad.joined is True          # join still attempted
    assert good.stopped and good.joined
    assert be.torn_down is True


def test_shutdown_tolerates_none_backend():
    live_autorun._shutdown([_FakeCollector("a")], None, join_timeout=0.1)  # must not raise


# --------------------------------------------------------------------------- #
# (c)(d) run(): finally always reclaims observers
# --------------------------------------------------------------------------- #
def _run_kwargs(cols, be):
    return dict(
        allow_live=False, docker=None, backend=be,
        keyring=object(), kid="k", seqwm=_FakeSeqWm(), ledger=_FakeLedger(),
        clock=None, join_timeout=0.1,
        collector_builder=lambda *a, **k: cols,
        graph_builder=lambda deps: ("GRAPH", deps),
        saver_factory=lambda: None,
        source_domains_fn=lambda cs: {},
    )


def test_run_shuts_down_on_driver_exception():
    cols = [_FakeCollector("a"), _FakeCollector("b")]
    be = _FakeBackend()

    def _boom(*a, **k):
        raise RuntimeError("driver boom")

    with tempfile.TemporaryDirectory() as d:
        raised = False
        try:
            live_autorun.run(d, "runx", driver_fn=_boom, **_run_kwargs(cols, be))
        except RuntimeError:
            raised = True
        assert raised, "driver exception must propagate"
    # finally ran: every collector started then reclaimed, backend torn down (누수-0)
    assert all(c.started and c.stopped and c.joined for c in cols)
    assert be.torn_down is True


def test_run_happy_path_returns_and_shuts_down():
    cols = [_FakeCollector("a")]
    be = _FakeBackend()
    seen = {}

    def _driver(graph, run_id, state0=None, jsonl_path="", max_iters=None,
                forever=False, tick_interval_s=0.0):
        seen["graph"] = graph
        seen["run_id"] = run_id
        seen["jsonl"] = jsonl_path
        seen["forever"] = forever
        return {"final": True}

    with tempfile.TemporaryDirectory() as d:
        out = live_autorun.run(d, "runy", driver_fn=_driver, max_iters=3, **_run_kwargs(cols, be))
        assert out == {"final": True}
        assert seen["run_id"] == "runy"
        assert seen["jsonl"] == os.path.join(d, "runy", "run.jsonl")
        assert os.path.isdir(os.path.join(d, "runy"))
    assert cols[0].started and cols[0].stopped and cols[0].joined
    assert be.torn_down is True


# --------------------------------------------------------------------------- #
# standalone runner
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nall {len(fns)} live_autorun tests passed")
