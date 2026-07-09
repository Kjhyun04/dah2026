"""test_live_autorun — P2 프로덕션 런처 생명주기(shutdown 누수-0, operator-go).

audit-P2 수정을 고정: 런처가 observer 생명주기를 소유하며 항상 회수한다.
langgraph / 라이브 스레드 불필요 — ``run``의 이음새(seam)에 fake를 주입하여
try/finally shutdown 경로를 결정론적으로 실행한다.

포함 범위:
  (a) parse_allow_live: operator-go 기본값 False; 명시적 truthy 토큰만 이를 뒤집음.
  (b) _shutdown: 모든 collector를 stop() + join() 후 Backend.teardown(), 그리고 하나의
      collector가 예외를 던져도 나머지나 teardown을 방치하지 않음(예외 안전).
  (c) run(): 드라이버 예외 발생 시 finally가 여전히 collector를 stop/join하고 backend를
      teardown(종료 누수-0), 그리고 예외는 전파됨.
  (d) run(): 정상 경로는 드라이버 결과를 반환하고 여전히 전부 shutdown함.

실행: ``python mdg/tests/test_live_autorun.py`` (pytest / langgraph 불필요).
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg import live_autorun  # noqa: E402


# --------------------------------------------------------------------------- #
# fake 객체
# --------------------------------------------------------------------------- #
class _FakeCollector:
    def __init__(self, name="c", stop_raises=False):
        self.name = name
        self.stopped = False
        self.joined = False
        self.started = False
        self._stop_raises = stop_raises
        # build_source_domains가 읽는 속성(부재 도메인 -> 생략)
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
# (a') parse_operator_auto (Phase 0 — 샌드박스 OPER 자동확인 게이트)
# --------------------------------------------------------------------------- #
def test_parse_operator_auto_default_false():
    # 안전 기본값: 부재/공백/0/false/쓰레기값 -> False (OPER는 escalate 유지).
    assert live_autorun.parse_operator_auto({}) is False
    assert live_autorun.parse_operator_auto({"MDG_OPERATOR_AUTO": ""}) is False
    assert live_autorun.parse_operator_auto({"MDG_OPERATOR_AUTO": "0"}) is False
    assert live_autorun.parse_operator_auto({"MDG_OPERATOR_AUTO": "false"}) is False
    assert live_autorun.parse_operator_auto({"MDG_OPERATOR_AUTO": "nope"}) is False


def test_parse_operator_auto_truthy():
    for v in ("1", "true", "TRUE", "Yes", "on"):
        assert live_autorun.parse_operator_auto({"MDG_OPERATOR_AUTO": v}) is True


def test_run_threads_operator_auto_into_deps():
    # Phase 0 배선: run()은 operator_auto를 graph builder의 deps로 전달해야 함.
    cols = [_FakeCollector("a")]
    be = _FakeBackend()
    seen = {}

    def _graph_builder(deps):
        seen["operator_auto"] = deps.get("operator_auto")
        return ("GRAPH", deps)

    kwargs = _run_kwargs(cols, be)
    kwargs["graph_builder"] = _graph_builder
    with tempfile.TemporaryDirectory() as d:
        live_autorun.run(d, "runz", operator_auto=True,
                         driver_fn=lambda *a, **k: {}, **kwargs)
    assert seen["operator_auto"] is True


def test_run_seeds_operator_auto_into_state_channel():
    # Phase 1 env->STATE 배선(죽은 route_after_decide 분기에 대한 회귀): operator_auto를 담은
    # deps만으로는 부족 — 조건부 엣지가 STATE 채널을 읽으므로 run()은 반드시
    # state0["operator_auto"]를 시드해야 함. 런처가 드라이버에 넘기는 state0을 포착해 단언.
    cols = [_FakeCollector("a")]
    be = _FakeBackend()
    seen = {}

    def _driver(graph, run_id, state0=None, **k):
        seen["operator_auto"] = (state0 or {}).get("operator_auto")
        return {}

    with tempfile.TemporaryDirectory() as d:
        live_autorun.run(d, "runw", operator_auto=True, driver_fn=_driver, **_run_kwargs(cols, be))
    # env->state 배선 라이브: route_after_decide가 이제 매 tick마다 operator_auto를 실제로 볼 수 있음.
    assert seen["operator_auto"] is True


def test_run_operator_auto_default_off_absent_from_state():
    # 안전 기본값(operator_auto=0): state 채널이 False -> 레거시 escalate 태세(회귀 0).
    cols = [_FakeCollector("a")]
    be = _FakeBackend()
    seen = {}

    def _driver(graph, run_id, state0=None, **k):
        seen["operator_auto"] = (state0 or {}).get("operator_auto")
        return {}

    with tempfile.TemporaryDirectory() as d:
        live_autorun.run(d, "runv", driver_fn=_driver, **_run_kwargs(cols, be))
    assert seen["operator_auto"] is False


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
    # 첫 collector가 stop()에서 예외; 나머지는 여전히 stop/join하고 backend도 teardown되어야 함.
    bad = _FakeCollector("bad", stop_raises=True)
    good = _FakeCollector("good")
    be = _FakeBackend()
    live_autorun._shutdown([bad, good], be, join_timeout=0.1)
    assert bad.stopped is False        # 예외를 던짐
    assert bad.joined is True          # join은 여전히 시도됨
    assert good.stopped and good.joined
    assert be.torn_down is True


def test_shutdown_tolerates_none_backend():
    live_autorun._shutdown([_FakeCollector("a")], None, join_timeout=0.1)  # 예외를 던지면 안 됨


# --------------------------------------------------------------------------- #
# (c)(d) run(): finally는 항상 observer를 회수
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
    # finally 실행됨: 모든 collector가 시작 후 회수, backend teardown됨(누수-0)
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
# 독립 실행 러너
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nall {len(fns)} live_autorun tests passed")
