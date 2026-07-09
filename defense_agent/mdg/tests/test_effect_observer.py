"""test_effect_observer — Phase 4 (RECOVERY_DEMO_PLAN §Phase4, B5).

recovery 가 효과를 낸 뒤(TAKEN EFFECT) ``applied[rule].confirmed`` 를 뒤집기 위해
``effect_confirm``(PA-2)이 호출하는 read-only 효과 관측자(``make_effect_observer``). Docker
inspect / ss / telemetry 는 모두 FAKE 주입됨(라이브 daemon/netns 없음)이므로, 이 테스트들은
response-tool 메커니즘별 True/False 확인 로직 + fail-safe(dep 누락 / DRY / error ->
False, 절대 허위 확인 없음)를 검증한다. 불변식2.: 관측자는 read-only 로만 프로브함; 유일한 spawn 은
주입된 Backend 를 통함(기록형 fake 로 검증). 불변식1.: 입력이 주어지면 결정론적.

``python mdg/tests/test_effect_observer.py`` 로 단독 실행 가능.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.core.nodes.effect_confirm import effect_confirm  # noqa: E402
from mdg.core.worldstate import AppliedRule, WorldState  # noqa: E402
from mdg.safe_exec.backend import ExecResult  # noqa: E402
from mdg.safe_exec.observer import make_effect_observer  # noqa: E402


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #
class _FakeDocker:
    """Duck-typed docker 백엔드: inspect_paused 는 컨테이너별 스크립트 값을 반환한다."""
    def __init__(self, paused: dict):
        self._paused = paused

    def inspect_paused(self, container):
        return self._paused.get(container)   # bool 또는 None(판정 불가)


class _ScriptedBackend:
    """Fake safe-exec Backend: 모든 ExecRequest 를 기록하고 프로브별 스크립트 결과를 반환한다.

    관측자의 backdoor_drop 경로는 최대 두(TWO) 프로브를 발행한다 — PRIMARY ``iptables -S INPUT``
    (규칙 존재) 다음 SECONDARY ``ss``(ESTAB 부재) — 그래서 fake 는 argv 로 디스패치한다.
    불변식2. 검증 — 관측자가 사용하는 유일한(ONLY) exec 경로는 Backend.run."""
    def __init__(self, *, ipt: ExecResult = None, ss: ExecResult = None):
        self._ipt = ipt if ipt is not None else ExecResult(ok=True, code=0, stdout="")
        self._ss = ss if ss is not None else ExecResult(ok=True, code=0, stdout="")
        self.calls = []

    def run(self, req):
        self.calls.append(req)
        return self._ipt if "iptables" in " ".join(req.argv) else self._ss


_SS_WITH_5762 = (
    "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
    "ESTAB  0      0      10.45.0.9:5762       10.45.0.5:44321\n"
    "LISTEN 0      128    0.0.0.0:22           0.0.0.0:*\n"
)
_SS_NO_5762 = (
    "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
    "LISTEN 0      128    0.0.0.0:5762         0.0.0.0:*\n"      # LISTEN 은 살아남음; ESTAB 만 카운트
    "ESTAB  0      0      10.45.0.9:22         10.45.0.5:5001\n"
)
_NETNS = {"web_backend": ["nsenter", "--target", "111", "--net", "--"],
          "uav_ue": ["nsenter", "--target", "222", "--net", "--"]}
# 우리 봉쇄 DROP 이 설치된 iptables -S INPUT(PRIMARY 확인 신호) vs. 미설치.
_IPT_WITH_DROP = "-P INPUT ACCEPT\n-A INPUT -s 10.45.0.5/32 -j DROP\n"
_IPT_NO_DROP = "-P INPUT ACCEPT\n"


# --------------------------------------------------------------------------- #
# docker_pause (backdoor_pause) — inspect .State.Paused
# --------------------------------------------------------------------------- #
def test_pause_confirmed_when_container_paused():
    obs = make_effect_observer(docker=_FakeDocker({"web_backend": True}))
    assert obs("backdoor_pause") is True


def test_pause_unconfirmed_when_not_paused_or_inconclusive():
    assert make_effect_observer(docker=_FakeDocker({"web_backend": False}))("backdoor_pause") is False
    # 판정 불가 inspect(None)를 confirmed 로 읽어선 안 됨
    assert make_effect_observer(docker=_FakeDocker({}))("backdoor_pause") is False
    # docker dep 자체가 없음 -> unconfirmed(fail-safe)
    assert make_effect_observer(docker=None)("backdoor_pause") is False


# --------------------------------------------------------------------------- #
# nsenter_input_drop (backdoor_drop) — ss 가 대상 netns 에서 5762 ESTAB 없음을 보임
# --------------------------------------------------------------------------- #
def test_drop_confirmed_via_rule_installed_primary():
    # PRIMARY: INPUT DROP 규칙이 설치됨 -> ESTAB 대기 없이 즉시 confirmed.
    be = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, stdout=_IPT_WITH_DROP),
                          ss=ExecResult(ok=True, code=0, stdout=_SS_WITH_5762))  # ESTAB 여전히 존재
    obs = make_effect_observer(netns_prefix_map=_NETNS, backend=be)
    assert obs("backdoor_drop") is True                       # 규칙 존재만으로 confirm
    # primary 프로브에서 단락됨: 정확히 exec 한 번(iptables -S), uav_ue netns 내부
    assert len(be.calls) == 1
    req = be.calls[0]
    assert req.argv[:5] == _NETNS["uav_ue"] and "iptables" in req.argv and "-S" in req.argv


def test_drop_confirmed_via_estab_gone_secondary():
    # SECONDARY: 규칙은 관측 불가하나, 5762 의 공격자 ESTAB 가 사라짐 -> confirmed.
    be = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, stdout=_IPT_NO_DROP),
                          ss=ExecResult(ok=True, code=0, stdout=_SS_NO_5762))
    obs = make_effect_observer(netns_prefix_map=_NETNS, backend=be)
    assert obs("backdoor_drop") is True
    # 두 프로브 모두 실행됨; ss 폴백은 read_only + uav_ue netns 내부(불변식2.)
    assert len(be.calls) == 2
    ss_req = be.calls[1]
    assert ss_req.read_only is True and ss_req.argv[:5] == _NETNS["uav_ue"] and "ss" in ss_req.argv


def test_drop_unconfirmed_when_rule_absent_and_5762_estab_present():
    be = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, stdout=_IPT_NO_DROP),
                          ss=ExecResult(ok=True, code=0, stdout=_SS_WITH_5762))
    assert make_effect_observer(netns_prefix_map=_NETNS, backend=be)("backdoor_drop") is False


def test_drop_unconfirmed_on_dry_run_or_unresolved_netns():
    # 두 프로브 모두 DRY-RUN 결과(operator-go 유보)면 confirm 안 함
    be_dry = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, dry_run=True),
                              ss=ExecResult(ok=True, code=0, dry_run=True))
    assert make_effect_observer(netns_prefix_map=_NETNS, backend=be_dry)("backdoor_drop") is False
    # 미해석 netns(맵에 컨테이너 없음) -> inert, exec 시도 안 함
    be = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, stdout=_IPT_WITH_DROP))
    assert make_effect_observer(netns_prefix_map={}, backend=be)("backdoor_drop") is False
    assert be.calls == []


# --------------------------------------------------------------------------- #
# send_signed_mode (signed_*) — telemetry rel_alt 회복 & mode != LAND
# --------------------------------------------------------------------------- #
def test_signed_confirmed_when_alt_recovered_and_not_land():
    obs = make_effect_observer(telemetry=lambda: {"rel_alt": 30.4, "mode": "GUIDED"})
    assert obs("signed_guided") is True


def test_signed_unconfirmed_when_landing_or_off_target_or_no_telemetry():
    # 여전히 LAND 모드 -> 미회복
    assert make_effect_observer(
        telemetry=lambda: {"rel_alt": 30.0, "mode": "LAND"})("signed_guided") is False
    # 고도가 30m 대역보다 훨씬 아래
    assert make_effect_observer(
        telemetry=lambda: {"rel_alt": 3.0, "mode": "GUIDED"})("signed_guided") is False
    # telemetry 미배선(탭 스냅샷 없음) -> unconfirmed, 안전(fail-safe)
    assert make_effect_observer(telemetry=None)("signed_guided") is False


# --------------------------------------------------------------------------- #
# 미지 규칙 + effect_confirm 통합
# --------------------------------------------------------------------------- #
def test_unknown_rule_is_unconfirmed():
    assert make_effect_observer(docker=_FakeDocker({"x": True}))("no_such_rule") is False


def test_effect_confirm_flips_confirmed_and_records_note():
    world = WorldState().with_applied(AppliedRule(rule="backdoor_pause", confirmed=False))
    obs = make_effect_observer(docker=_FakeDocker({"web_backend": True}))
    out = effect_confirm({"worldstate": world}, observe=obs)
    applied = out["worldstate"].applied["backdoor_pause"]
    assert applied.confirmed is True
    assert "unconfirmed->confirmed" in applied.confirm_note


def test_effect_confirm_stays_unconfirmed_without_effect():
    world = WorldState().with_applied(AppliedRule(rule="backdoor_pause", confirmed=False))
    obs = make_effect_observer(docker=_FakeDocker({"web_backend": False}))
    out = effect_confirm({"worldstate": world}, observe=obs)
    applied = out["worldstate"].applied["backdoor_pause"]
    assert applied.confirmed is False and applied.confirm_note == ""


def test_effect_confirm_signed_confirms_on_next_tick_snapshot():
    """Item C 정합: signed enforce(gcs_c2 위임, Item B) 후 드론이 상승하므로,
    다음(NEXT) tick 의 air-tap 스냅샷이 rel_alt≈30 / mode GUIDED 를 읽고 effect_confirm 이 signed_guided
    를 confirmed 로 뒤집는다. enforce tick 에서 LAND 지속 스냅샷은 UNCONFIRMED 유지(허위 confirm 없음)."""
    # enforce-tick telemetry: 여전히 12m LAND -> unconfirmed
    world = WorldState().with_applied(AppliedRule(rule="signed_guided", confirmed=False))
    obs_land = make_effect_observer(telemetry=lambda: {"rel_alt": 12.0, "flight_mode": "LAND"})
    out0 = effect_confirm({"worldstate": world}, observe=obs_land)
    assert out0["worldstate"].applied["signed_guided"].confirmed is False
    # 다음-tick telemetry: 30m GUIDED 로 회복 -> confirmed
    obs_up = make_effect_observer(telemetry=lambda: {"rel_alt": 30.2, "flight_mode": "GUIDED"})
    out1 = effect_confirm(out0, observe=obs_up)
    applied = out1["worldstate"].applied["signed_guided"]
    assert applied.confirmed is True
    assert "unconfirmed->confirmed" in applied.confirm_note


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
