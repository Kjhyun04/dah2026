"""test_effect_observer — Phase 4 (RECOVERY_DEMO_PLAN §Phase4, B5).

The read-only effect observer (``make_effect_observer``) that ``effect_confirm`` (PA-2) calls
to flip ``applied[rule].confirmed`` once a recovery has TAKEN EFFECT. Docker inspect / ss /
telemetry are all FAKE-injected (no live daemon/netns), so these tests assert the True/False
confirmation logic per response-tool mechanism plus the fail-safe (missing dep / DRY / error ->
False, never a spurious confirm). 불변식②: the observer probes read-only only; the only spawn is
through the injected Backend (asserted via a recording fake). 불변식①: deterministic given inputs.

Runnable standalone as ``python mdg/tests/test_effect_observer.py``.
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
    """Duck-typed docker backend: inspect_paused returns a scripted per-container value."""
    def __init__(self, paused: dict):
        self._paused = paused

    def inspect_paused(self, container):
        return self._paused.get(container)   # bool or None (inconclusive)


class _ScriptedBackend:
    """Fake safe-exec Backend: records every ExecRequest and returns a per-probe scripted result.

    The observer's backdoor_drop path issues up to TWO probes — PRIMARY ``iptables -S INPUT``
    (rule-existence) then SECONDARY ``ss`` (ESTAB-absence) — so the fake dispatches on argv.
    Asserts 불변식② — the ONLY exec path the observer uses is Backend.run."""
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
    "LISTEN 0      128    0.0.0.0:5762         0.0.0.0:*\n"      # LISTEN survives; only ESTAB counts
    "ESTAB  0      0      10.45.0.9:22         10.45.0.5:5001\n"
)
_NETNS = {"web_backend": ["nsenter", "--target", "111", "--net", "--"],
          "uav_ue": ["nsenter", "--target", "222", "--net", "--"]}
# iptables -S INPUT with our containment DROP installed (PRIMARY confirm signal), vs. without.
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
    # inconclusive inspect (None) must NOT be read as confirmed
    assert make_effect_observer(docker=_FakeDocker({}))("backdoor_pause") is False
    # no docker dep at all -> unconfirmed (fail-safe)
    assert make_effect_observer(docker=None)("backdoor_pause") is False


# --------------------------------------------------------------------------- #
# nsenter_input_drop (backdoor_drop) — ss shows no 5762 ESTAB in target netns
# --------------------------------------------------------------------------- #
def test_drop_confirmed_via_rule_installed_primary():
    # PRIMARY: the INPUT DROP rule is installed -> confirmed promptly, WITHOUT waiting on ESTAB.
    be = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, stdout=_IPT_WITH_DROP),
                          ss=ExecResult(ok=True, code=0, stdout=_SS_WITH_5762))  # ESTAB still present
    obs = make_effect_observer(netns_prefix_map=_NETNS, backend=be)
    assert obs("backdoor_drop") is True                       # rule-existence alone confirms
    # short-circuits on the primary probe: exactly one exec (iptables -S), inside the uav_ue netns
    assert len(be.calls) == 1
    req = be.calls[0]
    assert req.argv[:5] == _NETNS["uav_ue"] and "iptables" in req.argv and "-S" in req.argv


def test_drop_confirmed_via_estab_gone_secondary():
    # SECONDARY: rule not observable, but the attacker ESTAB on 5762 is gone -> confirmed.
    be = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, stdout=_IPT_NO_DROP),
                          ss=ExecResult(ok=True, code=0, stdout=_SS_NO_5762))
    obs = make_effect_observer(netns_prefix_map=_NETNS, backend=be)
    assert obs("backdoor_drop") is True
    # both probes ran; the ss fallback is read_only + inside the uav_ue netns (불변식②)
    assert len(be.calls) == 2
    ss_req = be.calls[1]
    assert ss_req.read_only is True and ss_req.argv[:5] == _NETNS["uav_ue"] and "ss" in ss_req.argv


def test_drop_unconfirmed_when_rule_absent_and_5762_estab_present():
    be = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, stdout=_IPT_NO_DROP),
                          ss=ExecResult(ok=True, code=0, stdout=_SS_WITH_5762))
    assert make_effect_observer(netns_prefix_map=_NETNS, backend=be)("backdoor_drop") is False


def test_drop_unconfirmed_on_dry_run_or_unresolved_netns():
    # DRY-RUN result (operator-go 유보) on BOTH probes must not confirm
    be_dry = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, dry_run=True),
                              ss=ExecResult(ok=True, code=0, dry_run=True))
    assert make_effect_observer(netns_prefix_map=_NETNS, backend=be_dry)("backdoor_drop") is False
    # unresolved netns (container absent from map) -> inert, no exec attempted
    be = _ScriptedBackend(ipt=ExecResult(ok=True, code=0, stdout=_IPT_WITH_DROP))
    assert make_effect_observer(netns_prefix_map={}, backend=be)("backdoor_drop") is False
    assert be.calls == []


# --------------------------------------------------------------------------- #
# send_signed_mode (signed_*) — telemetry rel_alt recovered & mode != LAND
# --------------------------------------------------------------------------- #
def test_signed_confirmed_when_alt_recovered_and_not_land():
    obs = make_effect_observer(telemetry=lambda: {"rel_alt": 30.4, "mode": "GUIDED"})
    assert obs("signed_guided") is True


def test_signed_unconfirmed_when_landing_or_off_target_or_no_telemetry():
    # still LAND mode -> not recovered
    assert make_effect_observer(
        telemetry=lambda: {"rel_alt": 30.0, "mode": "LAND"})("signed_guided") is False
    # altitude far below the 30m band
    assert make_effect_observer(
        telemetry=lambda: {"rel_alt": 3.0, "mode": "GUIDED"})("signed_guided") is False
    # telemetry not wired (no tap snapshot) -> unconfirmed, safe (fail-safe)
    assert make_effect_observer(telemetry=None)("signed_guided") is False


# --------------------------------------------------------------------------- #
# unknown rule + effect_confirm integration
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
    """Item C alignment: after the signed enforce (gcs_c2 delegation, Item B) the drone climbs, so the
    NEXT tick's air-tap snapshot reads rel_alt≈30 / mode GUIDED and effect_confirm flips signed_guided
    confirmed. A LAND-persisting snapshot on the enforce tick stays UNCONFIRMED (no false confirm)."""
    # enforce-tick telemetry: still LAND at 12m -> unconfirmed
    world = WorldState().with_applied(AppliedRule(rule="signed_guided", confirmed=False))
    obs_land = make_effect_observer(telemetry=lambda: {"rel_alt": 12.0, "flight_mode": "LAND"})
    out0 = effect_confirm({"worldstate": world}, observe=obs_land)
    assert out0["worldstate"].applied["signed_guided"].confirmed is False
    # next-tick telemetry: recovered to 30m GUIDED -> confirmed
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
