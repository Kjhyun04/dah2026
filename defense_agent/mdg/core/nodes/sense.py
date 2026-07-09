"""sense (PA-1/PA-7/PS-2) — 동기 진입 노드. Collector 큐를 논블로킹으로
드레인하고, 드레인 시점에 HMAC/seq 를 검증하며, WorldState 를 병합하고, tick_i 를 증가시킨다.

빈 큐 -> fail-open (G4). 위조 envelope -> fail-closed 폐기 + tamper
Incident(trust/impact/auto-quarantine 에 병합되지 않음). 여기서 async 없음, time.* 없음.

Liveness (P3-Q5): 드레인된 ``sensor_loss`` evidence(Watchdog 메트릭, PS-2-verified)는
그 ``value``(죽은 collector source_id)를 주입된 ``source_domains``
맵으로 도메인에 매핑하고 ``worldstate.dead_domains`` 에 기록한다 —
compute_trust 의 present-set 제외 소스이다. 매핑은 비대칭이다(SigningObs 선례, PS-7): 도메인은
그 도메인에 대한 라이브(non-sensor_loss) verified evidence 가 이 tick 에 도착할 때만
dead 에서 해제된다(collector 가 방출했다는 증거); 침묵은 절대 해제하지 않는다. ``source_domains=None``
(기본값 / 테스트 스캐폴드) -> liveness 부기 없음, 동작 불변.
"""
from __future__ import annotations

from ..state import Incident, MDGState, SensorEv
from ..worldstate import SigningObs, WorldState

# uav_proxy §9-B signing drop-line evidence(SignLogCollector). 그 관측이 여기서
# world.signing 의 유일한 권위 있는 승격자이다(P2-Q2/P3-Q2). 무관한 'Signing_Drop' 이름 신호가
# 래치를 스푸핑하지 못하도록 메트릭과 collector 채널 둘 다로 매칭한다.
_SIGNING_METRIC = "Signing_Drop"
_SIGNING_CHANNEL = "uav_proxy_signlog"


def _drain(inbox) -> list:
    """queue.Queue 유사 객체의 논블로킹 드레인(Empty 까지 get_nowait)."""
    out = []
    if inbox is None:
        return out
    try:
        import queue as _q
        empty_exc = _q.Empty
    except Exception:                       # pragma: no cover
        empty_exc = Exception
    while True:
        try:
            out.append(inbox.get_nowait())
        except empty_exc:
            break
        except Exception:
            break
    return out


def sense(state: MDGState, inbox=None, verify=None, clock=None,
          source_domains=None) -> dict:
    """inbox: (SensorEnvelope) 큐. verify(env)->(ok,reason,SensorEv). 그래프
    빌드가 주입; 기본값은 state 만으로 노드를 호출 가능하게 한다(fail-open).
    source_domains: watchdog ``sensor_loss`` 를 도메인에 귀속시키는 데 쓰는
    {source_id -> domain}(collector 로스터에서). None -> liveness 부기 비활성."""
    tick_i = int(state.get("tick_i", 0)) + 1

    envelopes = _drain(inbox)
    evidence: list[SensorEv] = []
    tamper: list[Incident] = []
    ts = clock.now() if clock is not None else 0.0

    for env in envelopes:
        if verify is not None:
            ok, reason, ev = verify(env)
        else:
            ok, reason, ev = True, "no-verify", env  # 스캐폴드 경로
        if ok and isinstance(ev, SensorEv) and not ev.tamper:
            evidence.append(ev)
        else:
            tamper.append(Incident(
                id=f"tamper-{tick_i}-{len(tamper)}", kind="tamper",
                score=0.0, ts=ts, members=[getattr(env, "source_id", "?")],
            ))

    # worldstate 병합(단일 권위 객체 교체)
    world: WorldState = state.get("worldstate") or WorldState(
        config_version=state.get("config_version", ""))

    # signing 태세 단조 래치(P2-Q2/P3-Q2): verified uav_proxy signing drop-line
    # 관측(SignLogCollector)이 유일한 승격자 — UNKNOWN -> CONFIRMED_ON, 한 번, 그리고
    # 절대 되돌아오지 않음. 관측이 필수(fail-safe 비대칭): 이 tick 에 drop-line 이 없으면
    # signing 은 그대로, 침묵은 절대 승격하지 않고, 배너만으로는 절대 승격하지 않는다(drop
    # evidence 만 승격). 이미 CONFIRMED 인 태세는 그대로 둔다(멱등 래치).
    # PS-2-verified evidence 만 이 리스트에 도달하므로 위조 래치는 구조적으로 배제된다.
    if world.signing is SigningObs.UNKNOWN:
        for ev in evidence:
            if (getattr(ev, "metric", "") == _SIGNING_METRIC
                    and getattr(ev, "channel", "") == _SIGNING_CHANNEL):
                world.signing = SigningObs.CONFIRMED_ON
                break

    # liveness present-set 부기(P3-Q5): watchdog sensor_loss -> dead domain 매핑,
    # 그 도메인에 대한 라이브 방출에서만 도메인 해제(비대칭; 침묵은 절대 해제 안 함).
    if source_domains is not None:
        dead = set(world.dead_domains)
        for ev in evidence:
            metric = getattr(ev, "metric", "")
            if metric == "sensor_loss":
                dom = source_domains.get(str(getattr(ev, "value", "")))
                if dom is not None:
                    dead.add(dom)                     # loss 시 추가만
            else:
                dom = getattr(ev, "domain", None)
                if dom is not None:
                    dead.discard(dom)                 # 라이브 방출 = 복구됨
        world.dead_domains = sorted(dead)

    out: dict = {"tick_i": tick_i, "evidence": evidence, "worldstate": world}
    if tamper:
        out["incidents"] = tamper                 # operator.add 누산기
    return out
