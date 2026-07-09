"""verifier.py (PA-2 · grep0 · FRAMEWORK §2.3) — 그래프 외부의 독립 신뢰 루트.

Verifier 는 자체 로직을 가진 별도 프로세스다. 오직 replay JSONL
(run.jsonl)만 소비한다 — mdg.core.* 를 절대 import 하지 않고(decider 없음, verdict 채널 없음),
testbed 를 건드리지 않으며, 결정론적이다(JSONL 바이트의 순수 함수; time.* 없음,
무작위성 없음, 네트워크 없음). 이것이 verify_grep0 경계다: 코어는
Verifier 의 verdict 를 import 할 수 없고, Verifier 는 코어의 결정 로직을 import 할 수 없다 — 그래서
Viewer 는 agent ≠ truth 를 정직하게 보여줄 수 있다(H-K).

독립 truth 는 에이전트의 결정이 아니라 원(RAW) 기록 evidence + 관측된 worldstate 로부터
계산된다. 네 가지 신호(라이브 testbed 에 고정, §P / D-1 / B-4):

  1. cross-root 링크 헬스 = 독립된 두 PLANE 의 생존성, 논리곱(∧):
       - comm/drone 루트: 평문 MAVLink tap 상의 Link_Heartbeat (uav_ue lo:14550, D-1)
       - command 루트   : gcs_proxy chokepoint REACHABLE/PRESENT (14556 command-plane)
     진짜-생존은 둘 다 필요. 한쪽만 => cross-root INCONSISTENT.
     ANTI-SPOOF 는 비대칭이다(P5-Q3 lock): anti-MITM 속성은 COMM/drone
     루트에 근거한다 — 위조된 네트워크 downlink 는 드론 자신의 loopback lo:14550
     heartbeat 까지 조작할 수 없다. command 루트는 오직 거친(COARSE) presence 확인일 뿐이다: 음성/침묵
     검출기가 없어서(AirCommandTap idle=0 이 정상 baseline), command plane 을 위조하면서
     gcs_proxy 컨테이너를 present 로 유지하는 MITM 은 그 자체만으로는
     CROSS_ROOT_INCONSISTENT 를 발동시키지 않는다. gcs_proxy_alive=True 를 행위적 command 헬스로 읽지 마라.
  2. telemetry-침묵 검출 = tap 은 돌았으나 heartbeat 를 관측하지 못함, 연속
     SILENCE_TICKS 틱 동안 => TELEMETRY_SILENCE(링크/드론 상실).
  3. gcs_proxy presence = command-plane chokepoint REACHABLE/PRESENT(role_verified, 라이브
     14556 tap, 또는 양성 행위 anchor) — 거친 presence, spoof 검출기 아님.
  4. agent≠truth 발산 = 에이전트의 결정은 NOMINAL(Continue / Continue+Monitoring)
     인데 독립 truth 는 SILENCE 또는 cross-root INCONSISTENT 라고 말함 —
     Viewer 가 표면화하는 정직-노트로, 에이전트의 태세를 결코 ground truth 로 오인하지 않게 한다.

설계상 self-contained: mdg.replay.play 나 mdg.core 를 import 하지 않고
작은 JSONL/tick 리더를 재구현한다(여기서는 신뢰-루트 격리 > DRY). 정규(canonical) 레코드 스키마와
레거시 드라이버 {node: patch} 스키마를 모두 관용한다.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

# --- 고정된 verdict 임계값(verifier 소유 상수; P5-Q1 lock) ---
# 결정론적, 라이브 소스 없음. 이들은 방어 가능한 기본값이지 문서 출처 상수가 아니며,
# core config/thresholds.yaml 로 옮기지 않고 의도적으로 여기에 둔다: grep0
# Verifier 는 별도 신뢰 루트이고, 자신이 독립적으로 검사하는 코어와 상수 파일을 공유하면
# 안 된다(테스트 격리 > DRY). 정규 문서 값이 등장할 때에만 옮긴다.
SILENCE_TICKS = 2          # 연속 침묵 틱 -> TELEMETRY_SILENCE
_NOMINAL_DECISIONS = {"Continue", "Continue+Monitoring"}  # agent≠truth 발산 트리거 집합
_NODE_ORDER = ["sense", "correlate", "compute_trust", "compute_impact", "orient",
               "select_policy", "rank_recovery", "decide", "act", "effect_confirm", "escalate"]
_NODE_IX = {n: i for i, n in enumerate(_NODE_ORDER)}
_ACCUMULATORS = ("ledger", "decisions", "incidents")

# Truth verdict 라벨
LINK_HEALTHY = "LINK_HEALTHY"
TELEMETRY_SILENCE = "TELEMETRY_SILENCE"
CROSS_ROOT_INCONSISTENT = "CROSS_ROOT_INCONSISTENT"
DEGRADED = "DEGRADED"
UNKNOWN = "UNKNOWN"


# --------------------------------------------------------------------------- #
# JSONL -> 틱별 뷰(self-contained; core/replay import 없음)
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
    ledger: list = field(default_factory=list)      # act/escalate 는 ledger patch 를 방출; _ACCUMULATORS 가 이를 접음


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
# 독립 truth verdict
# --------------------------------------------------------------------------- #
@dataclass
class Truth:
    """틱별 독립 verdict 하나(secret 없음; 기록된 evidence 로부터만 도출)."""
    tick: int
    tick_i: Optional[int]
    verdict: str
    telemetry_alive: Optional[bool]        # None = 이 틱에 tap 이 돌지 않음(unknown)
    telemetry_silent: bool
    gcs_proxy_alive: Optional[bool]
    cross_root_consistent: Optional[bool]  # 루트가 unknown 일 때 None
    silence_streak: int
    agent_decision: Optional[str]
    agent_truth_divergence: bool
    reason: str = ""


def _telemetry(evidence: list) -> tuple[Optional[bool], bool]:
    """평문 MAVLink tap evidence 로부터 (telemetry_alive, telemetry_silent) 를 반환한다.

    alive  = Link_Heartbeat(변조 없음)가 관측됨(drone-side lo:14550 / 14560).
    silent = tap 은 돌았으나 heartbeat 를 내지 못함(tap 채널의 Packet_Loss).
    alive=None => 이 틱에 tap 이 무동작(telemetry evidence 전무) => unknown.

    P5-Q2 lock(telemetry-infra 일관성): 14560(네트워크 downlink)과 uav_ue lo:14550
    (drone loopback)은 기록된 evidence 에서 분리 불가능하다 — AirTelemetryTap 은 단일
    tcpdump 를 돌려 하나의 dict 를 방출한다(source_id="air_telemetry_tap", channel="plaintext_mavlink_tap").
    따라서 telemetry 루트는 여기서 metric 만으로 매칭되고, anti-spoof '∧' 은
    telemetry 내부가 아니라 verify_run() 에서 CROSS-PLANE 으로 실현된다(comm heartbeat ∧ command-plane gcs_proxy).
    FORWARD GUARD(아직 구현하지 마라): 미래의 collector 분리가 14560 대 lo:14550 에 대해 두 개의
    구별되는 source_id 를 방출할 때에만 이것을 조여 두 heartbeat 를 모두 요구하고
    루트 매칭을 metric 전용에서 source_id 범위로 전환해야 한다. 오늘은 그 분기를 행사할
    분리 가능한 evidence 가 존재하지 않으므로, 선제적 리팩터링은 미검증 경로를 늘릴 뿐이다.
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
    """Command-plane chokepoint REACHABLE/PRESENT(거친 presence, spoof 검출기 아님).

    role_verified 가 주 술어인 이유는 음성(NEGATIVE) verdict 를 공급할 수 있는 유일한 신호이기
    때문이다: 인프라 gcs_proxy 역할의 경우 recon 이 docker inspect .State.Pid 로부터 role_verified 를
    설정하므로, role_verified['gcs_proxy']==False 는 문자 그대로 컨테이너 Pid 가 사라졌음 =
    chokepoint down 을 뜻한다. 계층화(P5-Q3 lock):
      1. role_verified['gcs_proxy'] 가 True                  -> True (RESOLVED/PRESENT)
      2. 양성 전용(POSITIVE-only) 상향(raw packet / 행위 anchor 가 낡은 inspect 를 override):
           - 변조 없는 air_command_tap 또는 command-domain plaintext_mavlink_tap evidence
           - behaviorally_verified['gcs_proxy'] 가 True(라이브 command-plane anchor 관측됨)
         이들의 부재/False 는 절대 하향으로 읽히지 않는다: AirCommandTap idle=0 이 정상
         baseline 이고(침묵은 죽은 chokepoint 를 증언할 수 없다), 행위 anchor 는 operator-go tap
         아래에서 전부-False 로 부팅한다(UNKNOWN != OFF, MEMORY 오판 가드).
      3. role_verified['gcs_proxy'] 가 present-but-False 이고 양성 evidence 없음 -> False
      4. role_verified 에 gcs_proxy 부재                     -> None (unknown)

    ANTI-SPOOF 비대칭(문서화됨, 패치 안 함): command 루트에는 음성/침묵 검출기가 없기
    때문에, command plane 을 위조하면서 gcs_proxy 컨테이너를 present 로 유지하는 MITM 은
    alive=True 로 읽히고 CROSS_ROOT_INCONSISTENT 를 발동시키지 않는다. verifier 의
    진짜 anti-spoof 보장은 TELEMETRY 루트의 drone-side lo:14550 cross-tap 에 근거한다(D-1)
    — 모듈 docstring 참조. gcs_proxy_alive 는 presence 확인이지 command-plane 헬스가 아니다.
    """
    rv = world.get("role_verified")
    if isinstance(rv, dict) and rv.get("gcs_proxy"):
        return True
    # 양성 전용(POSITIVE-only) 상향(계층: raw evidence + 행위 anchor). 이들 중 어느 것도
    # present-but-False 인 role_verified 를 하향할 수 없다; 오직 role_verified 자신만 False 를 낸다.
    for ev in evidence:
        if isinstance(ev, dict) and ev.get("source_id") == "air_command_tap" and not ev.get("tamper"):
            return True
        if isinstance(ev, dict) and ev.get("channel") == "plaintext_mavlink_tap" \
                and ev.get("domain") == "command" and not ev.get("tamper"):
            return True
    bv = world.get("behaviorally_verified")          # .get 가드: 키 없는 레거시 JSONL
    if isinstance(bv, dict) and bv.get("gcs_proxy"):  # role_verified/None 경로로 강등
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
    """run.jsonl 을 결정론적으로 독립 Truth verdict 리스트로 접는다.

    파일 바이트의 순수 함수(grep0: core import 없음, testbed 없음, 시계 없음)."""
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
        # alive 가 None(unknown)이면 streak 를 그대로 둔다(침묵으로 가산하지 않음)

        # cross-root 일관성(∧): 두 루트 모두 known 이고 "up" 에 합의해야 함
        if alive is None or gcs is None:
            cross = None
        else:
            cross = ((alive is True) and (gcs is True)) or ((alive is False) and (gcs is False))

        # verdict 우선순위: silence(run) > cross-root inconsistent > healthy > degraded > unknown
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
    """실행 수준 독립 요약(결정론적)."""
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
    """독립 verdict 스트림을 truth.jsonl 에 영속화(구성상 secret 없음)."""
    with open(path, "w", encoding="utf-8") as fh:
        for v in verdicts:
            fh.write(json.dumps(asdict(v), ensure_ascii=False, sort_keys=True,
                                separators=(",", ":")) + "\n")


def _utf8_stdout() -> None:
    """최선 노력: 레거시 콘솔(예: cp949)의 CLI 출력에서 유니코드(∧/≠/주의)를 허용."""
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
