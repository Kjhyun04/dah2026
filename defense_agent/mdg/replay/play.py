"""play.py (H-J) — 오프라인 리플레이: run.jsonl 로부터 tick 타임라인을 재구성한다.

이식성 축(V3 §8): 테스트베드가 전혀 없는 리뷰어가 run.jsonl 만으로 Viewer/Verifier를
구동한다. 이 모듈은 아무것도 재실행하지 않는다(graph 없음, 테스트베드 없음,
subprocess 없음) — 기록된 node 업데이트를 tick별 타임라인으로 정규화하는 순수 stdlib 리더다.
두 가지 on-disk 스키마를 허용한다:

  - canonical (record.py):  {"seq": n, "node": "sense", "patch": {...}}
  - legacy (core.driver):   {"sense": {...}, ...}   (하나 이상의 node->patch 키)

tick 경계 = sense node 업데이트(sense가 graph 진입점, PA-1: 1 tick은 sense에서
시작). 한 tick 내 patch들은 병합되어(채널별 last-writer-wins; accumulator는 연결)
Viewer/Verifier가 소비하는 read-only TickView가 된다.

선택적으로 리플레이 VirtualClock(record.build_virtual_clock)을 만들고, 독립형
Verifier가 있으면 truth.jsonl을 방출한다 — 다만 재실행은 범위 밖으로 유지된다.
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
    """run.jsonl을 canonical record {"seq","node","patch"} 리스트로 읽는다.

    legacy driver 라인({node: patch})은 node별 canonical record 하나로 확장되며,
    on-disk 순서를 보존한다(seq는 없을 때 합성). 빈/손상 라인은 건너뛴다.
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
                # legacy {node: patch[, node2: patch2]} — 안정적 순서로 확장
                for node in sorted(obj.keys(), key=lambda n: _ORDER_IX.get(n, 99)):
                    patch = obj[node]
                    out.append({"seq": seq, "node": str(node),
                                "patch": patch if isinstance(patch, dict) else {}})
                    seq += 1
    return out


@dataclass
class TickView:
    """한 tick의 병합된 read-only 뷰(모든 node patch를 함께 접음)."""
    index: int
    nodes: list[str] = field(default_factory=list)          # 이 tick에 실행된 node들
    tick_i: Optional[int] = None
    config_version: str = ""
    worldstate: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    impact: dict = field(default_factory=dict)
    trust: dict = field(default_factory=dict)
    decisions: list = field(default_factory=list)           # 이 tick에 누적됨
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
            view.evidence = v                       # sense가 스냅샷을 대체
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
    """canonical record를 tick별 TickView로 묶는다. 각 sense node 업데이트마다
    새 tick이 열린다(PA-1 진입). 첫 sense 이전 record(드묾/없음)는 tick 0을 이룬다."""
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
# 리플레이 VirtualClock (driver가 재실행 시 주입할 수 있도록 재export)
# --------------------------------------------------------------------------- #
def build_virtual_clock(records: list[dict], start: float = 0.0):
    from .record import build_virtual_clock as _bvc  # 로컬 import (play를 stdlib-first로 유지)
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
            # 독립형 Verifier (stdlib, core를 import하지 않음)가 독립적 truth를 계산
            from mdg.verifier import verifier as V
            verdicts = V.verify_run(path)
            V.write_truth(verdicts, truth_out)
            print(f"truth: wrote {len(verdicts)} verdict(s) -> {truth_out}")
        except Exception as exc:  # pragma: no cover
            print(f"truth: skipped ({exc})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
