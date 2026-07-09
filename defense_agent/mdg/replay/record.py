"""record.py (PA-7 · PS-3) — canonical node-I/O JSONL 레코더.

각 LangGraph node 업데이트(``graph.stream(inp, cfg, stream_mode='updates')``)를
JSONL 한 줄로 기록한다. 잠긴 네 가지 속성:

  1. stream_mode='updates' — stream이 곧 실행이다(1 tick = 1 stream pass); 각
     yield된 업데이트는 ``{node: partial_state}``로, 실행 순서대로 node별 기록된다.
  2. Virtual-clock 주입 — 리플레이 결정론은 빌드 시 graph deps에 주입된
     ``VirtualClock``(core.clock)에서 온다; 이 모듈은 ``ts_stream()`` /
     ``build_virtual_clock()``을 노출해 기록된 run의 ts 시퀀스가 리플레이 시 그 clock을 구동한다.
     여기서 time.*은 절대 호출하지 않는다.
  3. secret-free — 모든 patch는 직렬화 전에 ``state.to_record``(허용-필드,
     default-deny)와 ``driver.redact``(잔여 비밀 스크럽)를 거쳐 투영되며,
     직렬화된 줄 전체를 다시 스크럽해 json ``default=str`` 우회를 봉인한다
     (PS-3 / verify_leak0). 3개 비밀 클래스는 MDGState에 필드가 없다(구조적).
  4. byte-identical — 직렬화가 canonical이므로(``sort_keys=True``, compact separators),
     같은 run을 재기록하면 byte-identical 바이트가 나온다(``canonical_line``은 순수 함수).

Canonical line 스키마(줄당 node 업데이트 하나):
    {"seq": <int>, "node": <str>, "patch": {<투영+편집된 state 델타>}}

레코더는 단일 redact 계약이다: ``driver.redact`` / ``driver._scrub_str``와
``state.to_record``를 fork하지 않고 재사용한다(DRY). core-side(기록 파이프라인)이므로
여기서 core를 import하는 것은 허용된다; Verifier는 방출된 JSONL을 소비하며 아무것도 import하지 않는다.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Iterator, Optional

# 단일 redact/투영 계약 — fork하지 말고 재사용(driver는 langgraph도 fastapi도
# import하지 않으므로 어떤 환경에서도 import-safe).
from ..core.clock import VirtualClock
from ..core.driver import _scrub_str, redact
from ..core.state import to_record

__all__ = [
    "canonical_line", "record_update", "record_stream",
    "ts_stream", "build_virtual_clock",
]


def _canonical_json(obj: Any) -> str:
    """결정론적 JSON: sorted keys + compact separators로 같은 run을 재기록하면
    dict 삽입 순서와 무관하게 byte-identical하다. default=str은 to_record가 놓친
    임의 객체에 대한 최후의 문자열화 수단이다; 반환된 줄은 호출자가 다시 스크럽하므로
    default=str이 __str__을 통해 비밀을 누출할 수 없다."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def canonical_line(seq: int, node: str, patch: Any) -> str:
    """node 업데이트 하나를 투영 + 편집 + canonical 직렬화하여 JSONL 한 줄로 만든다.

    순수 함수(I/O 없음, clock 없음) => 동일 입력에 byte-identical. patch는 node가
    반환한 partial-state dict다; dict가 아닌 patch는 빈 투영으로 강등된다.
    """
    projected = to_record(patch) if isinstance(patch, dict) else {}
    safe = {"seq": int(seq), "node": str(node), "patch": redact(projected)}
    # 직렬화된 줄에 대한 최종 스크럽(json default=str 우회 봉인, PS-3/PP-2).
    # [REDACTED]는 따옴표/백슬래시를 주입하지 않으므로 JSON 유효성이 보존된다.
    return _scrub_str(_canonical_json(safe))


def record_update(fh, seq: int, update: dict) -> int:
    """하나의 stream된 업데이트 안의 모든 (node, patch) 쌍을 ``fh``에 쓴다. 다음
    seq를 반환한다. stream된 업데이트는 보통 single-node다; multi-node 업데이트는
    byte 안정성을 위해 정렬된 node 순서로 기록된다. 기록은 절대 driver로 예외를 전파하지 않는다."""
    for node in sorted(update.keys()):
        try:
            fh.write(canonical_line(seq, node, update[node]) + "\n")
        except Exception:
            # 기록은 절대 run을 죽이면 안 된다(불변식2.: side effect는 이미 발생함)
            pass
        seq += 1
    return seq


def record_stream(graph, inp: Any, cfg: dict, path: str, *, seq_start: int = 0) -> int:
    """stream_mode='updates'로 정확히 하나의 graph 실행을 구동하고 각 node
    업데이트를 ``path``에 기록한다(append). 다음 seq를 반환한다(monotonic 인덱스를
    위해 tick 간 이월). 단일 stream pass가 곧 실행이다 — 별도 invoke는 없다(그것은
    act side effect를 두 번 일으킴, 불변식2.). ``graph``가 ``.stream``을 노출해야 한다.
    """
    seq = seq_start
    fh = None
    try:
        fh = open(path, "a", encoding="utf-8")
    except Exception:
        fh = None
    try:
        for update in graph.stream(inp, cfg, stream_mode="updates"):
            if isinstance(update, dict):
                if fh is not None:
                    seq = record_update(fh, seq, update)
                else:
                    seq += len(update)
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
    return seq


# --------------------------------------------------------------------------- #
# Virtual-clock 주입 (리플레이 결정론, PA-7)
# --------------------------------------------------------------------------- #
def ts_stream(records: Iterable[dict]) -> list[float]:
    """기록된 evidence에서 monotonic ts 시퀀스를 추출한다(기록된 순서 그대로).

    Evidence 봉투는 권위 있는 ts를 담는다(HMAC-canonical, PS-2); 그 ts 값들의 시퀀스가
    VirtualClock을 구동해 리플레이된 run이 live run과 정확히 동일하게 시간을 진행한다
    (리플레이 시 time.* 없음). evidence가 없는 tick은 ts를 기여하지 않는다.

    ts 0.0(SensorEv.ts 기본값, 또는 실제 epoch 상대 0)은 정당한 값이며
    반드시 유지해야 한다 — truthiness 가드는 이를 조용히 떨어뜨려 clock 스트림을 줄인다.
    비수치/부재 ts와 bool(JSON true/false는 1/0으로 강제 변환됨)만 제외한다.
    """
    out: list[float] = []
    for rec in records:
        patch = rec.get("patch") if isinstance(rec, dict) else None
        if not isinstance(patch, dict):
            continue
        for ev in patch.get("evidence", []) or []:
            if not isinstance(ev, dict):
                continue
            ts = ev.get("ts")
            if isinstance(ts, (int, float)) and not isinstance(ts, bool):
                out.append(float(ts))
    return out


def build_virtual_clock(records: Iterable[dict], start: float = 0.0) -> VirtualClock:
    """기록된 run의 ts 스트림으로 리플레이 VirtualClock을 만든다(PA-7). 결정론적으로
    재실행하려면 반환된 clock을 graph deps(deps['clock'])에 주입하라."""
    return VirtualClock(ts_stream(records), start=start)


def iter_jsonl(path: str) -> Iterator[dict]:
    """JSONL 파일에서 파싱된 JSON 객체를 yield한다(빈/손상 라인은 건너뜀)."""
    with open(path, "r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                yield json.loads(ln)
            except Exception:
                continue
