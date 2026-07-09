"""Intent ledger (G3, PA-6) + SeqWatermark (PS-6).

record_intent 은 어떤 side effect 보다 먼저(guard 밖) Intent 를 durable JSONL 에 기록하고,
그래프의 ``ledger`` accumulator 도 이를 보유하도록 channel 업데이트를 반환한다.
recover_on_boot 은 이전 실행을 스캔해 누출된 side effect 를 되돌린다. SeqWatermark 는
소스별 HWM + window bitmap 을 영속화해 크래시 시 replay window 가 재개방되지 않게 한다.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field

from ..config import defaults as D
from ..core.state import Intent

_LOCK = threading.Lock()


class IntentLedger:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def record_intent(self, intent: Intent) -> dict:
        """side effect 이전에 durable JSONL 에 추가(fsync); 그래프 accumulator(operator.add)
        용으로 {'ledger':[intent]} 를 반환한다."""
        line = json.dumps(intent.model_dump(), ensure_ascii=False)
        with _LOCK:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return {"ledger": [intent]}

    def scan(self) -> list[Intent]:
        if not os.path.exists(self.path):
            return []
        out: list[Intent] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    out.append(Intent(**json.loads(ln)))
        return out

    def recover_on_boot(self, revert_fn=None) -> list[Intent]:
        """이전 실행을 스캔; revert_cmd 를 가진 기록된 가역 intent 각각에 대해 revert_fn
        (safe-exec)을 호출해 누출을 정리한다(G3). live 에서 revert 는 operator-go 이며,
        여기서는 되돌려질 집합을 반환한다."""
        intents = self.scan()
        pending = [i for i in intents if i.revert_cmd and not i.operator_gate]
        if revert_fn is not None:
            for it in pending:
                revert_fn(it)
        return pending


@dataclass
class SeqWatermark:
    """소스별 단조 증가 seq + 슬라이딩 윈도우 W high-watermark (PS-6).

    accept: seq>HWM(전진) OR (HWM-W < seq <= HWM AND 미관측). reject(replay):
    seq <= HWM-W(너무 오래됨) OR 이미 관측. Bitmap 은 W 로 유계(DoS 상한).
    """
    window: int = D.SEQ_WINDOW
    hwm: dict[str, int] = field(default_factory=dict)
    seen: dict[str, set] = field(default_factory=dict)
    path: str = ""

    def accept(self, source_id: str, seq: int) -> bool:
        hwm = self.hwm.get(source_id, -1)
        seen = self.seen.setdefault(source_id, set())
        if seq > hwm:
            self.hwm[source_id] = seq
            seen.add(seq)
            # 윈도우 아래는 제거
            lo = seq - self.window
            self.seen[source_id] = {s for s in seen if s > lo}
            self._persist()
            return True
        if seq <= hwm - self.window:
            return False                       # 너무 오래됨 -> replay
        if seq in seen:
            return False                       # 이미 관측 -> replay
        seen.add(seq)
        self._persist()
        return True

    def _persist(self) -> None:
        if not self.path:
            return
        # 소스별로 HWM 과 compact seen-bitmap 을 함께 영속화(PS-6). HWM 만 영속화하면
        # 경계에서 replay window 가 재개방된다: 크래시 후 윈도우 내 seen 집합이 소실되어
        # seq==HWM(이미 소비됨)이 다시 accept 된다. bitmap 은 윈도우 W 로 유계(DoS 상한)라
        # compact 하게 유지된다.
        with _LOCK:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump({"hwm": self.hwm,
                           "seen": {k: sorted(v) for k, v in self.seen.items()}}, fh)
                fh.flush()
                os.fsync(fh.fileno())

    def recover_on_boot(self) -> None:
        """sense drain 시작 전에 소스별 HWM + seen-bitmap 을 재로드(PS-6). bitmap 재로드가
        크래시를 가로질러 replay window 를 닫힌 상태로 유지하는 핵심이다."""
        if self.path and os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.hwm = {k: int(v) for k, v in data.get("hwm", {}).items()}
            self.seen = {k: set(int(s) for s in v) for k, v in data.get("seen", {}).items()}


def boot_recover(ledger: "IntentLedger", seqwm: "SeqWatermark", backend=None,
                 revert_fn=None, op_ledger=None) -> dict:
    """순서화된 boot 복구 (G3 + PS-6 + P4-Q3 + R4):
      1. sense drain 이전에 seq HWM 재로드(replay window 닫힌 상태 유지, PS-6),
      1b. 게이트가 어떤 verify 든 accept 하기 전에 operator-ledger 에서 consumed-nonce 집합
          재로드(P4-Q3)(크래시를 가로지르는 durable single-use 재전송 방지),
      2. R4 reap: 크래시한 이전 실행에서 남은 labelled 프로세스를 종료,
      3. 대기 중 기록된 intent 되돌리기(누출 정리; live revert 는 operator-go).
    요약 dict {reaped, reverted, op_nonces} 를 반환한다. 순수 orchestration — graph state 없음.
    게이트 자체는 ``OperatorGate(ledger=op_ledger)`` 에서 ``_seen_nonces`` 를 재시드한다; 이 호출은
    단지 sense drain 전에 재로드를 fence 하고 그 개수를 표면화할 뿐이다.
    """
    seqwm.recover_on_boot()
    op_nonces: set[str] = set()
    if op_ledger is not None:
        try:
            op_nonces = op_ledger.recover_on_boot()
        except Exception:
            op_nonces = set()
    reaped: list[int] = []
    if backend is not None:
        try:
            reaped = backend.teardown()
        except Exception:
            reaped = []
    reverted = ledger.recover_on_boot(revert_fn=revert_fn)
    return {"reaped": reaped, "reverted": [i.rule for i in reverted],
            "op_nonces": len(op_nonces)}
