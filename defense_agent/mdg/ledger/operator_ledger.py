"""Operator 승인 ledger (PS-9 / P4-Q3) — durable, secret-free 재전송 방지.

결정(P4-Q3, 잠금): 서명된 승인 TOKEN(HMAC 출력)은 절대 영속화하지 않는다(NOT-PERSIST). bearer
자격증명을 영속화하면 at-rest 캡처 표면만 넓히고 replay 방어는 전혀 얻지 못한다(replay 는 token 을
보관해서가 아니라 single-use nonce + 짧은 TTL 로 차단된다). 크래시를 살아남아야 하는 것은
CONSUMED-NONCE 집합이다: ``OperatorGate._seen_nonces`` 는 in-memory 집합이라, 영속성이 없으면 재부팅이
캡처되었으나 아직 만료되지 않은 token 에 대해 replay window 를 재개방한다(PS-6 가 seq high-watermark
에서 고친 것과 동일한 결함).

그래서 이 ledger 는 secret-free ``OperatorApprovalReceipt``(명령 바인딩 메타데이터 + lifecycle
verdict)를 저장하고 boot 복구를 위해 consumed-nonce 집합을 노출한다. token / hmac / key 필드를
전혀 보유하지 않는다 — 구조적으로 secret-free(PS-3)이므로 ``verify_replay_leak0`` 이 구성상 통과한다.
이는 intent ledger(집행/G3)와 별개의 durable ledger 다; 둘 다 0600, owner-only, 비공유 볼륨이며
checkpointer 와 구별된다(FRAMEWORK §2.2, PS-9 #3).
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass
from typing import Optional

_LOCK = threading.Lock()

# lifecycle verdict (receipt 어디에도 token/secret 없음)
_VERDICTS = ("ISSUED", "GRANTED", "DENIED", "EXPIRED", "REPLAY_REJECTED")


@dataclass
class OperatorApprovalReceipt:
    """secret-free 승인 receipt — 명령 바인딩 + lifecycle, 절대 token/key 아님."""
    decision_id: str
    command_digest: str
    nonce: str
    expiry: float
    verdict: str = "ISSUED"          # _VERDICTS 중 하나
    kid: str = ""
    issued_ts: float = 0.0
    consumed_ts: Optional[float] = None
    # NOTE: 설계상 ``token`` / ``hmac`` / ``key`` 필드는 여기 존재하지 않는다(PS-3, 구조적).


class OperatorLedger:
    """OperatorApprovalReceipt 의 Append-only JSONL (0600, owner-only, 비공유 볼륨).

    durable single-use 재전송 방지를 구동한다: ``consumed_nonces()`` 는 소비 verdict 에 도달한 모든
    nonce 를 반환하고, ``recover_on_boot()`` 는 그 집합을 재로드해 첫 verify 가 accept 되기 전에
    게이트가 ``_seen_nonces`` 를 재시드하게 한다(SeqWatermark 처럼 순서 fence).
    """

    _CONSUMED = frozenset({"GRANTED", "EXPIRED", "REPLAY_REJECTED"})

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def record(self, *, decision_id: str, command_digest: str, nonce: str, expiry: float,
               verdict: str = "ISSUED", kid: str = "", issued_ts: float = 0.0,
               consumed_ts: Optional[float] = None) -> OperatorApprovalReceipt:
        """secret-free receipt 추가(fsync). 알 수 없는 verdict 는 거부(fail-closed)."""
        if verdict not in _VERDICTS:
            raise ValueError(f"unknown operator receipt verdict: {verdict!r}")
        rcpt = OperatorApprovalReceipt(
            decision_id=decision_id, command_digest=command_digest, nonce=nonce, expiry=expiry,
            verdict=verdict, kid=kid, issued_ts=issued_ts, consumed_ts=consumed_ts,
        )
        line = json.dumps(asdict(rcpt), ensure_ascii=False)
        with _LOCK:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            # 권한을 owner-only 로 조임(best-effort; 미지원 환경, 예: Windows 에서는 no-op).
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        return rcpt

    def scan(self) -> list[OperatorApprovalReceipt]:
        if not os.path.exists(self.path):
            return []
        out: list[OperatorApprovalReceipt] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    out.append(OperatorApprovalReceipt(**json.loads(ln)))
        return out

    def consumed_nonces(self) -> set[str]:
        """소비 verdict 에 도달한 모든 nonce(single-use 는 재부팅을 가로질러 durable)."""
        return {r.nonce for r in self.scan() if r.verdict in self._CONSUMED and r.nonce}

    def recover_on_boot(self) -> set[str]:
        """consumed-nonce 집합 재로드(게이트가 어떤 verify 든 accept 하기 전에 호출). ``OperatorGate
        (ledger=...)`` 가 생성 시 ``_seen_nonces`` 를 시드할 수 있도록 그 집합을 반환한다."""
        return self.consumed_nonces()
