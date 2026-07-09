"""core.modules.backends.mock — MockBackend(개발·replay·로컬 검증 전용).

두 역할(도커 무접속):
  (1) 결정론 replay : table[tool_id] -> canned ExecOutput 반환. 오프라인 재현.
  (2) 로컬 실증     : live_local=True -> req.argv 를 **로컬 subprocess**(docker 미경유)로
                     supervise_subprocess 에 그대로 태운다. 종료계약(하드타임아웃 +
                     프로세스트리 강제종료 + 자원회수)을 dev 머신에서 실제로 실증.

DESIGN 경고 계승: mock 통과 ≠ 배포안전(실환경 누수·연결한계 미모사) ->
  배포안전은 게이트1 통합테스트로만 판정. (2)는 '종료 프리미티브가 실제로 죽는가'만
  검증하는 용도이지 컨테이너 누수를 모사하지 않는다.
작성 2026-07-05.
"""

from __future__ import annotations

import asyncio
import copy
import tempfile
from pathlib import Path
from typing import Mapping, Optional

from core.modules.backends.base import (
    Backend,
    CRSError,
    Err,
    ExecOutput,
    ExecRequest,
    Ok,
    Result,
    _DEFAULT_KILL_GRACE_S,
    _DEFAULT_MAX_OUTPUT_BYTES,
    supervise_subprocess,
)


class MockBackend(Backend):
    """개발/replay/로컬-검증 백엔드. 실 docker/ssh 무접속.

    table      : tool_id -> canned ExecOutput(결정론 replay). 히트 시 딥카피 반환.
    live_local : True 면 table 미스 시 req.argv 를 로컬 subprocess 로 실행
                 (docker 래핑 없음) — timeout/kill 실증용.
    default    : table 미스 & live_local=False 일 때 반환할 기본 출력(성공 no-op).
    """

    def __init__(
        self,
        *,
        table: Optional[Mapping[str, ExecOutput]] = None,
        live_local: bool = False,
        workdir: Optional[Path] = None,
        default: Optional[ExecOutput] = None,
        kill_grace_s: float = _DEFAULT_KILL_GRACE_S,
        max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
        sem: Optional[asyncio.Semaphore] = None,
    ) -> None:
        self._table: dict[str, ExecOutput] = dict(table or {})
        self._live_local = live_local
        self._workdir = Path(workdir) if workdir else Path(tempfile.gettempdir())
        self._default = default or ExecOutput(returncode=0, stdout="", stderr="")
        self._kill_grace_s = kill_grace_s
        self._max_output = max_output_bytes
        self._sem = sem

    async def run(self, req: ExecRequest) -> Result[ExecOutput]:
        # (1) canned 결정론 replay — tool_id 키 히트.
        canned = self._table.get(req.tool_id)
        if canned is not None:
            return Ok(copy.deepcopy(canned))

        # (2) 로컬 실증 — 종료계약(timeout/kill/회수)을 실제 subprocess 로 검증.
        if self._live_local:
            try:
                out = await supervise_subprocess(
                    req.argv,
                    stdin=req.stdin,
                    timeout_s=(req.timeout_s or 30.0),
                    kill_grace_s=self._kill_grace_s,
                    workdir=self._workdir,
                    max_output_bytes=self._max_output,
                    sem=self._sem,
                )
            except Exception as e:  # noqa: BLE001 — 예외 누출 금지
                return Err(
                    CRSError(
                        f"MockBackend live_local failed: {e}",
                        extra={"tool": req.tool_id},
                    )
                )
            return Ok(out)

        # (3) 미스 & 비실증 -> 기본 no-op 성공(결정론).
        return Ok(copy.deepcopy(self._default))

    async def teardown(self) -> None:
        # 지속 자원 없음(subprocess 는 supervise 가 이미 회수). 멱등 no-op.
        return None


__all__ = ["MockBackend"]
