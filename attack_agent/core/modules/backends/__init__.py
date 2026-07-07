"""core.modules.backends — P1 실행엔진 백엔드 (DESIGN §4.3·§12).

'실행'과 '정리'를 하나의 계약으로: 모든 Backend.run 은 (하드타임아웃 + 확실한
강제종료 + 자원회수)를 보장하고, teardown 은 표준 정리(orphan 0)를 보장한다.

  base   : Backend 계약 · ExecRequest/ExecOutput · 종료 프리미티브
           (finalize·scoped_tempfile·supervise_subprocess·terminate_tree).
  local  : LocalBackend(정본 배포·docker exec) · SshBackend(원격 옵션).
  mock   : MockBackend(개발/replay/로컬 timeout·kill 실증).

정본 = LocalBackend(SSH 불필요, 13 §1). mock 통과 ≠ 배포안전(게이트1 통합테스트로만).
"""

from __future__ import annotations

from core.modules.backends.base import (
    Backend,
    CRSError,
    Err,
    ExecOutput,
    ExecRequest,
    Ok,
    Result,
    Sidecar,
    finalize,
    read_trimmed,
    resolve_backend_kind,
    scoped_pipe,
    scoped_tempfile,
    supervise_subprocess,
    terminate_tree,
)
from core.modules.backends.local import ContainerResolver, LocalBackend, SshBackend
from core.modules.backends.mock import MockBackend

__all__ = [
    # 계약 · 페이로드
    "Backend",
    "ExecRequest",
    "ExecOutput",
    "Sidecar",
    # 구현
    "LocalBackend",
    "SshBackend",
    "MockBackend",
    "ContainerResolver",
    # 종료 프리미티브
    "finalize",
    "scoped_pipe",
    "scoped_tempfile",
    "read_trimmed",
    "terminate_tree",
    "supervise_subprocess",
    "resolve_backend_kind",
    # tool_wrap 재수출
    "Result",
    "Ok",
    "Err",
    "CRSError",
]
