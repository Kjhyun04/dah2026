"""core.modules.backends.base — 백엔드 실행 계약 + 종료 프리미티브 (DESIGN §4.3).

이 모듈이 P1 실행엔진의 **정본 계약**이다. DESIGN §4.3 의 느슨한 `Backend.run(cmd)`
표현을 구조화 `ExecRequest -> Result[ExecOutput]` 로 재정의한다(Map gaps: 'cmd' 저명세
해소). 계약의 심장은 회고(§0·§4.1)에서 무너진 지점 — **확실히 죽고, 자원을 회수한다** —
을 세 축으로 보장하는 것이다:

  (A) 하드 타임아웃      : asyncio.timeout 워치독.
  (B) 확실한 강제종료    : 프로세스 트리 kill(POSIX=killpg / Windows=taskkill /T).
                          컨테이너 내부는 `timeout -k`(R1) 2차 보증 — LocalBackend 배선.
  (C) 자원회수          : finalize() 로 성공/예외/취소 무관 정리 coro 를 항상 await.
                          stdout/stderr 는 **PIPE 미사용**(손자 파이프 데드락 회피) ->
                          scoped_tempfile 로 파일 캡처 후 트림 로드.

반환은 tool_wrap 의 Result[T](Ok|Err) 계약을 계승한다(Runner 시그니처와 정합).
  예외를 밖으로 던지지 않는다 — 실패는 Err(CRSError) 로 봉투화.
비밀(secret_params)은 argv/env 가 아니라 ExecRequest.stdin(bytes) 로만 주입한다(R6).
grep0(06 P2·17 §3): 이 계층은 truth/감독/ground-truth 를 import·산출하지 않는다.

aixcc utils.py 가 `.shield` 에서 import 하지만 참조본에 미복사된 finalize/scoped_pipe
프리미티브를 여기서 재구현한다(Map gaps: 종료계약 핵심 프리미티브).
작성 2026-07-05.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import (
    AsyncIterator,
    Awaitable,
    Iterator,
    Literal,
    Optional,
    Self,
    Sequence,
)

from core.modules.tool_wrap import CRSError, Err, Ok, Result

# 실행 발판(vantage) 어휘 — ExecBinding.sidecar 와 동일하게 닫힘(13 §3).
type Sidecar = Literal["ue", "core", "sgi", "host"]

# 기본 상한(자원 보호). 개별 백엔드가 생성자에서 덮어쓸 수 있음.
_DEFAULT_TIMEOUT_S: float = 30.0
_DEFAULT_KILL_GRACE_S: float = 5.0
_DEFAULT_MAX_OUTPUT_BYTES: int = 256 * 1024  # 파일 캡처 트림 상한


# ═══════════════════════════════════════════════════════════════════════════
# 1. 페이로드 dataclass — ExecRequest / ExecOutput
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class ExecRequest:
    """Backend.run 입력(구조화). ExecBinding + 검증 params + 해석된 비밀 -> 실행요청.

    argv    : 실행 커맨드 벡터. argv[0]=이미지 baked script 경로. **비밀 원문 불포함**
              (secret_params 는 stdin 경로). shell 미경유(주입 안전).
    stdin   : secret_params 값(vault->stdin, R6). None 이면 자식 stdin=DEVNULL.
    sidecar : 실행 발판(ue/core/sgi/host). host 는 컨테이너 없이 호스트 직접 실행.
    on_host : sidecar=='host' 동의(호스트에서 docker CLI/inspect 직접). 자동 세팅.
    """

    sidecar: Sidecar
    argv: tuple[str, ...]
    stdin: Optional[bytes] = None
    timeout_s: float = _DEFAULT_TIMEOUT_S
    tool_id: str = ""
    reversible: bool = True
    on_host: bool = False

    def __post_init__(self) -> None:
        # argv 를 불변 튜플로 정규화(외부 리스트 변이 차단).
        object.__setattr__(self, "argv", tuple(self.argv))
        if self.sidecar == "host":
            object.__setattr__(self, "on_host", True)
        if not self.argv:
            raise ValueError("ExecRequest.argv is empty (need at least the script path)")


@dataclass(slots=True)
class ExecOutput:
    """백엔드 원시 실행결과 = exec_meta 원천(09 §1 누수감시).

    killed/timed_out -> parse_output 이 보수판정(허위 effected/accepted 0)에 사용.
    latency_ms/killed -> results._ResultBase 로 전사. stdout 은 파일 경유 트림 로드.
    """

    returncode: int
    stdout: str = ""
    stderr: str = ""
    latency_ms: int = 0
    killed: bool = False
    timed_out: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# 2. 종료 프리미티브 — finalize / scoped_pipe / scoped_tempfile
#    (aixcc utils.py 미복사분 재구현. 종료계약의 핵심.)
# ═══════════════════════════════════════════════════════════════════════════


@contextlib.asynccontextmanager
async def finalize(coro: Awaitable[object]) -> AsyncIterator[None]:
    """본문 성공/예외/취소와 무관하게 정리 coro 를 **항상 await**(확정 자원회수).

    workdb.task_entry 의 `async with finalize(self._reap(proc)): async with
    asyncio.timeout(t): await proc.wait()` 패턴을 백엔드 종료계약에 이식.
    shield 로 취소가 정리를 중단시키지 못하게 보호한다.
    """
    try:
        yield
    finally:
        await asyncio.shield(_as_future(coro))


def _as_future(coro: Awaitable[object]) -> "asyncio.Future[object]":
    """coro/awaitable -> Future(shield 대상). 이미 Future 면 그대로."""
    return asyncio.ensure_future(coro)  # type: ignore[arg-type]


@contextlib.contextmanager
def scoped_pipe() -> Iterator[tuple[int, int]]:
    """os.pipe() fd 쌍 수명관리(utils.py scoped_pipe 미러). finally 에서 확정 close.

    PIPE 데드락 회피 경로에서 fd 누수 0 을 보장(게이트1: 소켓/fd free).
    """
    r, w = os.pipe()
    try:
        yield r, w
    finally:
        for fd in (r, w):
            with contextlib.suppress(OSError):
                os.close(fd)


@contextlib.contextmanager
def scoped_tempfile(dir_: Path, *, suffix: str = "") -> Iterator[Path]:
    """임시파일 수명관리(stdout/stderr 파일 캡처용). finally 에서 확정 unlink.

    PIPE 캡처 금지 규칙(DESIGN §4.1)에 따라 자식 출력은 이 파일로 리다이렉트한다.
    """
    dir_.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(dir_), suffix=suffix)
    os.close(fd)  # mkstemp fd 즉시 반납 — 우리는 경로만 사용
    p = Path(name)
    try:
        yield p
    finally:
        with contextlib.suppress(OSError):
            p.unlink()


def read_trimmed(path: Path, limit: int = _DEFAULT_MAX_OUTPUT_BYTES) -> str:
    """출력 파일 -> 트림 문자열(trim_tool_output 미러). 상한 초과 시 말미 절단 표기."""
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if len(data) > limit:
        data = data[:limit] + b"\n...[truncated]..."
    return data.decode("utf-8", "replace")


# ═══════════════════════════════════════════════════════════════════════════
# 3. 프로세스 트리 강제종료 (크로스플랫폼)
# ═══════════════════════════════════════════════════════════════════════════


def terminate_tree(proc: asyncio.subprocess.Process) -> None:
    """프로세스 트리 확정 kill. POSIX=killpg(SIGKILL) / Windows=taskkill /F /T.

    정확 대상 지정: PID/프로세스그룹만 죽인다(넓은 grep kill 금지).
    주의(DESIGN §4.1): 로컬 `docker exec` 클라이언트를 죽여도 dockerd 소유
      컨테이너-내부 프로세스는 죽지 않는다 — 그 보증은 컨테이너 내부 `timeout -k`(R1)
      가 담당(LocalBackend 배선). 이 함수는 로컬 프로세스 트리만 책임진다.
    """
    if proc.returncode is not None:
        return
    pid = proc.pid
    try:
        if os.name == "posix":
            # start_new_session=True 로 띄운 자식 -> 세션리더 pgid == pid.
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        else:
            # Windows: 자식+손자 트리 확정 종료. taskkill 은 즉시 반환(단명).
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    except (ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(Exception):
            proc.kill()  # 폴백: 단일 프로세스만이라도 확실히


def _spawn_kwargs() -> dict[str, object]:
    """플랫폼별 '새 프로세스 그룹/세션' 생성 인자(트리 kill 대상 격리)."""
    if os.name == "posix":
        return {"start_new_session": True}
    # Windows: 새 프로세스 그룹 — taskkill /T 트리 종료의 앵커.
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return {"creationflags": flags}


# ═══════════════════════════════════════════════════════════════════════════
# 4. 공용 subprocess 감독 (LocalBackend·MockBackend 공유)
# ═══════════════════════════════════════════════════════════════════════════


async def supervise_subprocess(
    argv: Sequence[str],
    *,
    stdin: Optional[bytes],
    timeout_s: float,
    kill_grace_s: float,
    workdir: Path,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    sem: Optional[asyncio.Semaphore] = None,
    env: Optional[dict[str, str]] = None,
) -> ExecOutput:
    """단일 로컬 프로세스 실행 = 종료계약 정본 구현(A+B+C 단일 계약).

    미러 규격(workdb.task_entry):
      `async with finalize(reap): async with asyncio.timeout(t): await proc.wait()`

    - 출력은 PIPE 아닌 임시파일(scoped_tempfile)로 캡처 -> 손자 파이프 데드락 회피.
    - 비밀(stdin bytes)은 표준입력으로만 주입(argv/env 노출 0, R6).
    - 타임아웃 시 프로세스 트리 강제종료 + killed/timed_out 표기 + 자원회수.
    - sem 이 주어지면 단일 슬롯 직렬화(공유 한정자원 예: 5762 pool=1).

    ※ dockerd 소유 컨테이너의 확정 종료는 여기서 보장 못 함(그건 컨테이너 내부
      timeout -k, LocalBackend 배선). 이 함수는 '로컬 프로세스 트리' 계약만 보장.
    """
    guard = sem if sem is not None else contextlib.nullcontext()
    start = time.monotonic()
    killed = False
    timed_out = False

    async with guard:
        with (
            scoped_tempfile(workdir, suffix=".out") as out_path,
            scoped_tempfile(workdir, suffix=".err") as err_path,
        ):
            # 자식 출력 -> 파일 fd(부모는 spawn 직후 자기 핸들 close).
            out_f = open(out_path, "wb")
            err_f = open(err_path, "wb")
            proc: Optional[asyncio.subprocess.Process] = None
            try:
                child_env = {**os.environ, **env} if env else None
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=(
                        asyncio.subprocess.PIPE
                        if stdin is not None
                        else asyncio.subprocess.DEVNULL
                    ),
                    stdout=out_f,
                    stderr=err_f,
                    env=child_env,
                    **_spawn_kwargs(),
                )
            except (FileNotFoundError, OSError) as e:
                out_f.close()
                err_f.close()
                # spawn 자체 실패 — 실행 불가(도구 미존재 등). 비-예외 표기 반환.
                return ExecOutput(
                    returncode=127,
                    stderr=f"spawn failed: {e}",
                    latency_ms=int((time.monotonic() - start) * 1000),
                    killed=False,
                    timed_out=False,
                )
            finally:
                # 부모 측 파일 핸들 반납(자식이 dup 보유). fd 누수 0.
                out_f.close()
                err_f.close()

            async def _reap() -> None:
                """정리 coro: 살아있으면 트리 kill 후 반드시 wait(좀비 0)."""
                if proc.returncode is None:
                    terminate_tree(proc)
                with contextlib.suppress(ProcessLookupError):
                    await proc.wait()

            async with finalize(_reap()):
                # 비밀 stdin 주입(파일 stdout 이므로 역방향 데드락 없음).
                if stdin is not None and proc.stdin is not None:
                    with contextlib.suppress(
                        BrokenPipeError, ConnectionResetError
                    ):
                        proc.stdin.write(stdin)
                        await proc.stdin.drain()
                    with contextlib.suppress(Exception):
                        proc.stdin.close()
                try:
                    async with asyncio.timeout(timeout_s):
                        await proc.wait()
                except TimeoutError:
                    # 하드 타임아웃 -> 트리 강제종료. finalize 의 _reap 이 wait 회수.
                    killed = True
                    timed_out = True
                    terminate_tree(proc)
                    # kill grace: SIGKILL 반영 대기(짧게). 미종료 시 finalize 재보증.
                    with contextlib.suppress(TimeoutError):
                        async with asyncio.timeout(kill_grace_s):
                            await proc.wait()

            rc = proc.returncode if proc.returncode is not None else -1
            return ExecOutput(
                returncode=rc,
                stdout=read_trimmed(out_path, max_output_bytes),
                stderr=read_trimmed(err_path, max_output_bytes),
                latency_ms=int((time.monotonic() - start) * 1000),
                killed=killed,
                timed_out=timed_out,
            )


# ═══════════════════════════════════════════════════════════════════════════
# 5. Backend ABC — 실행 계약 정본
# ═══════════════════════════════════════════════════════════════════════════


class Backend(ABC):
    """DESIGN §4.3 백엔드 실행 계약. run='실행' + teardown='정리'를 하나의 계약으로.

    run     : (하드타임아웃 + 확실한 강제종료 + 자원회수)를 보장하는 단위.
              반환은 Result[ExecOutput](Ok|Err) — 예외 누출 금지.
    teardown: 표준 정리(자식·소켓·임시파일·기동 사이드카/reap). orphan 0.
    구현     : mock/local/ssh. mock 통과 ≠ 배포안전(게이트1 통합테스트로만 판정).

    async 컨텍스트 매니저 지원 -> `async with LocalBackend(...) as be:` 로 teardown 보장.
    """

    @abstractmethod
    async def run(self, req: ExecRequest) -> Result[ExecOutput]:
        """실행요청 1건 -> 결과. 실패(비도달·spawn실패·kill)는 Err 로 봉투화."""
        raise NotImplementedError

    @abstractmethod
    async def teardown(self) -> None:
        """자원회수(자식·소켓·임시파일·reap). 멱등. 예외를 밖으로 던지지 않음."""
        raise NotImplementedError

    async def preflight(self) -> Result[None]:
        """R3 게이트(ARIA vendor·openssl aria·pymavlink 정합 확인). 기본 통과.

        make_runner_factory 의 preflight 게이트가 팩토리 스코프 1회 호출·캐시한다.
        기본은 무조건 통과(mock/원격 무관) — 실측이 필요한 백엔드(LocalBackend)만 override.
        """
        return Ok(None)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.teardown()


# ═══════════════════════════════════════════════════════════════════════════
# 6. 백엔드 모드 어휘 정합 (Map gaps: docker_exec/local/ssh/mock reconcile)
# ═══════════════════════════════════════════════════════════════════════════

# config.ExecSpec.mode=Literal['docker_exec','ssh','host'] vs DESIGN mock/local/ssh
# vs 13 §1 local/ssh — 정본 어휘로 통일: 'docker_exec'·'local'·'host' -> LocalBackend.
_MODE_TO_BACKEND: dict[str, str] = {
    "docker_exec": "local",  # config 기본값 == LocalBackend
    "local": "local",
    "host": "local",  # 호스트 직접도 LocalBackend(on_host 분기)로 흡수
    "ssh": "ssh",
    "mock": "mock",
}


def resolve_backend_kind(mode: str) -> str:
    """exec.mode(config/DESIGN/문서13 3중 어휘) -> 백엔드 종류('local'|'ssh'|'mock').

    미확정 어휘 정합점: 'docker_exec'<->'local' 동의어, 'host' 는 LocalBackend 흡수.
    """
    kind = _MODE_TO_BACKEND.get(mode)
    if kind is None:
        raise CRSError(
            f"unknown exec mode: {mode!r}",
            extra={"known": sorted(_MODE_TO_BACKEND)},
        )
    return kind


__all__ = [
    "Sidecar",
    "ExecRequest",
    "ExecOutput",
    "Backend",
    "finalize",
    "scoped_pipe",
    "scoped_tempfile",
    "read_trimmed",
    "terminate_tree",
    "supervise_subprocess",
    "resolve_backend_kind",
    # tool_wrap 재수출(백엔드 구현이 동일 심볼 사용)
    "Result",
    "Ok",
    "Err",
    "CRSError",
]
