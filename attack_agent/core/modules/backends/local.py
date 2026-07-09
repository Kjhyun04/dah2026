"""core.modules.backends.local — LocalBackend(정본 배포) + SshBackend(원격 옵션).

DESIGN §4.3 · 13 §1(V2-D30, SSH 제거->local 정본). docker.sock 로 로컬
docker exec <sidecar> <script> <args> 실행. 안티패턴 전량 회피(DESIGN §4.1):

  X 도구별 docker run --rm 단명 컨테이너 -> OK 장수 사이드카 + docker exec.
  X subprocess.run(capture_output, timeout) PIPE 데드락 -> OK 파일 캡처 + 워치독.
  X dockerd 소유 컨테이너를 killpg 로 죽인다 가정 -> OK 컨테이너 내부 timeout -k(R1).

이중 종료 보증:
  (1) 로컬 워치독 : supervise_subprocess 의 asyncio.timeout -> docker exec 클라이언트
      프로세스 트리 강제종료(로컬 자원회수).
  (2) 컨테이너 내부: timeout -k <grace> <t> 래핑 -> dockerd 소유 프로세스 확정 종료(R1·PRIMARY).
      로컬 클라이언트가 먼저 죽어도 컨테이너 내부는 timeout 이 스스로 상한(T+G) 내 회수.

종료 모델(테스트베드 실측 반영 · FACT1~4):
  · wrap = setsid sh -c ': DAH_JOB=<uuid>; timeout -k <G> <T> "$@";
            __rc=$?; echo $__rc > /tmp/dah_rc_<uuid>; exit $__rc' _ <argv>.
    - setsid : sh 를 새 세션/프로세스그룹 리더로 승격(PGID == sh PID) -> per-job reap 이
      kill -TERM -<PGID>(process-group kill)로 그룹 통째 회수 가능(FACT3). docker exec -i(무 TTY)
      의 자식은 프로세스그룹 리더가 아니므로 busybox setsid 는 setsid() 성공->fork 없이 직접 exec
      -> docker exec 가 sh 종료까지 대기하며 exit code 를 정확히 회수한다.
    - timeout -k 를 마지막 명령이 아니게(; __rc=$?; echo …; exit $__rc) 배치 -> busybox ash 의
      exec 최적화(마지막 외부명령을 sh 자리에 덮어씀, FACT1)를 차단 -> sh 가 부모로 상주하여
      마커(DAH_JOB=<uuid>)가 실행 내내 cmdline 에 존재(reap 의 PGID 조회 앵커).
    - rc-file fallback(강건 exit-code 회수): 특정 busybox 빌드에서 setsid 가 fork/즉시반환
      (_exit 0)하면 docker exec 가 항상 0 을 반환해 killed/preflight 오판이 난다. 이를 없애기
      위해 wrap 이 실제 rc 를 echo $__rc > /tmp/dah_rc_<uuid> 로 컨테이너 파일에 기록하고, 백엔드가
      docker exec 반환 후 그 파일을 read(파일 캡처 규약과 동일·PIPE 금지)하여 setsid fork 여부와
      무관하게 실제 rc 를 확정한다(_recover_rc). fork 로 docker exec 가 조기반환한 경우엔 컨테이너
      내부에서 rc 파일 등장을 유계 폴링(T+G 상한) 후 읽는다. exit $__rc 전파는 무-fork 빌드용
      빠른 경로로 남긴다(파일과 값 일치).
  · per-job teardown(R2·컨테이너-스코프): 마커->PGID 그룹 kill(FACT2·3 whack-a-mole: busybox
    timeout 이 자기 PGID 로 탈출/pid1 reparent -> 마커 상실 -> 생존)을 폐기. 대신
    _reap_all_script = 사이드카 안에서 pid1(+리퍼 자기트리) 제외 전 프로세스 kill
    (TERM->grace->KILL). SIGKILL·per-pid 라 pgid-escape 무관하게 탈출한 timeout 까지 확실 회수.
    PID 네임스페이스 private 가드(pid1=sleep 확인, fail-closed)로 호스트 광역 kill 차단.
    teardown 이 (container,job) 을 컨테이너로 dedupe -> 사이드카당 1회. sem 획득으로 in-flight
    run/rc-recovery 와 비중첩(직렬 불변식 강제). 안전 전제 = 우리 사이드카는 pid1=sleep infinity
    + ephemeral 잡, 상주 데몬 없음.
  · teardown(캠페인 종료·R2): 우리 라벨 사이드카를 docker rm -f(SidecarManager/safeexec.reap_labeled)
    하면 컨테이너 내부 모든 프로세스가 원자적으로 회수(FACT4) — 이것이 캠페인 종료 회수의 정본.
    본 백엔드의 in-place 스윕은 그 상보(사이드카 상보·컨테이너 상주 시 잔여 회수)다.

비밀(R6): secret_params 값은 argv/env 가 아니라 stdin(bytes)로만 — ExecRequest.stdin
  -> docker exec -i … <script> 표준입력. 스크립트는 baked 규약대로 stdin 을 읽는다.
작성 2026-07-05 · 종료모델 재구현(setsid+PGID killpg) 2026-07-06 ·
  reap 교체(PGID 그룹 kill -> 컨테이너-스코프 kill-all-but-pid1 스윕, whack-a-mole 종결) 2026-07-06.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import shlex
import uuid
from pathlib import Path
from typing import Callable, Mapping, Optional

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
    _DEFAULT_TIMEOUT_S,
    supervise_subprocess,
)

# sidecar 리터럴 -> 실행 컨테이너 이름 해석기(SidecarManager.ensure 주입점).
# dict 도 허용 -> 정규화 시 callable 로 감쌈. host 는 컨테이너 없음(호출 안 됨).
type ContainerResolver = Callable[[str], str] | Mapping[str, str]

_JOB_MARK = "DAH_JOB"         # 고유 마커 토큰(정확 대상 reap 앵커 · cmdline 상주)
_RC_VAR = "__dah_rc"          # timeout exit code 포착 변수(마커 상주 + exit code 정확 전파)
_WATCHDOG_MARGIN_S = 5.0      # 로컬 워치독은 컨테이너 내부 timeout 보다 이 폭만큼 늦게 발화

# rc-file fallback(강건 exit-code 회수). wrap 이 실제 rc 를 컨테이너 파일에 기록하고 백엔드가
# 그 파일을 read -> busybox setsid 가 fork/즉시반환(_exit 0)해 docker exec 가 항상 0 을 반환하는
#   빌드에서도 실제 rc 를 확정한다(setsid fork 여부와 무관). 파일 캡처 규약과 동일(PIPE 금지).
_RC_DIR = "/tmp"              # 사이드카(alpine/busybox) 임시 경로 — IP/컨테이너명 아님(config 대상 아님)
_RC_PREFIX = "dah_rc_"        # rc 파일 접두(우리 소유 식별) · 파일명 = <prefix><uuid>

# R3 preflight 프로브 정의(정의만 — backend.run 경유 실행. 오프라인 무실행).
#   sgi 사이드카에서 계층 도구 정합을 확인한다(게이트1 통합테스트 실검증 대상).
#   openssl-bin  : openssl 바이너리 존재성(환경별 ARIA 목록 false-negative로 전역 봉쇄 방지).
#   pymavlink    : MAVLink 툴링 import 가용성(A/D계층 주입·식별 정합).
_R3_PROBES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "openssl-bin",
        (
            "sh",
            "-c",
            "command -v openssl >/dev/null",
        ),
    ),
    ("pymavlink", ("python3", "-c", "import pymavlink")),
)
_PREFLIGHT_TIMEOUT_S = 10.0   # 각 프로브 하드 상한(정합 확인은 단명)


def _wrap_in_container(
    argv: tuple[str, ...], *, timeout_s: float, kill_grace_s: float, job: str
) -> list[str]:
    """컨테이너 내부 실행 커맨드 벡터 조립(R1 상한종료 + JOB 마커 breadcrumb).

      sh -c ': DAH_JOB=<job>; timeout -k <G> <T> "$@"; __rc=$?; echo $__rc > <rcfile>; exit $__rc' _ <script> <args...>

    setsid 제거(2026-07-06): 구 모델은 setsid 로 sh 를 새 프로세스그룹 리더로 만들어 per-job
      PGID 그룹 kill 을 앵커했으나, reap 이 컨테이너-스코프 kill-all-but-pid1 스윕(_reap_all_script)
      으로 교체되면서 setsid/PGID/마커가 불필요해졌다. 게다가 util-linux setsid(ubuntu 사이드카)는
      fork 하여(busybox setsid 는 exec) docker exec 가 자식의 stdout 생성 전에 조기반환 -> stdout 유실
      (recon JSON 소실) 버그를 유발했다(2026-07-06 실측). setsid 제거로 docker exec 가 sh 종료까지
      대기하며 stdout·실제 rc 를 정상 회수한다.

    설계:
    - timeout -k <G> <T> : dockerd 소유 프로세스라도 T(+G) 내 확정 종료(R1·PRIMARY). 로컬
      워치독/클라이언트가 먼저 죽어도 컨테이너 내부에서 자기회수.
    - ; __rc=$?; echo $__rc > <rcfile>; exit $__rc : timeout 의 exit code 를 $?로 포착해
      (1) exit 로 전파(setsid 없이 docker exec 가 실제 rc 회수) + (2) rc 파일에 기록(_recover_rc
      belt·이제 무-fork 라 exit 전파와 항상 일치). : DAH_JOB=<job> 는 debug breadcrumb(reap 미사용).
    - "$@" 는 $1.. 위치인자(= script+args). $0='_'(자리 채움).
    - 비밀 stdin 은 sh->timeout->script 로 상속(argv 노출 0, R6).
    """
    marker = f"{_JOB_MARK}={job}"  # debug breadcrumb(reap 미사용 — kill-all-but-pid1 은 마커 불요)
    rc_file = _rc_path(job)  # job=hex uuid -> 셸 특수문자 없음(안전)
    inner = (
        f": {marker}; "
        f'timeout -k {int(kill_grace_s)} {int(timeout_s)} "$@"; '
        f"{_RC_VAR}=$?; echo ${_RC_VAR} > {rc_file}; exit ${_RC_VAR}"
    )
    return ["sh", "-c", inner, "_", *argv]  # setsid 제거(util-linux fork->stdout 유실 방지)


def _rc_path(job: str) -> str:
    """job(hex uuid) -> 컨테이너 rc 파일 경로. 파일명은 우리 접두로 소유 식별."""
    return f"{_RC_DIR}/{_RC_PREFIX}{job}"


def _recover_rc_script(job: str, wait_iters: int) -> str:
    """rc 파일이 나타날 때까지 유계 대기 후 rc 를 stdout 으로 출력하고 파일을 제거하는 셸.

    busybox setsid 가 fork/즉시반환하면 docker exec 가 잡 완료 전에 반환할 수 있어(레이스) rc 파일이
    아직 없을 수 있다 -> 컨테이너 내부에서 timeout -k 상한(T+G) 범위로 파일 등장을 폴링(sleep 1,
    정수초라 busybox 이식성 안전)한 뒤 읽는다. 무-fork(정상) 빌드에선 파일이 이미 있어 첫 반복에서
    즉시 반환(대기 0). 읽은 뒤 rm -f 로 잔여 0.
    """
    f = shlex.quote(_rc_path(job))
    n = int(wait_iters)
    return (
        f"f={f}; i=0; "
        f'while [ ! -s "$f" ] && [ $i -lt {n} ]; do sleep 1; i=$((i+1)); done; '
        f'cat "$f" 2>/dev/null; rm -f "$f"'
    )


def _parse_rc(text: str) -> Optional[int]:
    """rc 파일 stdout -> int. 마지막 비어있지 않은 라인을 정수로 해석. 실패 시 None(폴백)."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    try:
        return int(lines[-1])
    except ValueError:
        return None


def _rc_wait_iters(timeout_s: float, kill_grace_s: float, margin_s: float) -> int:
    """rc 파일 폴링 최대 반복(sleep 1 · 초 단위). 컨테이너 잡 상한 T+G + margin 을 덮는다."""
    return max(1, math.ceil(timeout_s + kill_grace_s + margin_s))


def _reap_all_script(grace_s: float) -> str:
    """컨테이너-스코프 리퍼 셸: pid1(+리퍼 자기트리) 제외 전 프로세스 kill(TERM->grace->KILL).

    §4 미결 해소(마커/PGID 모델의 구조적 구멍 제거): busybox timeout 이 자기 프로세스그룹으로
    탈출하거나 setsid-fork 로 pid1 에 reparent 되어 마커를 잃어도, per-pid /proc 스윕이 직접
    죽인다. SIGKILL 은 uncatchable·pgid-escape 무관 -> 탈출한 timeout 도 확실 회수.

    설계·적대검증 근거(alpine BusyBox 1.37.0 실증):
      · kill/read/[/set = ash 빌트인 -> 스윕 루프가 fork 0(리퍼 자기 자식 레이스 없음).
      · $$ 는 subshell 에서도 불변(POSIX) -> SELF 로 리퍼 트리 식별 가능(alpine 은 BASHPID 없음).
      · /proc/<pid>/stat 은 comm 이 공백/) 를 담을 수 있어 마지막 ')' 이후(${st##*)})만
        파싱해야 ppid 를 안전 추출.

    안전 가드(적대검증 채택):
      · pid1 정체 확인(fail-closed): /proc/1/comm 이 keepalive(sleep — SidecarManager
        _SLEEP_CMD)가 아니면 스윕 중단(exit 3). 공유/호스트 PID 네임스페이스(--pid=host
        --pid=container:)에선 pid1=호스트 init -> 불일치 -> 호스트 광역 kill 원천 차단.
      · is_mine: SELF($$) 검사를 -le 1 가드보다 먼저 수행(리퍼가 pid1일 때 자식 오살
        방지) + stat read 는 2>/dev/null 선행. 리퍼 자기 트리(subshell·grace sleep)를 ppid
        조상 추적으로 제외.

    안전 전제(우리 모델): 이 무차별 스윕은 우리 소유 사이드카(pid1=sleep infinity +
      ephemeral docker-exec 잡, 상주 비-pid1 데몬 없음)에 대해서만 안전하다. sem=1 +
      teardown 전용(호출자가 teardown 시 sem 획득) 불변식이 근거 — 라이브 잡/rc-recovery 와
      스윕이 겹치지 않는다. 캠페인 종료 원자 회수의 정본은 여전히 우리 라벨 docker rm -f
      (FACT4) — 이 스윕은 사이드카 상주 시의 in-place 상보다.

    좀비 잔여(정직성): pid1=sleep infinity 는 wait() 를 하지 않으므로, 스윕이 죽인
      프로세스 중 사망 전 pid1 로 reparent 된 것은 defunct(Z) 좀비로 /proc 에 남는다. 좀비는
      자원(CPU·메모리·5762 연결) 0 의 inert 엔트리이며, 캠페인 종료 docker rm -f(PRIMARY)로
      원자 회수된다. gate-1 실측(2026-07-06): 탈출 timeout 포함 모든 LIVE 프로세스 0,
      잔여는 전부 Z(alpine 8·dahv2/air 9) — 누수 아님(자원 미보유).
    """
    g = max(1, int(grace_s))  # busybox sleep 는 정수초 · sub-second grace 붕괴 방지
    return (
        "SELF=$$\n"
        f"GRACE={g}\n"
        "read -r C < /proc/1/comm 2>/dev/null || C=\n"
        "case \"$C\" in\n"
        "  *sleep*) ;;\n"
        "  *) echo \"reap-abort: pid1=$C not keepalive\" >&2; exit 3;;\n"
        "esac\n"
        "is_mine() {\n"
        "  p=$1\n"
        "  while :; do\n"
        '    [ "$p" = "$SELF" ] && return 0\n'
        '    [ "$p" -le 1 ] && return 1\n'
        '    read -r st 2>/dev/null < "/proc/$p/stat" || return 1\n'
        "    rest=${st##*)}\n"
        "    set -- $rest; p=$2\n"
        "  done\n"
        "}\n"
        "sweep() {\n"
        "  for d in /proc/[0-9]*; do\n"
        "    pid=${d#/proc/}\n"
        '    [ "$pid" = 1 ] && continue\n'
        '    [ "$pid" = "$SELF" ] && continue\n'
        '    is_mine "$pid" && continue\n'
        '    kill -"$1" "$pid" 2>/dev/null\n'
        "  done\n"
        "}\n"
        "sweep TERM\n"
        'sleep "$GRACE"\n'
        "sweep KILL\n"
    )


def _as_resolver(r: Optional[ContainerResolver]) -> Optional[Callable[[str], str]]:
    """dict|callable|None -> callable|None 정규화."""
    if r is None:
        return None
    if callable(r):
        return r
    mapping = r  # Mapping

    def _lookup(name: str) -> str:
        if name not in mapping:
            raise CRSError(
                f"no container for sidecar {name!r}", extra={"known": sorted(mapping)}
            )
        return mapping[name]

    return _lookup


class LocalBackend(Backend):
    """정본 배포 백엔드. 로컬 docker.sock 경유 docker exec(SSH 불필요).

    container_of : sidecar 리터럴(ue/core/sgi) -> 장수 사이드카 컨테이너 이름 해석.
                   (실제 배선은 SidecarManager.ensure 를 주입 — 이 백엔드는 해석만 소비.)
                   host 벤티지는 컨테이너 미해석(호스트 직접 실행).
    docker_bin   : docker CLI 경로/이름(하드코딩 0 — 주입 가능).
    sem          : 공유 한정자원 단일 슬롯(예: 5762 pool=1). None=무제한.
    """

    def __init__(
        self,
        *,
        workdir: Path,
        container_of: Optional[ContainerResolver] = None,
        docker_bin: str = "docker",
        default_timeout_s: float = _DEFAULT_TIMEOUT_S,
        kill_grace_s: float = _DEFAULT_KILL_GRACE_S,
        watchdog_margin_s: float = _WATCHDOG_MARGIN_S,
        max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
        sem: Optional[asyncio.Semaphore] = None,
    ) -> None:
        self._workdir = Path(workdir)
        self._container_of = _as_resolver(container_of)
        self._docker = docker_bin
        self._default_timeout_s = default_timeout_s
        self._kill_grace_s = kill_grace_s
        self._watchdog_margin_s = watchdog_margin_s
        self._max_output = max_output_bytes
        # 공유 한정자원(예: 5762 업링크) 직렬화: sem 미주입 시 단일슬롯(1) 기본.
        #   다중 연결 금지(세마포어=1) — 실배선 경로가 이 기본으로 직렬화된다.
        self._sem = sem if sem is not None else asyncio.Semaphore(1)
        # teardown 정확 reap 대상: (container, job) 집합(우리 라벨만, R2).
        self._jobs: set[tuple[str, str]] = set()

    # ── 커맨드 조립 ──────────────────────────────────────────────────────
    def _container_argv(self, req: ExecRequest, timeout_s: float, job: str) -> list[str]:
        """호스트에서 실행할 최종 argv 조립.

        host   : req.argv 를 호스트에서 직접(예: docker inspect / /sign.key 접근).
        그 외  : docker exec -i <container> setsid sh -c ': DAH_JOB=<job>;
                  timeout -k <grace> <t> "$@"; __rc=$?; exit $__rc' _ <script> <args>
                  — setsid 새 프로세스그룹(그룹 kill 앵커) + 내부 timeout(R1·PRIMARY)
                  + cmdline 상주 마커(정확 reap 앵커).
        """
        if req.on_host:
            # 호스트 직접 실행 — 컨테이너 래핑 없음. 로컬 워치독만 종료 보증.
            return list(req.argv)

        if self._container_of is None:
            raise CRSError(
                "LocalBackend: container_of resolver not wired for sidecar exec",
                extra={"sidecar": req.sidecar, "tool": req.tool_id},
            )
        container = self._container_of(req.sidecar)
        inner = _wrap_in_container(
            req.argv, timeout_s=timeout_s, kill_grace_s=self._kill_grace_s, job=job
        )
        # -i: stdin 유지(비밀 주입 경로).
        return [self._docker, "exec", "-i", container, *inner]

    # ── 실행 ─────────────────────────────────────────────────────────────
    async def run(self, req: ExecRequest) -> Result[ExecOutput]:
        timeout_s = req.timeout_s if req.timeout_s else self._default_timeout_s
        job = uuid.uuid4().hex
        try:
            argv = self._container_argv(req, timeout_s, job)
        except CRSError as e:
            return Err(e)

        # 로컬 워치독은 컨테이너 내부 timeout 보다 margin 만큼 늦게 발화
        # (내부 timeout 이 1차, 로컬 kill 은 docker/hang 대비 2차).
        outer_timeout = (
            timeout_s
            if req.on_host
            else timeout_s + self._watchdog_margin_s
        )
        container: Optional[str] = None
        if not req.on_host:
            container = self._container_of(req.sidecar)  # type: ignore[misc]
            self._jobs.add((container, job))

        # 공유 한정자원(5762 등) 직렬화 sem 을 run 스코프에서 잡는다(supervise 엔 sem 미주입).
        # -> busybox setsid fork 로 docker exec 가 조기반환해도 rc 파일 회수 대기 동안 sem 을 유지
        # -> '다중 연결 금지(세마포어=1)' 불변식이 fork 빌드에서도 보존된다.
        guard = self._sem if self._sem is not None else contextlib.nullcontext()
        async with guard:
            try:
                out = await supervise_subprocess(
                    argv,
                    stdin=req.stdin,
                    timeout_s=outer_timeout,
                    kill_grace_s=self._kill_grace_s,
                    workdir=self._workdir,
                    max_output_bytes=self._max_output,
                    sem=None,  # sem 은 run 스코프가 소유(이중 획득 방지)
                )
            except Exception as e:  # noqa: BLE001 — 예외 누출 금지(Result 봉투화)
                return Err(
                    CRSError(
                        f"LocalBackend.run failed: {e}",
                        extra={"tool": req.tool_id, "sidecar": req.sidecar},
                    )
                )
            # rc-file fallback: docker exec 반환 rc 는 busybox setsid fork 시 항상 0 이라 신뢰 불가.
            # killed/timed_out(로컬 워치독 발화)은 우리가 죽인 것이라 그 판정을 신뢰 -> rc 회수 생략.
            #   그 외엔 컨테이너 rc 파일에서 실제 rc 를 회수해 확정(sem 유지 중).
            if container is not None and not out.killed and not out.timed_out:
                rc = await self._recover_rc(container, job, timeout_s)
                if rc is not None:
                    out.returncode = rc
        return Ok(out)

    async def _recover_rc(
        self, container: str, job: str, timeout_s: float
    ) -> Optional[int]:
        """컨테이너 rc 파일에서 실제 exit code 회수(파일 캡처 규약, PIPE 금지). 실패 시 None(폴백).

        wrap 이 echo $__dah_rc > <rcfile> 로 기록한 실제 rc 를, docker exec 반환 후 별도
        docker exec <container> sh -c '<유계대기+cat+rm>' 로 읽는다. setsid fork/즉시반환으로
        docker exec 가 잡 완료 전에 반환한 경우에도 컨테이너 내부에서 rc 파일 등장을 유계 폴링해
        실제 rc 를 확정한다(setsid fork 여부와 무관). 회수 셸 출력은 임시파일로 캡처(PIPE 미사용).
        """
        wait_iters = _rc_wait_iters(
            timeout_s, self._kill_grace_s, self._watchdog_margin_s
        )
        script = _recover_rc_script(job, wait_iters)
        argv = [self._docker, "exec", container, "sh", "-c", script]
        # 회수 docker exec 워치독: 컨테이너 폴링 상한(=wait_iters 초)을 여유롭게 초과.
        outer = wait_iters + self._kill_grace_s + self._watchdog_margin_s
        try:
            out = await supervise_subprocess(
                argv,
                stdin=None,
                timeout_s=outer,
                kill_grace_s=self._kill_grace_s,
                workdir=self._workdir,
                max_output_bytes=64,  # rc 는 소량(정수 1줄)
                sem=None,  # 회수 read 는 5762 무관 — sem 미개입(run 스코프가 이미 보유)
            )
        except Exception:  # noqa: BLE001 — 회수 실패는 폴백(예외 누출 금지)
            return None
        if out.killed or out.timed_out:
            return None
        return _parse_rc(out.stdout)

    # ── R3 preflight 게이트 ──────────────────────────────────────────────
    async def preflight(self) -> Result[None]:
        """R3: openssl-aria·pymavlink 정합을 sgi 사이드카에서 확인(_R3_PROBES 정의).

        make_runner_factory 가 팩토리 스코프 1회 호출·캐시. 프로브 실패/무접속 시 Err
        (fail-open: orchestrator 는 ToolError 로 진행). container_of 미배선이면 통과(호스트/mock 무관).

        실행은 self.run(ExecRequest) 경유 — 직접 docker subprocess 호출 없음(종료계약
          일관: setsid + timeout -k 래핑 + JOB 마커 상주 -> per-job PGID reap). 오프라인 무실행.
        """
        if self._container_of is None:
            return Ok(None)
        for name, cmd in _R3_PROBES:
            req = ExecRequest(
                sidecar="sgi",
                argv=cmd,
                timeout_s=_PREFLIGHT_TIMEOUT_S,
                tool_id=f"preflight:{name}",
            )
            match await self.run(req):
                case Err() as e:
                    return e
                case Ok(out):
                    if out.returncode != 0:
                        return Err(
                            CRSError(f"preflight failed: {name} (rc={out.returncode})")
                        )
        return Ok(None)

    # ── 정리 ─────────────────────────────────────────────────────────────
    async def teardown(self) -> None:
        """각 사이드카를 컨테이너-스코프로 회수(pid1 제외 전 프로세스 sweep). best-effort·멱등.

        (container,job) 을 컨테이너로 dedupe -> 사이드카 1개당 리퍼 exec 1회(잡 수 무관·GRACE
        중복 지불 없음). 스윕은 컨테이너 PID 네임스페이스 전체를 비우므로 잡 단위 반복이 불필요.

        sem 획득: run()/rc-recovery 와 스윕이 겹치지 않도록 직렬 불변식을 '가정'이 아니라
          '강제'(적대검증 이슈3.). 우리 흐름은 teardown 이 run 완료 후라 sem 이 이미 free.
        캠페인 종료 회수의 정본은 우리 라벨 사이드카 docker rm -f(FACT4·원자적 회수,
          SidecarManager/safeexec.reap_labeled 소유)다. 이 in-place 스윕은 사이드카 상주 시의 상보.
        """
        grouped: dict[str, list[str]] = {}
        for container, job in self._jobs:
            grouped.setdefault(container, []).append(job)
        self._jobs.clear()
        if not grouped:
            return
        async with self._sem:  # 직렬 강제: in-flight run/rc-recovery 와 스윕 비중첩
            for container, jobs in grouped.items():
                with contextlib.suppress(Exception):
                    await self._reap_container(container, jobs)

    async def _reap_container(self, container: str, jobs: list[str]) -> None:
        """단일 사이드카 in-place 회수: pid1(+리퍼) 제외 전 프로세스 sweep + 잔여 우리 rc 파일 rm.

        컨테이너-스코프(잡 수 무관 1회 exec). killed 경로에서 남은 우리 rc 파일도 함께 rm(/tmp 청결).
        """
        script = _reap_all_script(self._kill_grace_s)
        rc_paths = " ".join(shlex.quote(_rc_path(j)) for j in jobs)
        if rc_paths:
            script += f"rm -f {rc_paths} 2>/dev/null\n"
        argv = [self._docker, "exec", container, "sh", "-c", script]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        # 스크립트가 grace 만큼 sleep 하므로 외곽 대기는 grace 를 넘겨 잡는다.
        outer = self._kill_grace_s * 2 + self._watchdog_margin_s
        try:
            async with asyncio.timeout(outer):
                await proc.wait()
        except TimeoutError:
            with contextlib.suppress(Exception):
                proc.kill()
                await proc.wait()


# ═══════════════════════════════════════════════════════════════════════════
# SshBackend — 원격 옵션(exec.mode=ssh). paramiko/asyncssh 불요(ssh CLI).
# ═══════════════════════════════════════════════════════════════════════════


class SshBackend(Backend):
    """원격 실행 옵션(G31 소멸이나 원격 배치 시 필요). ssh CLI 경유 원격 docker exec.

    로컬 ssh 클라이언트 프로세스는 supervise_subprocess 가 종료계약으로 관리하고,
    원격 컨테이너 내부는 setsid 새 프로세스그룹 + timeout -k(R1)로 자기회수한다. 비밀은
    ssh stdin 을 통해 원격 docker exec -i 표준입력으로 흐른다(argv 노출 0, R6).
    """

    def __init__(
        self,
        *,
        host: str,
        user: str,
        ssh_key: str,
        workdir: Path,
        container_of: Optional[ContainerResolver] = None,
        docker_bin: str = "docker",
        ssh_bin: str = "ssh",
        default_timeout_s: float = _DEFAULT_TIMEOUT_S,
        kill_grace_s: float = _DEFAULT_KILL_GRACE_S,
        watchdog_margin_s: float = _WATCHDOG_MARGIN_S,
        max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
        sem: Optional[asyncio.Semaphore] = None,
    ) -> None:
        self._host = host
        self._user = user
        self._key = ssh_key
        self._workdir = Path(workdir)
        self._container_of = _as_resolver(container_of)
        self._docker = docker_bin
        self._ssh = ssh_bin
        self._default_timeout_s = default_timeout_s
        self._kill_grace_s = kill_grace_s
        self._watchdog_margin_s = watchdog_margin_s
        self._max_output = max_output_bytes
        # 공유 한정자원(원격 5762 등) 직렬화: sem 미주입 시 단일슬롯(1) 기본(다중 연결 금지).
        self._sem = sem if sem is not None else asyncio.Semaphore(1)
        # (container, job) 정확 reap 대상 — 원격 컨테이너 내부 PGID killpg 앵커.
        self._jobs: set[tuple[str, str]] = set()

    def _remote_cmd(self, req: ExecRequest, timeout_s: float, job: str) -> str:
        """원격 쉘에서 실행할 커맨드 문자열(shlex 안전 인용)."""
        if req.on_host:
            remote_argv = list(req.argv)
        else:
            if self._container_of is None:
                raise CRSError(
                    "SshBackend: container_of resolver not wired",
                    extra={"sidecar": req.sidecar},
                )
            container = self._container_of(req.sidecar)
            inner = _wrap_in_container(
                req.argv,
                timeout_s=timeout_s,
                kill_grace_s=self._kill_grace_s,
                job=job,
            )
            remote_argv = [self._docker, "exec", "-i", container, *inner]
        return " ".join(shlex.quote(a) for a in remote_argv)

    def _ssh_argv(self, remote_cmd: str) -> list[str]:
        return [
            self._ssh,
            "-i",
            self._key,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{self._user}@{self._host}",
            remote_cmd,
        ]

    async def run(self, req: ExecRequest) -> Result[ExecOutput]:
        timeout_s = req.timeout_s if req.timeout_s else self._default_timeout_s
        job = uuid.uuid4().hex
        try:
            remote_cmd = self._remote_cmd(req, timeout_s, job)
        except CRSError as e:
            return Err(e)
        container: Optional[str] = None
        if not req.on_host:
            container = self._container_of(req.sidecar)  # type: ignore[misc]
            self._jobs.add((container, job))

        outer_timeout = (
            timeout_s if req.on_host else timeout_s + self._watchdog_margin_s
        )
        # sem 은 run 스코프 소유(supervise·rc회수 전체를 감싸 fork 빌드에서도 직렬화 보존).
        guard = self._sem if self._sem is not None else contextlib.nullcontext()
        async with guard:
            try:
                out = await supervise_subprocess(
                    self._ssh_argv(remote_cmd),
                    stdin=req.stdin,
                    timeout_s=outer_timeout,
                    kill_grace_s=self._kill_grace_s,
                    workdir=self._workdir,
                    max_output_bytes=self._max_output,
                    sem=None,  # sem 은 run 스코프가 소유
                )
            except Exception as e:  # noqa: BLE001
                return Err(
                    CRSError(
                        f"SshBackend.run failed: {e}",
                        extra={"tool": req.tool_id, "host": self._host},
                    )
                )
            # rc-file fallback(LocalBackend 와 동일 계약, 원격 ssh 경유).
            if container is not None and not out.killed and not out.timed_out:
                rc = await self._recover_rc(container, job, timeout_s)
                if rc is not None:
                    out.returncode = rc
        return Ok(out)

    async def _recover_rc(
        self, container: str, job: str, timeout_s: float
    ) -> Optional[int]:
        """원격 컨테이너 rc 파일에서 실제 exit code 회수(ssh->docker exec, 파일 캡처·PIPE 금지).

        setsid fork/즉시반환으로 원격 docker exec 가 조기반환해도 컨테이너 내부 유계 폴링으로 실제 rc
        확정. 회수 셸 출력은 임시파일로 캡처. 실패 시 None(폴백).
        """
        wait_iters = _rc_wait_iters(
            timeout_s, self._kill_grace_s, self._watchdog_margin_s
        )
        script = _recover_rc_script(job, wait_iters)
        remote = (
            f"{shlex.quote(self._docker)} exec {shlex.quote(container)} "
            f"sh -c {shlex.quote(script)}"
        )
        outer = wait_iters + self._kill_grace_s + self._watchdog_margin_s
        try:
            out = await supervise_subprocess(
                self._ssh_argv(remote),
                stdin=None,
                timeout_s=outer,
                kill_grace_s=self._kill_grace_s,
                workdir=self._workdir,
                max_output_bytes=64,
                sem=None,
            )
        except Exception:  # noqa: BLE001
            return None
        if out.killed or out.timed_out:
            return None
        return _parse_rc(out.stdout)

    async def teardown(self) -> None:
        """원격 각 사이드카를 컨테이너-스코프로 회수(pid1 제외 전 프로세스 sweep, best-effort).

        LocalBackend 와 동일 모델: (container,job) 을 컨테이너로 dedupe -> 원격
        docker exec <container> sh -c '<kill-all-but-pid1 스윕>' 을 컨테이너별 1회, 단일 ssh
        세션에 묶어 실행. 넓은 pkill 금지. sem 획득으로 in-flight run 과 비중첩(적대검증 이슈3.).
        (캠페인 종료 원자 회수의 정본은 원격 라벨 사이드카 docker rm -f — FACT4.)
        """
        grouped: dict[str, list[str]] = {}
        for container, job in self._jobs:
            grouped.setdefault(container, []).append(job)
        self._jobs.clear()
        if not grouped:
            return
        parts: list[str] = []
        for container, jobs in grouped.items():
            script = _reap_all_script(self._kill_grace_s)
            rc_paths = " ".join(shlex.quote(_rc_path(j)) for j in jobs)
            if rc_paths:
                script += f"rm -f {rc_paths} 2>/dev/null\n"  # rc 파일 청소(/tmp 청결)
            reap = f"{shlex.quote(self._docker)} exec {shlex.quote(container)} sh -c {shlex.quote(script)}"
            parts.append(reap)
        remote = " ; ".join(parts)
        argv = self._ssh_argv(remote)
        async with self._sem:  # 직렬 강제: in-flight run 과 스윕 비중첩
            with contextlib.suppress(Exception):
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                # 각 스크립트가 grace 만큼 sleep — 컨테이너 수에 비례해 넉넉히.
                outer = (self._kill_grace_s * 2 + self._watchdog_margin_s) * max(1, len(grouped))
                try:
                    async with asyncio.timeout(outer):
                        await proc.wait()
                except TimeoutError:
                    with contextlib.suppress(Exception):
                        proc.kill()
                        await proc.wait()


__all__ = ["LocalBackend", "SshBackend", "ContainerResolver"]
