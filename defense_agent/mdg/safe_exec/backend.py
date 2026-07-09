"""Backend.run(ExecRequest) — 유일한 subprocess 경로(불변식2., Robo Duck R1~R6).

Graph node와 collector는 절대 프로세스를 spawn하지 않는다; ExecRequest를
``subprocess``의 유일한 소유자인 Backend.run에 넘긴다. Backend가 spawn을 수행하고
(비밀은 stdin으로, R5) R1/R2/R3/R4/R6 teardown 규율을 ``safeexec``에 위임한다
(setsid 프로세스 그룹, 라벨된 container-scope reap).
PrioritySemaphore(1)이 nsenter 자원 단일화를 제공한다.

모드:
  - ``mock``  : 절대 spawn하지 않음; 합성 출력을 반환(단위 테스트 / 오프라인).
  - ``local`` : ``allow_live``가 True일 때만, subprocess.Popen을 통한 실제 subprocess.

Live 상태 변경은 operator-go 유보다(운영 제약): ``allow_live``는 기본 False이므로,
``local`` backend라도 운영자가 명시적으로 뒤집기 전까지 DRY-RUN 결과를 반환한다.
이것이 테스트베드 무집행 제약 뒤의 코드 수준 가드다.
"""
from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

from . import safeexec


# -- read_only trust-boundary 허용목록 (보안 관련, 권고 아님) ------- #
#   ``read_only``는 Backend.run에서 두 가지 권한을 통제한다: read_only fast-path는 (a)
#   allow_live=False일 때도 spawn하며(관측은 자유롭게 허용) (b) pool=1 자원-단일화
#   세마포어를 건너뛴다. 따라서 호출자가 주장한 boolean은 실제 argv에 대해
#   검증되어야 하며, 그렇지 않으면 변경 명령이 두 가드를 몰래 통과할 수 있다. tcpdump
#   ``-w <file>``은 캡처 파일을 쓰고 ``-z <cmd>``/``-G``는 postrotate 명령을 실행한다
#   — 진짜 상태 변경 — 그리고 nsenter/docker는 임의 바이너리를 감쌀 수 있다.
#   post-nsenter 바이너리를 알려진 비변경 관측기로 고정하고 fast-path를 허용하기 전에
#   모든 write/exec/rotate 플래그를 거부한다.
_READONLY_OBSERVERS = frozenset({"tcpdump", "ss", "docker", "iptables"})
#   -w/-W/-G/-z: tcpdump 파일쓰기, 파일개수, rotate 초, postrotate 실행.
_READONLY_BANNED_FLAGS = ("-w", "-W", "-G", "-z")
#   NOTE (live finding, 2026-07-08): ``ip``는 의도적으로 여기 없다. recon tun-scan
#   (``nsenter ... ip -4 addr show <iface>``)은 netns-entry 표면을 최소화하기 위해 설계상
#   OPERATOR-GO 유보다(resolve.py docstring + test_p2_recon.test_resolve_tun_scan_is_operator_go_dry_run)
#   — 그래서 UE-pool role_verified는 allow_live를 요구한다. 결과: 검증된
#   결정 경로(legality-pass -> DROP plan)는 allow_live=False에서 관측되지 않는다; 그것은
#   operator-go allow_live 창(집행과 동일한 게이트)에서만 나타난다. 이것이 의도된
#   이중 operator-go 게이트(recon resolve + 집행)다.


def _strip_nsenter_prefix(argv: list[str]) -> list[str]:
    """canonical ``nsenter ... -- <binary> ...`` 접두 뒤의 감싼 명령을 반환한다.
    맨(비-nsenter) argv는 그대로 반환된다; ``--`` 종결자가 없는 잘못된 nsenter는
    []를 낸다(argv[0]을 잘못 읽는 대신 아래 허용목록을 실패시킴)."""
    if argv and argv[0] == "nsenter":
        if "--" in argv:
            return argv[argv.index("--") + 1:]
        return []
    return list(argv)


def is_read_only_argv(argv: list[str]) -> bool:
    """``argv``가 인식된 비변경 관측 형태일 때만 True. post-nsenter
    바이너리는 허용목록의 관측기여야 하고, write/exec/rotate 플래그가 나타나선 안 되며,
    ``docker``는 read-only ``logs`` 하위 명령으로 좁혀진다. 이것이 ``read_only`` fast-path
    뒤의 검증이다; 여기서 실패하는 주장은 read_only가 아닌 것으로 취급된다."""
    body = _strip_nsenter_prefix(argv)
    if not body:
        return False
    binary, rest = body[0], body[1:]
    if binary not in _READONLY_OBSERVERS:
        return False
    for a in rest:
        if any(a == bad or a.startswith(bad) for bad in _READONLY_BANNED_FLAGS):
            return False
    if binary == "docker":                    # read-only 하위 명령만: `logs` + `inspect`
        # resolve.py stage-1은 "inspect, read-only"다(container 존재 + .State.Pid + cellular
        # IP) — 상태 변경이 아닌 메타데이터 읽기 — 그래서 recon은 allow_live=False에서 pid를 해결할 수 있다
        # (탐지 경로). 변경성 docker 동사(run/rm/exec/pause/stop)는 차단된 채로 유지된다.
        if not rest or rest[0] not in ("logs", "inspect"):
            return False
    if binary == "iptables":                  # read-only 나열만(-L/-S/-C); 변경 없음
        # effect-confirm 의 INPUT DROP 규칙 존재 읽기(`iptables -w -S INPUT`). 모든
        # 변경성 동사를 거부한다 — long form 또는 command 문자를 포함한 short cluster
        # (A/I/D/R/F/X/N/P/Z/E, -Z counter-zero 포함) — 그래서 이 read-only fast-path는 결코
        # 규칙을 설치/flush/zero할 수 없다; 그리고 최소 하나의 나열 동사(-L/-S/-C)를 요구한다.
        # 분리형(-n -v -x -L)과 결합형(-nvxL) short-flag 형태를 모두 처리한다.
        _MUT_LONG = {"--append", "--insert", "--delete", "--replace", "--flush",
                     "--delete-chain", "--new-chain", "--policy", "--zero", "--rename-chain"}
        _MUT_LETTERS, _LIST_LETTERS = set("AIDRFXNPZE"), set("LSC")
        listing = False
        for a in rest:
            if a in _MUT_LONG:
                return False
            if a in ("--list", "--list-rules", "--check"):
                listing = True
            elif a.startswith("-") and not a.startswith("--"):
                cluster = set(a[1:])
                if cluster & _MUT_LETTERS:
                    return False
                if cluster & _LIST_LETTERS:
                    listing = True
        if not listing:
            return False
    return True


@dataclass
class ExecRequest:
    argv: list[str]                          # shell 문자열 없음; argv 리스트만
    timeout_s: float = 10.0
    stdin_secret: Optional[str] = None       # R5: 비밀은 stdin으로, 절대 argv 아님
    label: str = safeexec.LABEL              # R3: container-scope reap 라벨(dah_def)
    revert_cmd: str = ""                     # run 전에 ledger에 기록(G3)
    reversible: bool = True
    read_only: bool = False                  # 관측 명령(tcpdump/ss/logs)


@dataclass
class ExecResult:
    ok: bool
    code: int
    stdout: str = ""
    stderr: str = ""
    dry_run: bool = False
    note: str = ""


class PrioritySemaphore:
    """nsenter 대상 자원 단일화를 위한 pool=1 (G4)."""
    def __init__(self, permits: int = 1):
        self._sem = threading.BoundedSemaphore(permits)

    def __enter__(self):
        self._sem.acquire()
        return self

    def __exit__(self, *exc):
        self._sem.release()


class Backend:
    """subprocess의 단일 소유자. allow_live는 기본 False(operator-go 유보).

    mode='local'은 subprocess.Popen으로 spawn한다(R1~R6 teardown); mode='mock'은
    합성 출력을 반환한다(그리고 결정론적 테스트를 위해 스크립트된 stdout 테이블을 따른다).
    """

    def __init__(self, allow_live: bool = False, semaphore: Optional[PrioritySemaphore] = None,
                 mode: str = "local", mock_stdout: str = "", mock_table: Optional[dict] = None):
        self.allow_live = allow_live
        self.mode = mode
        self._sem = semaphore or PrioritySemaphore(1)
        self._mock_stdout = mock_stdout
        self._mock_table = mock_table or {}   # {argv-부분문자열: stdout}

    # -- mock -------------------------------------------------------------- #
    def _mock_run(self, req: ExecRequest) -> ExecResult:
        joined = " ".join(req.argv)
        stdout = self._mock_stdout
        for key, val in self._mock_table.items():
            if key in joined:
                stdout = val
                break
        # mock은 합성이지만 live인 관측 출력을 나타낸다: dry_run False이므로
        # collector가 파싱한다. 운영상 무집행 가드는 'local' 모드의 allow_live이지
        # mock이 아니다.
        return ExecResult(ok=True, code=0, stdout=stdout, dry_run=False,
                          note=f"MOCK: {joined}")

    # -- 유일한 spawn 지점 (R1~R6) ------------------------------------ #
    def _spawn(self, req: ExecRequest) -> ExecResult:
        env = safeexec.child_env(req.label)                 # R3: 서브트리에 라벨
        popen_kw = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, env=env)
        popen_kw.update(safeexec.session_popen_kwargs())    # R2: setsid 프로세스 그룹
        proc = subprocess.Popen(req.argv, **popen_kw)       # 유일한 spawn
        try:
            out, err = proc.communicate(input=req.stdin_secret, timeout=req.timeout_s)  # R5
            return ExecResult(ok=(proc.returncode == 0), code=proc.returncode,
                              stdout=out or "", stderr=err or "")
        except subprocess.TimeoutExpired:                   # R1: 하드 데드라인
            safeexec.kill_group(proc)
            try:
                out, err = proc.communicate(timeout=2.0)
            except Exception:
                out, err = "", ""
            return ExecResult(ok=False, code=124, stdout=out or "", stderr=err or "",
                              note="timeout")
        finally:
            safeexec.reap_proc(proc)                        # R6: 항상 teardown

    # -- run --------------------------------------------------------------- #
    def run(self, req: ExecRequest) -> ExecResult:
        if self.mode == "mock":
            return self._mock_run(req)

        # read_only는 호출자가 주장한 플래그다; fast-path(allow_live 우회 + 세마포어 없음)를
        # 열도록 허용하기 전에 실제 argv에 대해 검증한다. 인식된 관측 형태(허용목록 관측기
        # 바이너리, write/exec/rotate 플래그 없음, docker->logs만)와 일치하지 않는 주장은
        # 일반 상태 변경 요청으로 강등되어 어느 가드도 건너뛸 수 없다 — 실제 관측기
        # (tcpdump/ss/docker-logs 모두 통과)를 깨지 않으면서 미검증 신뢰
        # 경계를 닫는다.
        read_only = bool(req.read_only) and is_read_only_argv(req.argv)

        # read-only 관측(tcpdump/ss/docker logs/:9090)은 상태 변경이 아니다 —
        # RUNBOOK §2가 자유롭게 허용한다. 상태 변경 집행(read_only=False)만
        # 운영자가 allow_live를 뒤집기 전까지 DRY로 유지된다(operator-go 유보).
        if not self.allow_live and not read_only:
            return ExecResult(
                ok=True, code=0, dry_run=True,
                note=f"DRY-RUN (operator-go 유보): {' '.join(req.argv)}",
            )

        # 관측(read_only=True): 세마포어 미획득 — 경합 없음.
        #   idle air-tap tcpdump가 count 패킷을 기다리며 오래 블로킹해도, pool=1 세마포어를
        #   점유하지 않으므로 그래프 act 노드/타 collector의 집행이 직렬 대기하지 않는다
        #   (성능 경합 버그 수정). teardown/reap(R1·R6)은 _spawn 내부에서 그대로 수행되므로
        # 불변식2.(누수-0)는 세마포어와 무관하게 유지된다.
        #   read-only 관측은 소켓 슬롯을 실제로 점유(연결/집행)하지 않으므로,
        #   세마포어 없이도 자원 단일화 대상이 아니다.
        if read_only:
            return self._spawn(req)

        # 집행(read_only=False, 또는 read_only 주장이 argv 검증 실패로 강등됨):
        #   nsenter 대상 자원 단일화를 위해 pool=1 세마포어 획득.
        with self._sem:                                     # pool=1
            return self._spawn(req)

    def teardown(self, label: str = safeexec.LABEL) -> list[int]:
        """R4/R6: 이 container에 남은 라벨된 프로세스를 reap한다.

        오직 mode=='mock'에서만 게이트된다(mock은 절대 spawn하지 않으므로 reap할 것 없음).
        의도적으로 allow_live에는 게이트되지 않는다: 기본 operator-go 유보 backend
        (allow_live=False)도 read_only 관측기를 실제로 spawn한다(tcpdump/ss/docker
        logs는 run()에서 read_only fast-path를 타고 allow_live가 False여도
        _spawn에 도달), 그래서 크래시가 바로 그 모드에서 라벨된 고아를 남길 수 있다.
        reap를 allow_live에 게이트하면 주된 read-only 관측 경로의 크래시-고아 복구가
        비활성화된다(감사 P1).

        이것은 보호 자산 상태 변경이 아니다: reap_labelled는 iter_labelled_pids를 호출하고
        오직 이 container의 /proc만 스캔해 우리 자신의 DAH_DEF_LABEL=dah_def 마커를 찾아
        각 pid를 개별적으로 os.kill(pid, SIGKILL)한다(single-pid 시맨틱, Python os.kill
        계약에 따름). 따라서 오직 우리 자신의 라벨된 서브트리만 teardown할 수 있고 —
        테스트베드/호스트 자산은 절대 아니다 — 그래서 무집행 운영 제약 하에서 안전하다.
        """
        if self.mode == "mock":
            return []
        return safeexec.reap_labelled(label)
