"""safeexec — 단일 subprocess 경로 뒤의 R1~R6 teardown/reap 프리미티브.

``backend.Backend`` 가 유일한 spawn 소유자다 (subprocess 를 import 하고
비밀을 stdin 으로 넣는다 — verify_no_fw_subproc / verify_keys 가 이를 고정). 이 모듈은
Backend 가 위임하는 teardown discipline 을 담아, spawn 지점을 작게 유지하고
reap/label 로직을 공유·독립 테스트 가능하게 한다.

Robo-Duck 유래 teardown 보장 (R1~R6):
  R1  hard timeout       — Backend 가 wall-clock 데드라인을 강제; 만료 시 여기의
                           ``kill_group`` 를 호출해 전체 프로세스 그룹을 SIGKILL.
  R2  session isolation  — ``session_popen_kwargs`` 가 start_new_session (setsid)을 설정하여
                           자식들이 하나의 죽일 수 있는 프로세스 그룹을 공유하게 한다.
  R3  labelling          — ``child_env`` 가 모든 관리 단위에 DAH_DEF_LABEL=dah_def 를 찍어
                           orphan 을 scoped reap 용으로 발견 가능하게 한다.
  R4  container-scoped    — ``reap_labelled`` 가 오직 이 컨테이너의 /proc 만 스캔하여 라벨을 단
      reap                 잔여 단위를 죽인다 (호스트 전역 절대 아님).
  R5  secret hygiene     — 비밀은 stdin (Backend)으로 가며, argv/env 에는 절대 아니다.
  R6  idempotent no-leak  — ``reap_proc`` 는 항상 Backend 의 finally 에서 실행되며
      teardown              멱등적이므로, 예외가 발생해도 side effect 누수가 0 이다.

POSIX (python:3.12-slim 런타임)는 setsid + killpg + /proc 스캔을 쓴다. 비-POSIX
(로컬 Windows dev)에서는 이들이 best-effort 로 강등되어 import 와 dry/mock 이 실행 가능하게 유지되고;
live 작동은 Linux 전용이다.
"""
from __future__ import annotations

import os
import signal
import subprocess

LABEL = "dah_def"                 # R3: 컨테이너 범위 reap 라벨
LABEL_ENV = "DAH_DEF_LABEL"       # 모든 관리 단위에 라벨을 실어 나르는 env 키
_IS_POSIX = os.name == "posix"


def child_env(label: str = LABEL, extra: dict | None = None) -> dict:
    """R3: 관리 자식용 env, subtree 전반에 reap 라벨을 태깅."""
    env = dict(os.environ)
    env[LABEL_ENV] = label
    if extra:
        env.update(extra)
    return env


def session_popen_kwargs() -> dict:
    """R2: 전체 트리를 한 번에 reap 가능하게 하는 프로세스 그룹 격리 kwargs."""
    if _IS_POSIX:
        return {"start_new_session": True}
    # Windows dev: 트리에 시그널을 보낼 수 있도록 새 프로세스 그룹.  # pragma: no cover
    return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}


def kill_group(proc: "subprocess.Popen") -> None:
    """R1/R2: 자식이 살아남지 않도록 전체 프로세스 그룹 (setsid)을 SIGKILL."""
    try:
        if _IS_POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:                                                # pragma: no cover (dev)
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def reap_proc(proc: "subprocess.Popen") -> None:
    """R6: 관리 프로세스 하나의 멱등 teardown — 아직 살아 있으면 group 을 죽이고
    fd 누수를 막기 위해 파이프를 닫는다. 어떤 코드 경로의 finally 에서도 호출 안전."""
    try:
        if proc.poll() is None:
            kill_group(proc)
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass
    except Exception:
        pass
    for stream in (getattr(proc, "stdin", None), getattr(proc, "stdout", None),
                   getattr(proc, "stderr", None)):
        try:
            if stream is not None:
                stream.close()
        except Exception:
            pass


def iter_labelled_pids(label: str = LABEL) -> list[int]:
    """R4: LABEL_ENV=label 을 지닌 프로세스를 찾아 이 컨테이너의 /proc 를 스캔한다.

    구조적으로 컨테이너 범위: 컨테이너의 /proc 는 자신의 PID
    namespace 만 나열하므로, 이것은 결코 호스트에 도달하지 않는다. 자기 pid 는 제외. POSIX 전용.
    """
    if not _IS_POSIX or not os.path.isdir("/proc"):          # pragma: no cover (dev)
        return []
    me = os.getpid()
    found: list[int] = []
    marker = f"{LABEL_ENV}={label}".encode()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == me:
            continue
        try:
            with open(f"/proc/{pid}/environ", "rb") as fh:
                if marker in fh.read():
                    found.append(pid)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return found


def reap_labelled(label: str = LABEL) -> list[int]:
    """R4: 이 컨테이너의 남은 라벨 프로세스를 모두 죽인다. reap 된 pid 를 반환.
    멱등 (R6) — 반복 호출 안전 (boot recovery / watchdog / shutdown)."""
    reaped: list[int] = []
    for pid in iter_labelled_pids(label):
        try:
            os.kill(pid, signal.SIGKILL)                      # pragma: no cover (dev)
            reaped.append(pid)
        except (ProcessLookupError, PermissionError):
            continue
    return reaped
