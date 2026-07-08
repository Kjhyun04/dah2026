"""safeexec — R1~R6 teardown/reap primitives behind the single subprocess path.

``backend.Backend`` is the sole spawn owner (it imports subprocess and feeds the
secret on stdin — verify_no_fw_subproc / verify_keys pin that). This module holds the
teardown discipline Backend delegates to, so the spawn site stays small and the
reap/label logic is shared and independently testable.

Robo-Duck-derived teardown guarantees (R1~R6):
  R1  hard timeout       — Backend enforces a wall-clock deadline; on expiry it calls
                           ``kill_group`` here to SIGKILL the whole process group.
  R2  session isolation  — ``session_popen_kwargs`` sets start_new_session (setsid) so
                           children share one killable process group.
  R3  labelling          — ``child_env`` stamps DAH_DEF_LABEL=dah_def on every managed
                           unit so orphans are discoverable for scoped reap.
  R4  container-scoped    — ``reap_labelled`` scans ONLY this container's /proc and kills
      reap                 leftover units bearing the label (never host-wide).
  R5  secret hygiene     — secrets go on stdin (Backend), never argv/env.
  R6  idempotent no-leak  — ``reap_proc`` always runs in Backend's finally and is
      teardown              idempotent, so a raised exception still leaks 0 side effects.

POSIX (python:3.12-slim runtime) uses setsid + killpg + /proc scan. On non-POSIX
(local Windows dev) these degrade to best-effort so imports and dry/mock stay runnable;
live actuation is Linux-only.
"""
from __future__ import annotations

import os
import signal
import subprocess

LABEL = "dah_def"                 # R3: container-scope reap label
LABEL_ENV = "DAH_DEF_LABEL"       # env key carrying the label on every managed unit
_IS_POSIX = os.name == "posix"


def child_env(label: str = LABEL, extra: dict | None = None) -> dict:
    """R3: env for a managed child, tagged with the reap label across the subtree."""
    env = dict(os.environ)
    env[LABEL_ENV] = label
    if extra:
        env.update(extra)
    return env


def session_popen_kwargs() -> dict:
    """R2: process-group isolation kwargs so the whole tree is reapable at once."""
    if _IS_POSIX:
        return {"start_new_session": True}
    # Windows dev: new process group so we can signal the tree.  # pragma: no cover
    return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}


def kill_group(proc: "subprocess.Popen") -> None:
    """R1/R2: SIGKILL the whole process group (setsid) so no child survives."""
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
    """R6: idempotent teardown of one managed process — kill group if still alive and
    close pipes to avoid fd leaks. Safe to call in a finally on any code path."""
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
    """R4: scan THIS container's /proc for processes carrying LABEL_ENV=label.

    Container-scoped by construction: a container's /proc only lists its own PID
    namespace, so this never reaches the host. Excludes our own pid. POSIX only.
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
    """R4: kill any leftover labelled process in this container. Returns reaped pids.
    Idempotent (R6) — safe to call repeatedly (boot recovery / watchdog / shutdown)."""
    reaped: list[int] = []
    for pid in iter_labelled_pids(label):
        try:
            os.kill(pid, signal.SIGKILL)                      # pragma: no cover (dev)
            reaped.append(pid)
        except (ProcessLookupError, PermissionError):
            continue
    return reaped
