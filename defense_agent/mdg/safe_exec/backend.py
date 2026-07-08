"""Backend.run(ExecRequest) — THE ONLY subprocess path (불변식②, Robo Duck R1~R6).

Graph nodes and collectors never spawn processes; they hand an ExecRequest to
Backend.run, which is the sole owner of ``subprocess``. Backend performs the spawn
(secret on stdin, R5) and delegates the R1/R2/R3/R4/R6 teardown discipline to
``safeexec`` (setsid process group, labelled container-scope reap). A
PrioritySemaphore(1) gives 5762/nsenter resource singularity.

Modes:
  - ``mock``  : never spawns; returns synthetic output (unit tests / offline).
  - ``local`` : real subprocess via subprocess.Popen, ONLY when ``allow_live`` is True.

Live state-change is operator-go RESERVED (운영 제약): ``allow_live`` defaults False,
so even a ``local`` backend returns a DRY-RUN result until an operator explicitly flips
it. This is the code-level guard behind the testbed no-actuation constraint.
"""
from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

from . import safeexec


# -- read_only trust-boundary allowlist (security-relevant, NOT advisory) ------- #
#   ``read_only`` gates TWO privileges in Backend.run: the read_only fast-path (a)
#   spawns even when allow_live=False (observation is permitted freely) and (b) skips
#   the pool=1 resource-singularity semaphore. A caller-asserted boolean must therefore
#   be validated against the ACTUAL argv, or a mutating command could smuggle itself past
#   both guards. tcpdump ``-w <file>`` writes a capture file and ``-z <cmd>``/``-G`` run a
#   postrotate command — genuine state changes — and nsenter/docker can wrap any binary.
#   We pin the post-nsenter binary to the known non-mutating observers and reject any
#   write/exec/rotate flag before granting the fast-path.
_READONLY_OBSERVERS = frozenset({"tcpdump", "ss", "docker"})
#   -w/-W/-G/-z: tcpdump file-write, filecount, rotate-seconds, postrotate-exec.
_READONLY_BANNED_FLAGS = ("-w", "-W", "-G", "-z")
#   NOTE (live finding, 2026-07-08): ``ip`` is deliberately NOT here. The recon tun-scan
#   (``nsenter ... ip -4 addr show <iface>``) is OPERATOR-GO RESERVED by design (resolve.py
#   docstring + test_p2_recon.test_resolve_tun_scan_is_operator_go_dry_run) to minimise the
#   netns-entry surface — so UE-pool role_verified requires allow_live. Consequence: the verified
#   decision path (legality-pass -> DROP plan) is NOT observable under allow_live=False; it manifests
#   only under the operator-go allow_live window (same gate as actuation). This is the intended
#   double operator-go gate (recon resolve + actuation).


def _strip_nsenter_prefix(argv: list[str]) -> list[str]:
    """Return the wrapped command after the canonical ``nsenter ... -- <binary> ...``
    prefix. A bare (non-nsenter) argv is returned unchanged; a malformed nsenter with no
    ``--`` terminator yields [] (fails the allowlist below rather than mis-reading argv[0])."""
    if argv and argv[0] == "nsenter":
        if "--" in argv:
            return argv[argv.index("--") + 1:]
        return []
    return list(argv)


def is_read_only_argv(argv: list[str]) -> bool:
    """True iff ``argv`` is a recognized non-mutating observation form. The post-nsenter
    binary must be an allowlisted observer, no write/exec/rotate flag may appear, and
    ``docker`` is narrowed to its read-only ``logs`` subcommand. This is the validation
    behind the ``read_only`` fast-path; a claim that fails here is treated as NOT read_only."""
    body = _strip_nsenter_prefix(argv)
    if not body:
        return False
    binary, rest = body[0], body[1:]
    if binary not in _READONLY_OBSERVERS:
        return False
    for a in rest:
        if any(a == bad or a.startswith(bad) for bad in _READONLY_BANNED_FLAGS):
            return False
    if binary == "docker":                    # only read-only subcommands: `logs` + `inspect`
        # resolve.py stage-1 is "inspect, read-only" (container existence + .State.Pid + cellular
        # IP) — a metadata read, NOT a state change — so recon can resolve pids under allow_live=False
        # (detection path). Mutating docker verbs (run/rm/exec/pause/stop) stay blocked.
        if not rest or rest[0] not in ("logs", "inspect"):
            return False
    return True


@dataclass
class ExecRequest:
    argv: list[str]                          # NO shell string; argv list only
    timeout_s: float = 10.0
    stdin_secret: Optional[str] = None       # R5: secret via stdin, never argv
    label: str = safeexec.LABEL              # R3: container-scope reap label (dah_def)
    revert_cmd: str = ""                     # recorded to ledger before run (G3)
    reversible: bool = True
    read_only: bool = False                  # observation cmds (tcpdump/ss/logs)


@dataclass
class ExecResult:
    ok: bool
    code: int
    stdout: str = ""
    stderr: str = ""
    dry_run: bool = False
    note: str = ""


class PrioritySemaphore:
    """pool=1 for 5762 ss / nsenter target resource singularity (G4)."""
    def __init__(self, permits: int = 1):
        self._sem = threading.BoundedSemaphore(permits)

    def __enter__(self):
        self._sem.acquire()
        return self

    def __exit__(self, *exc):
        self._sem.release()


class Backend:
    """Single owner of subprocess. allow_live defaults False (operator-go 유보).

    mode='local' spawns via subprocess.Popen (R1~R6 teardown); mode='mock' returns
    synthetic output (and honours a scripted stdout table for deterministic tests).
    """

    def __init__(self, allow_live: bool = False, semaphore: Optional[PrioritySemaphore] = None,
                 mode: str = "local", mock_stdout: str = "", mock_table: Optional[dict] = None):
        self.allow_live = allow_live
        self.mode = mode
        self._sem = semaphore or PrioritySemaphore(1)
        self._mock_stdout = mock_stdout
        self._mock_table = mock_table or {}   # {argv-substring: stdout}

    # -- mock -------------------------------------------------------------- #
    def _mock_run(self, req: ExecRequest) -> ExecResult:
        joined = " ".join(req.argv)
        stdout = self._mock_stdout
        for key, val in self._mock_table.items():
            if key in joined:
                stdout = val
                break
        # mock represents synthetic-but-live observation output: dry_run False so
        # collectors parse it. The operational no-actuation guard is allow_live in
        # 'local' mode, not mock.
        return ExecResult(ok=True, code=0, stdout=stdout, dry_run=False,
                          note=f"MOCK: {joined}")

    # -- the single spawn site (R1~R6) ------------------------------------ #
    def _spawn(self, req: ExecRequest) -> ExecResult:
        env = safeexec.child_env(req.label)                 # R3: label the subtree
        popen_kw = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, env=env)
        popen_kw.update(safeexec.session_popen_kwargs())    # R2: setsid process group
        proc = subprocess.Popen(req.argv, **popen_kw)       # the ONLY spawn
        try:
            out, err = proc.communicate(input=req.stdin_secret, timeout=req.timeout_s)  # R5
            return ExecResult(ok=(proc.returncode == 0), code=proc.returncode,
                              stdout=out or "", stderr=err or "")
        except subprocess.TimeoutExpired:                   # R1: hard deadline
            safeexec.kill_group(proc)
            try:
                out, err = proc.communicate(timeout=2.0)
            except Exception:
                out, err = "", ""
            return ExecResult(ok=False, code=124, stdout=out or "", stderr=err or "",
                              note="timeout")
        finally:
            safeexec.reap_proc(proc)                        # R6: always tear down

    # -- run --------------------------------------------------------------- #
    def run(self, req: ExecRequest) -> ExecResult:
        if self.mode == "mock":
            return self._mock_run(req)

        # read_only is a caller-asserted flag; validate it against the actual argv before
        # it is allowed to unlock the fast-path (allow_live bypass + no semaphore). A claim
        # that does not match a recognized observation form (allowlisted observer binary,
        # no write/exec/rotate flag, docker->logs only) is downgraded to a normal state-
        # changing request so it CANNOT skip either guard — closing the unvalidated trust
        # boundary without breaking any real observer (tcpdump/ss/docker-logs all pass).
        read_only = bool(req.read_only) and is_read_only_argv(req.argv)

        # read-only observation (tcpdump/ss/docker logs/:9090) is NOT a state change —
        # RUNBOOK §2 permits it freely. Only state-changing actuation (read_only=False)
        # stays DRY until an operator flips allow_live (operator-go 유보).
        if not self.allow_live and not read_only:
            return ExecResult(
                ok=True, code=0, dry_run=True,
                note=f"DRY-RUN (operator-go 유보): {' '.join(req.argv)}",
            )

        # 관측(read_only=True): 세마포어 미획득 — 경합 없음.
        #   idle air-tap tcpdump가 count 패킷을 기다리며 오래 블로킹해도, pool=1 세마포어를
        #   점유하지 않으므로 그래프 act 노드/타 collector의 집행이 직렬 대기하지 않는다
        #   (성능 경합 버그 수정). teardown/reap(R1·R6)은 _spawn 내부에서 그대로 수행되므로
        #   불변식②(누수-0)는 세마포어와 무관하게 유지된다.
        #   5762 pool=1 의도 무손상: WebProbe의 ss는 read-only 관측이라 5762 소켓 슬롯을
        #   실제로 점유(연결/집행)하지 않는다 — 세마포어 없이도 자원 단일화 대상이 아님.
        if read_only:
            return self._spawn(req)

        # 집행(read_only=False, 또는 read_only 주장이 argv 검증 실패로 강등됨):
        #   nsenter/5762 대상 자원 단일화를 위해 pool=1 세마포어 획득.
        with self._sem:                                     # pool=1
            return self._spawn(req)

    def teardown(self, label: str = safeexec.LABEL) -> list[int]:
        """R4/R6: reap any leftover labelled process in this container.

        Gated ONLY on mode=='mock' (mock never spawns, so nothing to reap). It is
        deliberately NOT gated on allow_live: the default operator-go 유보 backend
        (allow_live=False) still REAL-spawns read_only observers (tcpdump/ss/docker
        logs take the read_only fast-path in run() and hit _spawn even when
        allow_live is False), so a crash can leave labelled orphans in exactly that
        mode. Gating reap on allow_live would disable crash-orphan recovery for the
        primary read-only observation path (감사 P1).

        This is not a protected-asset state change: reap_labelled → iter_labelled_pids
        scans ONLY this container's /proc for our own DAH_DEF_LABEL=dah_def marker and
        os.kill(pid, SIGKILL)s each such pid individually (single-pid semantics, per the
        Python os.kill contract). It can therefore only tear down our own labelled
        subtree — never a testbed/host asset — so it is safe under the no-actuation
        operating constraint.
        """
        if self.mode == "mock":
            return []
        return safeexec.reap_labelled(label)
