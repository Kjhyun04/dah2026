"""verify_leak0 — GATE1 누수-0 하네스 (기동 후 N회 실행하고 종료, 잔존 0).

불변식2. (누수-0 실행) 을 두 축에서 강제한다:

  A. PROCESS 잔존 0 — N회 관리형 exec 사이클 + teardown 후, 이 컨테이너 안에
     라벨(DAH_DEF_LABEL=dah_def) 붙은 프로세스가 0개로 남아야 한다
     (safeexec.iter_labelled_pids() == []). 실제 라이브 spawn 루프는
     allow_live + POSIX 를 요구하며 **operator-go 유보**(운영 제약)이다:
     MDG_OPERATOR_GO=1 이고 POSIX 일 때에만 라이브 루프가 실행되고,
     그 외에는 구조/idempotent-reap 계약만 검사하고 라이브 루프는
     'RESERVED (operator-go)' 로 보고한다. (win32 로컬 dev 는 이 경로.)

  B. SECRET 잔존 0 (PS-3 카나리) — MDG_CANARY_{LLM,OP,HMAC} + sk-ant 카나리를
     상태 문자열 leaf 와 __str__ 이 비밀을 흘리는 객체에 주입한 뒤, 드라이버
     녹화 스크럽 경로(redact + 직렬화 최종 스크럽, PP-2 default=str 봉인)를
     통과시키고 방출된 JSONL 라인에 카나리가 0개 남는지 검사한다.

실행: python mdg/verify/verify_leak0.py
라이브 상태변경(A 라이브 루프)은 운영 제약상 operator-go 유보. 로컬에서 실행
가능한 B(카나리 스크럽) + A 구조/idempotent 계약은 즉시 검사한다.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.verify._util import Report, run  # noqa: E402

_CANARIES = ["MDG_CANARY_LLM", "MDG_CANARY_OP", "MDG_CANARY_HMAC",
             "sk-ant-CANARYcanary01234567"]
_POSIX = os.name == "posix"
_OPERATOR_GO = os.environ.get("MDG_OPERATOR_GO") == "1"


class _LeakyStr:
    """default=str 우회 경로 검증용: __str__ 이 카나리를 흘린다(PP-2)."""
    def __str__(self) -> str:  # pragma: no cover - exercised via json default=str
        return "leaked=MDG_CANARY_OP token=sk-ant-CANARYcanary01234567"


# --------------------------------------------------------------------------- #
# B. SECRET 잔존 0 (로컬 실행 가능)
# --------------------------------------------------------------------------- #
def _check_secret_leak(rep: Report) -> None:
    from mdg.core.driver import _scrub_str, redact

    # B1: redact() 가 중첩 dict/list/str leaf 의 카나리를 모두 스크럽한다.
    nested = {
        "config_version": "v1",
        "note": "api_key=sk-ant-CANARYcanary01234567 present",
        "list": ["ok", "token: MDG_CANARY_LLM", {"deep": "hmac=MDG_CANARY_HMAC"}],
        "op": "operator_token = MDG_CANARY_OP",
    }
    scrubbed = json.dumps(redact(nested), ensure_ascii=False)
    for c in _CANARIES:
        rep.check(c not in scrubbed, f"B1 redact(): 카나리 '{c}' 가 스크럽 후 잔존")

    # B2: 직렬화 최종 스크럽이 default=str 우회(객체 __str__ 누수)를 봉인한다(PP-2).
    payload = {"node_x": {"evidence": _LeakyStr(), "ok": "fine"}}
    line = _scrub_str(json.dumps(payload, ensure_ascii=False, default=str))
    for c in ("MDG_CANARY_OP", "sk-ant-CANARYcanary01234567"):
        rep.check(c not in line, f"B2 default=str 우회: 카나리 '{c}' 가 최종 스크럽 후 잔존")
    # 스크럽이 JSON 유효성을 깨지 않는다(따옴표/백슬래시 미생성).
    try:
        json.loads(line)
        rep.check(True, "B2 스크럽 후 JSON 유효")
    except Exception as exc:  # pragma: no cover
        rep.check(False, f"B2 스크럽이 JSON 유효성 파괴: {exc}")

    # B3: to_record 화이트리스트가 카나리를 담은 미선언 키를 드롭한다(default-deny).
    from mdg.core.state import to_record
    st = {"config_version": "v1", "secret_leak": "MDG_CANARY_HMAC", "tick_i": 0}
    rec = to_record(st)  # type: ignore[arg-type]
    rep.check("secret_leak" not in rec,
              "B3 to_record: 미선언 키(secret_leak) 가 투영 후에도 잔존")
    rep.check("MDG_CANARY_HMAC" not in json.dumps(rec, ensure_ascii=False),
              "B3 to_record: 미선언 키의 카나리가 투영을 통과")


# --------------------------------------------------------------------------- #
# A. PROCESS 잔존 0
# --------------------------------------------------------------------------- #
def _check_process_residue(rep: Report) -> None:
    from mdg.safe_exec import safeexec

    # A0 (구조·항상 실행): reap 는 idempotent 이고 no-op 시 [] 를 돌려주며 raise 0.
    r1 = safeexec.reap_labelled("no-such-label-xyz")
    r2 = safeexec.reap_labelled("no-such-label-xyz")
    rep.check(isinstance(r1, list) and r1 == [], "A0 reap_labelled no-op 이 [] 아님")
    rep.check(isinstance(r2, list) and r2 == [], "A0 reap_labelled 이 idempotent 아님(2회차)")
    rep.check(isinstance(safeexec.iter_labelled_pids("no-such-label-xyz"), list),
              "A0 iter_labelled_pids 가 list 미반환")

    # A2 (구조·항상 실행): Backend.teardown 은 allow_live 가 아니라 mode 로만 게이트된다.
    #   감사 P1 회귀 가드 — read_only 관측은 allow_live=False(기본 operator-go 유보) 에서도
    #   실제로 spawn 하므로(run() 의 read_only fast-path 가 _spawn 을 탄다), 그 모드에서 크래시-고아
    #   회수 primitive 가 켜져 있어야 한다. 예전 'not allow_live -> []' 가드는 바로 이 기본
    #   관측 경로의 회수를 꺼버렸다. reap_labelled 를 스파이로 감싸 호출 여부만 확인한다
    #   (자기 dah_def 라벨 서브트리만 os.kill(pid, SIGKILL) — 단일-pid, 보호자산 무변경).
    from mdg.safe_exec.backend import Backend
    _orig_reap = safeexec.reap_labelled
    _reap_calls: list[str] = []

    def _spy_reap(label: str = safeexec.LABEL):
        _reap_calls.append(label)
        return _orig_reap(label)

    safeexec.reap_labelled = _spy_reap  # type: ignore[assignment]
    try:
        # mock 은 spawn 0 이므로 teardown 은 reap 를 호출하지 않고 [] 반환(게이트 유지).
        rep.check(Backend(mode="mock", allow_live=False).teardown() == [],
                  "A2 mock teardown 이 [] 미반환")
        rep.check(_reap_calls == [], "A2 mock teardown 이 reap_labelled 를 호출(게이트 실패)")
        # 핵심: allow_live=False local 이 실제로 reap 를 통과시켜야 한다(감사 P1 fix).
        Backend(mode="local", allow_live=False).teardown()
        rep.check(_reap_calls == [safeexec.LABEL],
                  "A2 allow_live=False local teardown 이 reap_labelled 를 호출하지 않음 "
                  "(감사 P1 회귀: 기본 관측모드에서 크래시-고아 회수 primitive 꺼짐)")
        # allow_live=True 도 당연히 통과(대칭).
        Backend(mode="local", allow_live=True).teardown()
        rep.check(_reap_calls == [safeexec.LABEL, safeexec.LABEL],
                  "A2 allow_live=True local teardown 이 reap_labelled 미호출")
    finally:
        safeexec.reap_labelled = _orig_reap  # type: ignore[assignment]

    if not (_POSIX and _OPERATOR_GO):
        # 운영 제약: 라이브 spawn 은 operator-go 유보. 여기서는 실행하지 않는다.
        why = "non-POSIX (win32 dev)" if not _POSIX else "MDG_OPERATOR_GO!=1"
        print(f"   [RESERVED operator-go] A 라이브 잔존0 루프 미실행 ({why}). "
              f"라이브 검증은 POSIX 컨테이너에서 MDG_OPERATOR_GO=1 로 실집행.")
        return

    # A1 (operator-go): 라이브 spawn N회 후 teardown 하면 라벨 프로세스 0 잔존.
    from mdg.safe_exec.backend import Backend, ExecRequest
    be = Backend(mode="local", allow_live=True)
    n_cycles = int(os.environ.get("MDG_LEAK0_N", "5"))
    for _ in range(n_cycles):
        # 짧게 사는 라벨 프로세스: 정상 종료 경로에서 reap 가 fd/그룹 정리.
        be.run(ExecRequest(argv=[sys.executable, "-c", "pass"], timeout_s=10))
    leftover_before = safeexec.iter_labelled_pids()
    reaped = be.teardown()
    leftover_after = safeexec.iter_labelled_pids()
    rep.check(leftover_after == [],
              f"A1 종료 후 라벨 프로세스 잔존 {leftover_after} (reaped={reaped}, "
              f"before={leftover_before})")

    # A1b (operator-go): allow_live=False + read_only 관측 spawn 잔존경로 (감사 P1 fix).
    #   기본 operator-go 유보 백엔드(allow_live=False)여도 read_only 관측 argv 는 DRY 가
    #   아니라 실제 _spawn 한다. 그 경로에서 spawn 후 종료하고 teardown 한 뒤 라벨 잔존 0 을 강제한다.
    import shutil
    if shutil.which("ss"):
        from mdg.safe_exec.backend import Backend, ExecRequest  # noqa: F811
        be0 = Backend(mode="local", allow_live=False)
        res = be0.run(ExecRequest(argv=["ss"], read_only=True, timeout_s=10))
        rep.check(not res.dry_run,
                  "A1b allow_live=False read_only 관측이 DRY 로 강등됨(실 spawn 이어야 함)")
        reaped0 = be0.teardown()
        rep.check(safeexec.iter_labelled_pids() == [],
                  f"A1b allow_live=False read_only spawn 후 라벨 잔존(reaped={reaped0})")
    else:
        print("   [SKIP] A1b: 'ss' 미설치 — allow_live=False read_only spawn 경로 미검증.")


def _check() -> Report:
    rep = Report("verify_leak0")
    _check_secret_leak(rep)
    _check_process_residue(rep)
    return rep


if __name__ == "__main__":
    run(_check)
