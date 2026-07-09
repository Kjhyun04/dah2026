"""signer_shim — operator-gate 토큰 바인딩 (PS-9) + KEY-FREE signed-mode emitter (P3-Q1 / C-2).

C-2 SoD 해소 (locked): MDG 는 어떤 경로에서도 uplink-signing 키를 보유하지 않는다. 거짓 전제 —
"operator-gate 는 signing 키와 같은 곳에 있어야 한다" — 는 폐기된다: ``uav_proxy`` 는 이미
드론 측에서 uplink signing 을 강제하고 ``gcs_c2`` 는 이미 자기 키로 서명한다. 따라서
MDG 의 자율 (act) 경로는 signing 키가 결코 필요 없다 (유일한 AUTO 대응은 netns
DROP). 여기의 operator-gate 는 서명이 아니라 인가 토큰을 발급한다.

이 모듈은 두 가지를 제공한다:

  1. 명령 결속 OperatorRequest (PS-9). 토큰은
     ``(decision_id, command_digest, nonce, expiry)`` 에 대한 HMAC 이다 — 그래서 포착된 승인은
     다른 명령을 인가할 수 없다 (그 command_digest 가 다르므로 HMAC 이 더 이상 검증되지 않음). nonce 는
     단일 사용이고 issue/consume 타임스탬프는 단조 증가 (replay + 연속성).

  2. KEY-FREE signed-mode emitter. ``emit_signed`` 는 어떤 signing-key
     경로도 결코 열거나 참조하지 않는다: allow_live=False 에서는 오직 command_digest (토큰 재료)만
     계산; live 승격은 인증된 채널로 gcs_c2 out-of-band signing 엔드포인트 (operator-go 유보)에
     위임한다 — 키 재장착은 금지 (E11 non-proliferation).

Secret hygiene (PS-3 / PS-5 #3): operator-gate HMAC 키는 오직 이 모듈의 프로세스
메모리에만 존재한다 — MDGState, replay JSONL, checkpointer 에는 절대 아니다. 이는
uplink-signing 키와 별개의 비밀이다. signing-key 경로 리터럴도, 키 파일 읽기도 여기 나타나지 않는다 (emitter 는
정적으로 key-free — verify_signer_no_keyopen).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import warnings
from dataclasses import dataclass, field
from typing import Optional

from .backend import ExecRequest  # 단일 spawn 소유자 request 타입 (불변식2.); 여기 subprocess 없음

# --- key-free emitter 바인딩: SoD 계약을 한곳에 (load-bearing 주석) --------- #
# MDG 는 실제 서명을 이미 키를 보유한 컨테이너에 위임한다. delegate 엔드포인트는
# 명명하되 키 경로는 절대 아니다 — emitter 는 key-free 로 유지되어야 한다.
GCS_SIGN_DELEGATE = "gcs_c2"          # out-of-band signer (이미 자기 키 보유)
# LIVE 검증된 위임 경로 (2026-07-09): 회복은 독립 sender 를 exec 하는 게 아니라 TRIGGER FILE 을
# 씀으로써 gcs_c2 에 위임된다. gcs_c2 내부에서 ``gcs.py`` 가 SITL signing 링크의 유일한 소유자다
# (그것만이 udpin:14550 소켓을 보유하며 자기 in-container 키로 setup_signing(sign_outgoing=
# True) 를 했다). 두 번째 프로세스는 그 링크에서 텔레메트리를 받거나 emit 할 수 없으므로, 독립
# sender (구 assets/gcs_signed_correct.py 방식)는 작동하지 않는다. 대신 gcs.py 가
# 매 루프마다 ``GCS_TRIGGER_FILE`` 를 폴링; 존재하면 "<MODE> <ALT>" 를 읽어 자기 링크로 SIGNED
# set_mode(GUIDED)+arm+takeoff(alt) 를 발행한 뒤 파일을 삭제한다. 따라서 MDG 의 위임은
# "트리거를 기록"이지 결코 "signer 를 실행"이 아니다: 이 모듈은 여전히 키 경로를 명명하지 않고
# 파일을 열지 않는다 (verify_signer_no_keyopen); 서명은 전적으로 gcs_c2 안에 머문다 (E11).
GCS_TRIGGER_FILE = "/tmp/mdg_correct"  # gcs_c2 내부 gcs.py 가 폴링하는 회복 트리거 (MDG 가 씀)
_RECOVERY_MODE = "GUIDED"             # 30 m 재배치를 수락하는 비행 모드 (S2 복귀)
_RECOVERY_ALT_M = 30                  # home/hover 상대 고도 (arducopter --home=...,30)
# TRIGGER-FILE 쓰기를 위한 Backend spawn hard 데드라인 (R1). 이 spawn 은 오직
# ``docker exec gcs_c2 sh -c 'printf "%s %s" "$1" "$2" > /tmp/mdg_correct' sh <MODE> <ALT>`` 만 실행한다 — 거의 즉각적인 메타데이터
# 쓰기 — 따라서 이 데드라인은 오직 멈춘 ``docker exec`` (daemon / IO stall)만 제한하며, 어떤 flight
# 시퀀스도 아니다. 실제 signed 작동은 gcs.py 의 폴링 루프 안에서 비동기로 일어나며
# 이 데드라인과 분리되어 있다 (결코 이에 의해 잘리지 않음). 30s 는 바쁜 docker
# daemon 에 충분한 여유를 주면서도 진짜 멈춘 spawn 은 SIGKILL 한다.
_DELEGATE_TIMEOUT_S = 30.0


def _canonical(*parts: object) -> bytes:
    """digest/HMAC 용 결정론적 canonical 바이트 결합 (순서 고정, NUL 구분)."""
    return b"\x00".join(str(p).encode("utf-8") for p in parts)


def command_digest(intent) -> str:
    """명령의 식별 필드에 대한 sha256 hex (KEY-FREE — 비밀 미개입).

    decision_id|rule|tool_id|config_version|sorted(params)|target|target_kind|enforce_at 를 결속한다.
    서로 다른 두 명령 (또는 다른 source 또는 강제 selector 로 스코프된 동일 명령,
    P4-Q1/P4-2)은 서로 다른 digest 를 낳으므로, 하나를 위해 발행된 포착 승인은 다른 것에 대해
    검증될 수 없다 — operator 승인은 (명령, source, 강제 chokepoint)로 스코프된다. (dispatch 가
    해석한 live src_ip 바인딩은 operator-go 유보: src_ip 는 오직
    AUTO netns-DROP 경로에서만 해석되며, escalate 에서는 아니다.)
    """
    params = getattr(intent, "params", None) or {}
    if isinstance(params, dict):
        params_repr = ";".join(f"{k}={params[k]}" for k in sorted(params))
    else:
        params_repr = str(params)
    blob = _canonical(
        getattr(intent, "decision_id", ""),
        getattr(intent, "rule", ""),
        getattr(intent, "tool_id", ""),
        getattr(intent, "config_version", ""),
        params_repr,
        getattr(intent, "target", ""),
        getattr(intent, "target_kind", ""),
        getattr(intent, "enforce_at", ""),
    )
    return hashlib.sha256(blob).hexdigest()


@dataclass
class OperatorRequest:
    """operator 가 승인하는 명령 결속 request (비밀 아님; ledger 로 감)."""
    decision_id: str
    command_digest: str
    nonce: str
    expiry: float          # 절대 데드라인 (issued_ts + ttl_s)
    issued_ts: float


class OperatorGate:
    """명령 결속 operator 승인을 발급/검증한다 (PS-9). HMAC 키를 오직 프로세스
    메모리에만 보유한다 (State 에는 절대 아님). nonce 단일 사용 + 단조 타임스탬프가 replay 를 막는다.

    KEY BOOTSTRAP (P4-Q2, locked): ``key=None`` 은 정상 MDG-runtime 자세이지,
    강등 모드가 아니다. 자율 경로 (escalate)는 오직 ``issue()`` (key-free)만 호출하므로, MDG
    프로세스는 승인 비밀이 필요 없다 — 침해된 MDG 는 그때
    self-approval 을 위조할 재료가 없다 (sign()/verify() 가 ``self._key`` 를 공유: verify 가능 == 위조 가능,
    따라서 MDG 안에 키를 두면 MDG 가 self-approve 하여 PS-9 결속 전체를 우회할 수 있음).
    따라서 key=None 하에서 ``verify()`` 가 fail-closed 를 반환하는 것은 의도된 계약이지
    (구조적 "runtime 은 self-approve 할 수 없음"), 버그가 아니다.

    실제 키의 프로비저닝은 OUT-OF-BAND 이며 operator/verifier 신뢰 도메인에 존재한다
    (tmpfs 0400 비밀 파일, operator-go 유보, PS-5) — MDG 를 통해 흐르지 않는다. ``key`` 는
    그 verifier-도메인 배포나 단위 테스트를 위해 주입될 수 있다. env 폴백
    ``MDG_OPERATOR_GATE_KEY`` 는 DEV/replay 전용 (``docker inspect`` Config.Env,
    즉 PS-1 누수면으로 노출됨)이며 경고를 낸다; 프로덕션 키는 결코 env 로 도착하지 않는다.
    """

    _ENV_KEY = "MDG_OPERATOR_GATE_KEY"

    def __init__(self, key: Optional[bytes] = None, clock=None, ledger=None):
        if key is None:
            env = os.environ.get(self._ENV_KEY)
            if env:
                # DEV/replay 전용 — env 는 `docker inspect` Config.Env 에 보임 (PS-1 면).
                # 프로덕션은 operator/verifier 도메인의 tmpfs 0400 비밀로 프로비저닝
                # (operator-go 유보, PS-5); MDG runtime 은 key-free 로 유지 (key=None).
                warnings.warn(
                    "OperatorGate key read from env MDG_OPERATOR_GATE_KEY (DEV/replay only; "
                    "docker inspect exposes Config.Env). Production provisions the key via a "
                    "tmpfs 0400 secret in the operator/verifier domain, not MDG env (PS-5).",
                    stacklevel=2,
                )
                key = env.encode("utf-8")
        self._key: Optional[bytes] = key            # 프로세스 메모리 전용, State 에는 절대 아님 (PS-3)
        self._clock = clock
        # 비밀 없는 operator-ledger 가 주입되면 PS-9 anti-replay 가 durable 하다 (P4-Q3):
        # 토큰은 결코 영속되지 않고; 오직 consumed-nonce 집합만 리부트를 넘겨 살아남아
        # 포착됐지만 만료되지 않은 토큰이 크래시 후 replay 될 수 없게 한다.
        self._ledger = ledger
        seed = set()
        if ledger is not None:
            try:
                seed = set(ledger.recover_on_boot())
            except Exception:
                seed = set()
        self._seen_nonces: set[str] = seed           # 단일 사용 강제 (ledger 있으면 durable)
        self._last_issue_ts: float = 0.0             # 단조 issue 연속성
        self._last_consume_ts: float = 0.0           # 단조 consume 연속성

    def _now(self, now: Optional[float] = None) -> float:
        if now is not None:
            return float(now)
        if self._clock is not None:
            return float(self._clock.now())
        return time.time()

    # -- issue (KEY-FREE: request 구성에 키 불필요) --------------- #
    def issue(self, intent, *, nonce: str, ttl_s: float, now: Optional[float] = None,
              digest: Optional[str] = None) -> OperatorRequest:
        """명령 결속 OperatorRequest 를 발행한다. 타임스탬프 연속성: issue ts 는 단조가 되도록
        clamp 된다 (지난 issue 보다 결코 이르지 않음), 그래서 낡은 시계가 시퀀스를 되돌릴 수 없다.
        """
        t = self._now(now)
        if t < self._last_issue_ts:                  # 연속성: 되돌림 없음
            t = self._last_issue_ts
        self._last_issue_ts = t
        dg = digest if digest is not None else command_digest(intent)
        req = OperatorRequest(
            decision_id=getattr(intent, "decision_id", ""),
            command_digest=dg, nonce=nonce, expiry=t + float(ttl_s), issued_ts=t,
        )
        # P4-Q3: nonce 라이프사이클을 durable 하게 발행 (ISSUED 영수증 — 비밀 없음, 토큰 없음).
        self._record(req, verdict="ISSUED", consumed_ts=None)
        return req

    # -- durable 비밀 없는 영수증 (P4-Q3; 토큰은 결코 영속되지 않음) ----- #
    def _record(self, req: OperatorRequest, *, verdict: str, consumed_ts) -> None:
        if self._ledger is None:
            return
        try:
            self._ledger.record(decision_id=req.decision_id, command_digest=req.command_digest,
                                 nonce=req.nonce, expiry=req.expiry, verdict=verdict,
                                 issued_ts=req.issued_ts, consumed_ts=consumed_ts)
        except Exception:
            # ledger 쓰기가 gate 를 크래시시켜선 안 됨; anti-replay 는 이번 실행 메모리에서 여전히 유지.
            pass

    # -- sign / verify (KEY 필요) ------------------------------------- #
    def sign(self, req: OperatorRequest) -> str:
        """전체 바인딩에 대한 operator 측 HMAC 토큰. 키 필요 (없으면 '' fail-closed)."""
        if self._key is None:
            return ""
        mac = hmac.new(self._key,
                       _canonical(req.decision_id, req.command_digest, req.nonce, req.expiry),
                       hashlib.sha256)
        return mac.hexdigest()

    def verify(self, req: OperatorRequest, token: str, *, now: Optional[float] = None,
               expected_digest: Optional[str] = None) -> tuple[bool, str]:
        """명령 결속 승인을 검증한다 (PS-9). 거부: 키 없음, 잘못된/부재 토큰, 만료,
        replay 된 nonce, 비단조 consume ts, 그리고 (주어졌다면) command_digest 불일치 — 그래서
        명령 A 를 위해 발행된 포착 토큰은 명령 B 를 인가할 수 없다.

        성공 시 nonce 는 seen 으로 표시되고 consume-ts 가 전진한다 (단일 사용 + 연속성).
        """
        if self._key is None:
            return False, "no operator-gate key (fail-closed)"
        if expected_digest is not None and not hmac.compare_digest(req.command_digest, expected_digest):
            return False, "command_digest mismatch (captured token bound to a different command)"
        t = self._now(now)
        if t > req.expiry:
            return False, "expired (TTL elapsed)"
        if t < self._last_consume_ts:                # 연속성: consume ts 는 단조여야 함
            return False, "non-monotonic timestamp (replay/continuity violation)"
        if req.nonce in self._seen_nonces:
            return False, "nonce already consumed (replay)"
        expected = self.sign(req)
        if not expected or not hmac.compare_digest(expected, token or ""):
            return False, "HMAC mismatch (unauthorized / tampered binding)"
        # 작동-후-크래시가 리부트에서 같은 nonce 를 재승인할 수 없도록 True 반환 전에
        # GRANTED 영수증을 기록 (fsync) (P4-Q3 — 토큰 자체는 영속되지 않음).
        self._seen_nonces.add(req.nonce)
        self._last_consume_ts = t
        self._record(req, verdict="GRANTED", consumed_ts=t)
        return True, "approved"


# --------------------------------------------------------------------------- #
# KEY-FREE signed-mode emitter — 어떤 signing-key 경로도 결코 열지 않음 (verify_signer_no_keyopen)
# --------------------------------------------------------------------------- #
@dataclass
class SignerEmit:
    ok: bool
    dry_run: bool
    command_digest: str
    delegate: str = GCS_SIGN_DELEGATE
    note: str = ""
    extra: dict = field(default_factory=dict)


def _recovery_mode_alt(intent) -> tuple[str, int]:
    """MDG 가 gcs_c2 sender 에 넘기는 (mode, 상대-고도-m) 회복 파라미터를 해석한다.

    이들은 비밀도 아니고 raw 작동 페이로드도 아니다 — 실제 signed MAVLink 명령은
    gcs_c2 (키 보유) 안에서 만들어지고 서명된다. 기본값은 S2 물리-복귀
    계약 (GUIDED + 30 m home/hover)이다. Intent 는 존재하면 ``params`` (mode/alt)로 override 할 수 있고;
    잘못된 alt 는 30 m 기본값으로 폴백한다 (home 고도로 fail-safe)."""
    params = getattr(intent, "params", None) or {}
    if isinstance(params, dict):
        mode = str(params.get("mode", _RECOVERY_MODE)) or _RECOVERY_MODE
        raw_alt = params.get("alt", _RECOVERY_ALT_M)
    else:
        mode, raw_alt = _RECOVERY_MODE, _RECOVERY_ALT_M
    try:
        alt = int(raw_alt)
    except (TypeError, ValueError):
        alt = _RECOVERY_ALT_M
    return mode, alt


def _delegate_argv(mode: str, alt: int) -> list[str]:
    """단일 Backend-spawn argv: gcs_c2 안에 회복 TRIGGER FILE 을 쓴다.

    ``docker exec gcs_c2 sh -c 'printf "%s %s" "$1" "$2" > /tmp/mdg_correct' sh <mode> <alt>``

    MDG 는 오직 "<MODE> <ALT>" (예: ``GUIDED 30``)를 gcs_c2 의 트리거 파일에 기록할 뿐이다. 배포된
    gcs.py — SITL signing 링크의 유일한 소유자 — 가 그 파일을 폴링하여 자기 키로 SIGNED
    set_mode(GUIDED)+arm+takeoff(alt) 를 발행한 뒤 파일을 삭제한다. MDG 는 결코 키를 넘기거나
    명명하거나 열지 않는다 (E11 non-proliferation). ``mode``/``alt`` 는 ``sh`` 에 위치
    인자 ($1/$2)로 전달되며, 셸 문자열에 보간되지 않으므로 injection 면이 없다."""
    return ["docker", "exec", GCS_SIGN_DELEGATE, "sh", "-c",
            f'printf "%s %s" "$1" "$2" > {GCS_TRIGGER_FILE}', "sh", mode, str(alt)]


def emit_signed(intent, backend=None) -> SignerEmit:
    """MDG 가 키를 결코 보유하지 않은 채 signed-mode 교정 명령을 emit 한다.

    allow_live=False (기본 / operator-go 유보): 오직 command_digest (토큰
    재료)만 계산하고 DRY 결과를 반환 — spawn 없음, 파일 접근 없음 (기존 레거시 동작 그대로).

    allow_live=True (operator 승인 live 승격): 유일한 subprocess 소유자
    ``Backend.run`` (불변식2., 단일 spawn 지점)을 통해 회복 TRIGGER FILE 을 씀으로써 서명을
    ``gcs_c2`` (이미 자기 키 보유)에 위임한다:
    ``docker exec gcs_c2 sh -c 'printf "%s %s" "$1" "$2" > /tmp/mdg_correct' sh <MODE> <ALT>``. 배포된 gcs.py —
    SITL signing 링크의 유일한 소유자 — 가 그 파일을 폴링하여 자기 키로 SIGNED set_mode(GUIDED)+arm+
    takeoff(alt) 를 발행한 뒤 삭제한다. 이 함수는 signing-key 경로를 결코 열거나 읽거나
    명명하지 않는다 (verify_signer_no_keyopen); 오직 argv 를 만들어 Backend.run 에 넘길 뿐이다.
    """
    dg = command_digest(intent)
    live = bool(getattr(backend, "allow_live", False))
    if not live:
        return SignerEmit(ok=True, dry_run=True, command_digest=dg,
                          note="operator-go 유보: key-free digest only; sign delegated to gcs_c2 "
                               "(no signing key held, E11 non-proliferation)")
    # Live 승격: 인가는 operator 승인을 받았어야 한다 (OperatorGate.verify). 서명은
    # gcs_c2 delegate 가 out-of-band 로 발행한다 (gcs.py 가 트리거 파일을 폴링); MDG 는 오직
    # 단일 Backend spawn 을 통해 트리거를 기록할 뿐 키를 재장착하지 않는다. 부재/무효
    # backend 는 inert 로 실패 (spawn 없음).
    if not callable(getattr(backend, "run", None)):
        return SignerEmit(ok=False, dry_run=True, command_digest=dg,
                          note="live emit requested but no Backend spawn owner supplied (inert)")
    mode, alt = _recovery_mode_alt(intent)
    argv = _delegate_argv(mode, alt)
    res = backend.run(ExecRequest(argv=argv, timeout_s=_DELEGATE_TIMEOUT_S, reversible=False))
    return SignerEmit(ok=bool(getattr(res, "ok", False)),
                      dry_run=bool(getattr(res, "dry_run", False)),
                      command_digest=dg,
                      note=(f"delegate to {GCS_SIGN_DELEGATE} via Backend spawn: write trigger "
                            f"'{mode} {alt}' -> {GCS_TRIGGER_FILE} (gcs.py polls + signs with its "
                            f"own key; MDG holds no key, E11): {getattr(res, 'note', '')}"),
                      extra={"mode": mode, "alt": alt, "argv": argv})
