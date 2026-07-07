"""core.modules.safeexec — P1 누수방지 배선 + runner_factory 실배선 (09·13·14 §계약).

orchestrator 의 RunnerFactory 심(seam, 현 `_unwired_runner`)을 채우는 실행엔진 배선.
ExecBinding(sidecar/script/args_template/secret_params) → backend.run 구조화 호출로 변환.

★ 단일 진실(single source of truth): 실행 계약/백엔드 구현은 **core.modules.backends** 정본이다.
  Backend·ExecRequest·ExecOutput·MockBackend·LocalBackend·SshBackend 및 종료 프리미티브
  (finalize/scoped_pipe/scoped_tempfile)는 backends/ 에서 import 하며, 여기서 재정의하지 않는다.
  (이전엔 safeexec 가 이들을 중복 정의했고, 그 LocalBackend 는 JOB 마커를 `docker exec -e`
   환경변수로 넣어 cmdline 매칭이 못 잡는 **R1 reap 버그**가 있었다. 현재 backends/local.py 의
   per-job teardown 은 **컨테이너-스코프 kill-all-but-pid1(+리퍼 자기트리) 스윕**(TERM→grace→
   KILL, `_reap_all_script`)이다 — busybox `timeout` 이 마커/PGID 를 잃고 탈출해도 SIGKILL 로
   확실 회수한다. PID 네임스페이스 private 가드(pid1=sleep 확인)로 fail-closed. 이제 그 정본만 쓴다.)

이 모듈의 **고유 로직**만 유지한다:
  · Vault·render_argv·_argv_leak_guard(R6)   비밀 vault→stdin, argv 누수 0
  · make_runner / make_runner_factory          orchestrator RunnerFactory 정본(+R3 preflight 게이트)
  · parse_output                               kind → 공격자-가시 payload(+exec_meta)
  · reap_labeled / install_signal_reap         R2 라벨 reap(우리 라벨만·dah_safeexec)

누수-안전 불변식(코드로 구현·backends 정본에 배선됨):
  R1  컨테이너 내부 `timeout -k`(상한 확정종료·PRIMARY) + `setsid` 새 프로세스그룹 + JOB 마커
        **cmdline** 상주. per-job reap = 마커로 PGID 조회→`kill -TERM/-KILL -<PGID>`(그룹 kill·
        우리 uuid 만). 넓은 `pkill -f`/`kill` 금지. (backends/local.py `_wrap_in_container`·
        `_reap_pgid_script` 가 배선. `pkill -f` 는 sh 만 죽고 자식이 생존해 폐기.)
  R2  라벨(LABEL_KEY=LABEL_VALUE) teardown/부팅 reap. **우리 라벨만** 회수(reap_labeled).
  R3  preflight 게이트 — Backend.preflight() 로 위임, 팩토리 스코프 1회 캐시.
  R6  비밀은 vault→**stdin** 라우팅(argv/평문 env 금지). render_argv/leak-guard 가 강제.

★ 이 워크플로우는 완전 오프라인 — Backend.run 은 로컬 검증용 MockBackend 로만 구동.
  LocalBackend(docker exec)는 배포 정본 코드이나 이 단계에선 실행되지 않는다(테스트베드 무접속).

반환 규격(tool_wrap 정합): Runner 는 항상 Result[T](Ok|Err) — ToolResult 로 반환하지 않는다.
  tool_wrap 이 Ok→ToolSuccess / Err·CRSError→ToolError 로 승격. 예외 누출 금지.
작성 2026-07-05 · 리팩터(중복 제거·backends 정본 배선) 2026-07-06.
"""

from __future__ import annotations

import atexit
import os
import signal
from typing import (
    Any,
    Awaitable,
    Callable,
    Mapping,
    Optional,
)

from core.common.config import resolve_secret
from core.common.results import _ResultBase
from core.common.types import ExecBinding, ToolKind, ToolSpec
from core.modules.resolve import IP_PLACEHOLDER_ROLES, TargetResolver, target_ip_fields
from core.modules.tool_wrap import CRSError, Err, Ok, Result

# 단일 진실 = backends/. 계약·페이로드·구현·종료 프리미티브를 정본에서 가져와 재수출(API 안정).
from core.modules.backends import (
    Backend,
    ExecOutput,
    ExecRequest,
    LocalBackend,
    MockBackend,
    SshBackend,
    finalize,
    scoped_pipe,
    scoped_tempfile,
)

# ═══════════════════════════════════════════════════════════════════════════
# 0. 상수 — 라벨(R2) · JOB 마커 이름(참조용) · 파싱 어휘
# ═══════════════════════════════════════════════════════════════════════════

LABEL_KEY = "dah_safeexec"          # R2: 우리 소유 컨테이너/프로세스 라벨 키
LABEL_VALUE = "attack_agent"            # R2: 라벨 값(이 것만 reap)
# R1 JOB 마커 이름 — 실제 cmdline 상주/PGID killpg reap 배선은 backends/local.py(_JOB_MARK="DAH_JOB").
#   여기서는 참조/재수출용 상수로만 노출(API 안정). 값 정합은 backends 정본과 동일해야 함.
JOB_ENV = "DAH_JOB"

# 파싱 닫힌 어휘(results.py 정합). signing 어휘는 recon.build_recon_result 가 소유(PROBE).
_BLOCKED_VALS = frozenset({"signing", "auth", "no_effect", "timestamp", "baseline"})


# ═══════════════════════════════════════════════════════════════════════════
# 1. Vault — 비밀 vault→stdin 라우팅 (R6 · ADV-F5 · 절대규칙6)
# ═══════════════════════════════════════════════════════════════════════════


class Vault:
    """secret_params(sign_key/aria_key/ciphertext) → **stdin** 라우팅.

    값 출처(우선순위):
      ① params[name]      — 런타임 수집물(예: ciphertext, KB→호출자 전달). secret_params 라
                             args_template 미등장(render_argv reject) → argv 노출 0.
      ② values[name]      — 직접 주입 값(테스트/replay).
      ③ name_to_env[name] — env var **이름** → config.resolve_secret 로 값 조회(하드코딩 0).
    비밀은 로그·에러·argv·평문 env 에 절대 미포함(redact).
    """

    __slots__ = ("_name_to_env", "_values", "_env")

    def __init__(
        self,
        *,
        name_to_env: Optional[Mapping[str, str]] = None,
        values: Optional[Mapping[str, str]] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._name_to_env = dict(name_to_env or {})
        self._values = dict(values or {})
        self._env = env

    def get(self, name: str, params: Optional[Mapping[str, Any]] = None) -> str:
        """secret 이름 → 값. 미바인딩 시 CRSError(비밀 값은 에러 메시지 미포함)."""
        if params is not None:
            v = params.get(name)
            if v not in (None, ""):
                return str(v)
        if name in self._values:
            return self._values[name]
        if name in self._name_to_env:
            try:
                return resolve_secret(self._name_to_env[name], self._env)
            except Exception as e:  # 값 자체는 메시지에 넣지 않음(env 이름만)
                raise CRSError(
                    f"vault: secret env resolve failed for {name!r}",
                    extra={"env_name": self._name_to_env[name], "err": type(e).__name__},
                ) from None
        raise CRSError(f"vault: no binding for secret {name!r}")

    def route_stdin(
        self, binding: ExecBinding, params: Optional[Mapping[str, Any]] = None
    ) -> dict[str, str]:
        """secret_params → {name: value} (route_secrets 가 stdin bytes 로 인코딩)."""
        return {n: self.get(n, params) for n in binding.secret_params}


# stdin 프로토콜 정본(gap 해소): baked 스크립트는 stdin 을 `name=value\n` 라인들로 읽는다.
#   단일/복수 비밀 모두 키드(keyed). 값에 개행 없음 가정(암호문은 hex/base64 계열).
def _encode_stdin(secrets: Mapping[str, str]) -> Optional[bytes]:
    if not secrets:
        return None
    lines = [f"{k}={v}" for k, v in secrets.items()]
    return ("\n".join(lines) + "\n").encode("utf-8")


def route_secrets(
    binding: ExecBinding, params: Mapping[str, Any], vault: Vault
) -> Result[Optional[bytes]]:
    """ExecBinding.secret_params → stdin bytes(R6). 실패 시 Err(비밀 값 미노출)."""
    if not binding.secret_params:
        return Ok(None)
    try:
        secrets = vault.route_stdin(binding, params)
    except CRSError as e:
        return Err(e)
    except Exception as e:
        return Err(CRSError("secret routing failed", extra={"err": type(e).__name__}))
    return Ok(_encode_stdin(secrets))


# ═══════════════════════════════════════════════════════════════════════════
# 2. render_argv — args_template → argv (06 §5). secret 원문 금지 강제(R6)
# ═══════════════════════════════════════════════════════════════════════════


class _StrMap(dict):
    """format_map 용 — 값을 문자열화, 누락 키는 KeyError(엄격 치환)."""

    def __missing__(self, key: str) -> str:  # noqa: D401
        raise KeyError(key)


def render_argv(binding: ExecBinding, params: Mapping[str, Any]) -> Result[tuple[str, ...]]:
    """args_template '{param}' 치환 → shell 미경유 argv 벡터.

    R6 게이트: secret_params 이름이 args_template 에 **원문 등장 시 Err**(누수 차단).
    argv[0] = binding.script(이미지 baked 경로). 누락 param → Err.
    """
    tmpl = binding.args_template or ""
    for sp in binding.secret_params:
        if sp in tmpl:  # '{sign_key}' 및 bare 'sign_key' 모두 차단
            return Err(
                CRSError(
                    f"secret param {sp!r} must not appear in args_template (R6)",
                    extra={"script": binding.script},
                )
            )
    argv: list[str] = [binding.script]
    if tmpl:
        try:
            rendered = tmpl.format_map(_StrMap(params))
        except KeyError as e:
            return Err(
                CRSError(f"missing template param {e}", extra={"script": binding.script})
            )
        except Exception as e:
            return Err(
                CRSError(
                    "args_template render failed",
                    extra={"script": binding.script, "err": type(e).__name__},
                )
            )
        argv.extend(rendered.split())
    return Ok(tuple(argv))


def _argv_leak_guard(
    argv: tuple[str, ...], binding: ExecBinding, params: Mapping[str, Any], vault: Vault
) -> Optional[CRSError]:
    """산출 argv 에 비밀 **값**이 나타나면 CRSError(2차 방어, R6). 없으면 None."""
    for name in binding.secret_params:
        try:
            val = vault.get(name, params)
        except CRSError:
            continue  # 값 미해석 시 route_secrets 단계에서 이미 Err 처리
        if not val:
            continue
        for tok in argv:
            if val in tok:
                return CRSError(
                    f"secret value for {name!r} leaked into argv (R6 violation)",
                    extra={"script": binding.script},
                )
    return None


# ═══════════════════════════════════════════════════════════════════════════
# 3. parse_output — kind → 공격자-가시 payload (15). exec_meta 전사. grep0.
# ═══════════════════════════════════════════════════════════════════════════


def _as_str_list(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v]
    return []


def _mask(v: str) -> str:
    """수집 값 마스킹(비밀 로깅 금지). 앞 4문자 + '…'."""
    s = str(v)
    return (s[:4] + "…") if len(s) > 4 else "…"


def _parse_json(stdout: str) -> dict[str, Any]:
    import json

    s = stdout.strip()
    if not s:
        return {}
    try:
        d = json.loads(s)
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def parse_output(spec: ToolSpec, out: ExecOutput) -> Result[_ResultBase]:
    """ToolKind → ReconResult/CollectResult/InjectResult. out.latency_ms/killed 전사.

    killed/timed_out → 보수판정(허위 effected/accepted 0). grep0: truth 필드 미산출.
    파싱 실패는 conservative 기본 payload 로 흡수(killed 신호 보존이 Err 보다 유용).
    """
    from core.common.results import CollectResult, InjectResult

    data = _parse_json(out.stdout)
    killed = bool(out.killed or out.timed_out)
    lm = int(out.latency_ms)

    match spec.kind:
        case ToolKind.PROBE:
            # PROBE→ReconResult 조립의 단일 진실 = recon.build_recon_result 로 위임
            #   (recon_reach/defense/session 파서 일원화, 12). 지역 import(순환 회피).
            from core.modules.recon import build_recon_result

            return Ok(build_recon_result(data, latency_ms=lm, killed=killed))

        case ToolKind.COLLECT:
            raw_vals = data.get("values") or {}
            values = (
                {str(k): _mask(str(v)) for k, v in raw_vals.items()}
                if isinstance(raw_vals, dict)
                else {}
            )
            r = CollectResult(
                artifacts=_as_str_list(data.get("artifacts")),
                values=values,
                redacted=True,
                nonce_collision=data.get("nonce_collision"),
                latency_ms=lm,
                killed=killed,
            )
            return Ok(r)

        case ToolKind.INJECT:
            accepted = bool(data.get("accepted", False)) and not killed
            bb = data.get("blocked_by")
            effect_raw = data.get("effect") or {}
            effect = (
                {str(k): str(v) for k, v in effect_raw.items()}
                if (accepted and isinstance(effect_raw, dict))
                else {}
            )
            r = InjectResult(
                accepted=accepted,
                signed=data.get("signed"),
                blocked_by=(bb if bb in _BLOCKED_VALS else None),
                effect=effect,
                latency_ms=lm,
                killed=killed,
            )
            return Ok(r)

    # ToolKind 확장 시 방어(닫힌 enum 이라 정상 도달 안 함)
    return Err(CRSError(f"unknown ToolKind: {spec.kind!r}", extra={"tool": spec.id}))


# ═══════════════════════════════════════════════════════════════════════════
# 4. R2 라벨 reap — 우리 라벨(dah_safeexec)만 회수. + atexit/(opt-in) signal.
# ═══════════════════════════════════════════════════════════════════════════


def _docker_bin() -> str:
    return os.environ.get("DAH_DOCKER_BIN", "docker")


def reap_labeled(sync: bool = True) -> None:
    """R2 부팅/종료 reap: **우리 라벨(LABEL_KEY=LABEL_VALUE) 컨테이너만** `rm -f`.

    ★ 넓은 회수 금지 — label 필터로 우리 것만 조준한다(다른 소유 컨테이너 불가침).
      부팅 reap 대상도 오직 이 라벨(dah_safeexec=attack_agent)뿐이다(재확인).
    docker 부재/오프라인 시 best-effort no-op(예외 삼킴). backends/LocalBackend 의
      JOB 마커 PGID killpg reap(R1)과는 상보적 — 이쪽은 컨테이너(라벨) 원자 회수(FACT4),
      그쪽은 프로세스그룹(cmdline 마커→PGID). 캠페인 종료 회수의 정본은 이 컨테이너 rm -f 다.
    """
    import subprocess

    flt = f"label={LABEL_KEY}={LABEL_VALUE}"
    try:
        p = subprocess.run(
            [_docker_bin(), "ps", "-aq", "--filter", flt],
            capture_output=True, text=True, timeout=10,
        )
        ids = [x for x in p.stdout.split() if x]
        if ids:
            subprocess.run([_docker_bin(), "rm", "-f", *ids], capture_output=True, timeout=30)
    except Exception:
        pass  # 오프라인/무접속: 조용히 skip


atexit.register(reap_labeled)  # R2: 프로세스 종료 시 우리 라벨만 best-effort 회수


def install_signal_reap() -> None:
    """R2(opt-in): SIGINT/SIGTERM 시 우리 라벨 reap 후 이전 핸들러로 체이닝.

    라이브러리 import 만으로 전역 시그널을 가로채지 않도록 명시 호출로 분리(안전).
    부팅 reap 을 원하면 애플리케이션 엔트리포인트가 reap_labeled() 를 직접 호출한다
    (import 부작용으로 docker 를 건드리지 않기 위해 자동 실행하지 않음).
    """
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            prev = signal.getsignal(sig)
        except Exception:
            continue

        def _handler(signum: int, frame: Any, _prev: Any = prev, _sig: int = sig) -> None:
            reap_labeled()
            if callable(_prev):
                _prev(signum, frame)
            elif _sig == signal.SIGINT:
                raise KeyboardInterrupt

        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass  # 비-메인 스레드 등: skip


# ═══════════════════════════════════════════════════════════════════════════
# 5. make_runner / make_runner_factory — orchestrator RunnerFactory 정본
# ═══════════════════════════════════════════════════════════════════════════

# orchestrator.Runner/RunnerFactory 와 구조적 정합(중복 import 회피용 지역 별칭).
type Runner = Callable[..., Awaitable[Result[Any]]]
type RunnerFactory = Callable[[ToolSpec], Runner]
type PreflightGate = Callable[[], Awaitable[Result[None]]]


async def _resolve_target_ips(
    binding: ExecBinding, resolver: Optional[TargetResolver]
) -> Result[dict[str, str]]:
    """args_template 의 IP placeholder → TargetResolver 해석값 dict. fail-closed.

    IP placeholder 무(無) → Ok({}) (기존 동작 무변경). placeholder 有인데 resolver 없음
      또는 미해석 → Err(주입 봉쇄, 정직). role=IP_PLACEHOLDER_ROLES[field], vantage=binding.sidecar.
    전부 resolver.resolve_ip 경유(backend.run) — 직접 docker 호출 0. 비밀 미취급(IP 만).
    """
    fields = target_ip_fields(binding.args_template)
    if not fields:
        return Ok({})
    if resolver is None:
        return Err(
            CRSError(
                "target IP placeholder present but no resolver",
                extra={"script": binding.script, "fields": list(fields)},
            )
        )
    out: dict[str, str] = {}
    for f in fields:
        match await resolver.resolve_ip(IP_PLACEHOLDER_ROLES[f], binding.sidecar):
            case Err() as e:
                return e  # 미해석 → Err(주입 봉쇄, 정직)
            case Ok(ip):
                out[f] = ip
    return Ok(out)


def make_runner(
    spec: ToolSpec,
    backend: Backend,
    *,
    vault: Vault,
    timeout_s: int = 30,
    preflight_gate: Optional[PreflightGate] = None,
    resolver: Optional[TargetResolver] = None,
) -> Runner:
    """ExecBinding → backend.run 변환 클로저(spec 1개 → Runner).

    파이프라인: [IP 해석·주입] → render_argv(비밀 배제) → route_secrets(→stdin)
      → leak-guard(argv 비밀 0) → [R3 preflight] → backend.run(ExecRequest)
      → parse_output(kind→payload+exec_meta).
    항상 Result[T](Ok|Err) 반환 — 예외 누출 금지(tool_wrap 이 ToolResult 로 승격).
    """
    binding = spec.exec_binding

    async def run(**params: Any) -> Result[Any]:
        # (0) args_template IP placeholder → resolver 해석값 주입(fail-closed).
        #     resolved-wins: params 를 IP 값으로 덮음(planner 는 IP placeholder 미계획 →
        #     ParamSpec 미선언이라 애초 계획면 밖). placeholder 무면 no-op(기존 동작).
        match await _resolve_target_ips(binding, resolver):
            case Err() as e:
                return e
            case Ok(ips):
                if ips:
                    params = {**params, **ips}

        # (1) argv 조립(비밀 원문 배제, R6). argv[0]=binding.script.
        match render_argv(binding, params):
            case Err() as e:
                return e
            case Ok(argv):
                pass
            case _:  # pragma: no cover
                return Err(CRSError("render_argv contract violation"))

        # (2) secret_params → stdin bytes(R6)
        match route_secrets(binding, params, vault):
            case Err() as e:
                return e
            case Ok(stdin_bytes):
                pass
            case _:  # pragma: no cover
                return Err(CRSError("route_secrets contract violation"))

        # (3) leak-guard: 산출 argv 에 비밀 값 0(R6 2차 방어)
        if (leak := _argv_leak_guard(argv, binding, params, vault)) is not None:
            return Err(leak)

        # (4) R3 preflight 게이트(1회, 팩토리 캐시) — 통과 후에만 실행
        if preflight_gate is not None:
            match await preflight_gate():
                case Err() as e:
                    return e
                case Ok(_):
                    pass

        # (5) 구조화 실행요청 → backend.run(타임아웃+확정종료+자원회수).
        #     ★ script 는 argv[0] 로 이미 포함 — backends.ExecRequest 는 script 필드 없음.
        req = ExecRequest(
            sidecar=binding.sidecar,
            argv=argv,
            stdin=stdin_bytes,
            timeout_s=float(timeout_s),
            reversible=spec.reversible,
            tool_id=spec.id,
            on_host=(binding.sidecar == "host"),
        )
        try:
            outcome = await backend.run(req)
        except CRSError as e:
            return Err(e)
        except Exception as e:  # 백엔드 예외 → fail-open Err(누출 금지)
            return Err(
                CRSError(f"backend.run raised: {type(e).__name__}", extra={"tool": spec.id})
            )

        # (6) kind → 공격자-가시 payload(+exec_meta latency_ms/killed)
        match outcome:
            case Err() as e:
                return e
            case Ok(out):
                return parse_output(spec, out)
            case _:  # pragma: no cover
                return Err(CRSError("backend.run contract violation"))

    return run


def make_runner_factory(
    *,
    backend: Backend,
    vault: Optional[Vault] = None,
    timeout_s: int = 30,
    preflight: bool = True,
    resolver: Optional[TargetResolver] = None,
) -> RunnerFactory:
    """orchestrator.RunnerFactory 정본(현 `_unwired_runner` 대체).

    __call__(spec) → make_runner 클로저. R3 preflight 는 팩토리 스코프에서 1회 실행 후
      결과 캐시(모든 tool 공유) — backend.preflight() 로 위임(mock=통과, local=실측).

    ★ 공유 한정자원(예: 5762 업링크 — 세마포어=1·단일슬롯) 직렬화는 backend 가 소유한다.
      실배선 경로 orchestrator→make_runner_factory→make_runner→backend.run 은
      backends/local.py(LocalBackend) 를 태우며, 그 백엔드는 sem 미주입 시 단일슬롯(1)로
      기본 직렬화한다(다중 연결 금지). 팩토리는 backend 를 그대로 소비(세마포어 미개입).
    """
    _vault = vault or Vault()
    _pf: dict[str, Any] = {"done": False, "res": None}

    async def _gate() -> Result[None]:
        if not _pf["done"]:
            _pf["res"] = await backend.preflight()
            _pf["done"] = True
        res = _pf["res"]
        return res if res is not None else Ok(None)

    gate: Optional[PreflightGate] = _gate if preflight else None

    def factory(spec: ToolSpec) -> Runner:
        return make_runner(
            spec,
            backend,
            vault=_vault,
            timeout_s=timeout_s,
            preflight_gate=gate,
            resolver=resolver,
        )

    return factory


__all__ = [
    # 종료 프리미티브(backends 재수출 — API 안정)
    "finalize",
    "scoped_pipe",
    "scoped_tempfile",
    # 페이로드(backends 재수출)
    "ExecRequest",
    "ExecOutput",
    # 백엔드(backends 재수출 — 단일 진실)
    "Backend",
    "MockBackend",
    "LocalBackend",
    "SshBackend",
    # 비밀 라우팅(R6, safeexec 고유)
    "Vault",
    "route_secrets",
    "render_argv",
    # 파싱(safeexec 고유)
    "parse_output",
    # R2 회수(safeexec 고유)
    "reap_labeled",
    "install_signal_reap",
    # 팩토리(safeexec 고유)
    "make_runner",
    "make_runner_factory",
    # 상수
    "LABEL_KEY",
    "LABEL_VALUE",
    "JOB_ENV",
]
