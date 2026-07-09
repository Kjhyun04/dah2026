"""observer (Phase 4) — 회복 라이프사이클을 위한 read-only effect-confirm 관측자.

``make_effect_observer(...)`` 는 ``observe(rule) -> bool`` 클로저를 반환하며,
``effect_confirm`` (PA-2) 이 이를 호출하여 적용된 회복 규칙이 live 테스트베드에서 실제로
효력을 발휘했는지 판단한다. 이는 ``worldstate.applied[rule].confirmed`` 를 False -> True 로
뒤집는 "회복 완료" 신호이다.

메커니즘별 확인 (규칙은 RECOVERY_PRIORS 를 통해 response_tool 로 해석):
  - ``docker_pause``   (backdoor_pause) : enforce_at 컨테이너의 ``docker inspect .State.Paused``
    가 True (공격자 컨테이너가 동결됨).
  - ``nsenter_input_drop`` (pfcp_firewall / mongo_acl) : enforce_at 컨테이너의 netns 안에서
    회복 강제가 설치되어 있다. 신호 = INPUT 체인 DROP 규칙이 설치됨
    (``iptables -S INPUT`` 가 ``-s <src> -j DROP`` 라인을 표시). 규칙 존재로 확인하는 이유:
    이미 ESTABLISHED 된 소켓은 ingress DROP 으로 리셋되지 않아(커널은 새 패킷만 폐기) 효력
    이후에도 peer ESTAB 이 수 분간(keepalive/RTO) 잔존할 수 있어, 부재-기반 신호는 신뢰할 수
    없기 때문이다. "회복 완료" 를 규칙 존재로 좌우하지 않으면 ``already_applied``
    (applied∧confirmed) 가 False 로 유지되고 비멱등 ``iptables -I`` 가 매 debounce 윈도우마다
    재삽입되어, 단일 ``-D`` 로는 완전히 되돌릴 수 없는 중복 규칙이 누적된다 (가역성/leak-0 저촉).
    규칙 존재는 DROP 이 실제로 설치되는 즉시 확인되므로 재작동이 멱등적으로 억제된다.
  - ``send_signed_mode`` (signed_*) : 다운링크 텔레메트리 ``rel_alt`` 가 목표
    (30 m ± tol)로 회복 AND ``mode`` 가 명시적 비착륙 비행 모드 (존재, LAND 아님) —
    비행 재확립. 결측 mode 는 회복으로 간주하지 않는다 (고도 단독은 신호가 너무
    희소 — 기체가 하강 중에 30 m 를 통과하므로, 단순 고도 일치만으로는 오확인이
    가능; 양성 mode 판독이 필수).

불변식2. (누수-0): 여기의 모든 probe 는 READ-ONLY 이다. docker probe 는 메타데이터
``inspect`` (read_only=True fast-path); ss probe 는 대상 netns 로 감싼 allowlist 관측자;
텔레메트리는 수동 collector 스냅샷이다. 단일 주입 ``Backend`` (``backend.run`` = 유일한 ``_spawn``
지점)를 통하지 않고는 아무것도 spawn 하지 않는다. 새 subprocess 경로는 도입되지 않는다.
불변식1. (결정론): 관측자는 live 상태만 읽는다; 라우팅은 이에 절대 의존하지 않으므로
(effect_confirm -> END 무관), 결정론은 훼손되지 않는다.

Fail-safe: 미해석 대상 / 의존성 결여 / DRY / 에러는 모두 ``False`` (미확인)을 낳으며,
허위 확인은 절대 없다 — 다음 tick 이 재관측한다 (PA-2). 오확인(회복 완료를 거짓으로 선언)이
위험한 방향이므로, 클로저는 보수적으로 동작한다.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..config.defaults import RECOVERY_PRIORS
from .backend import Backend, ExecRequest

# signed_* 비행 회복 목표: 상대 고도(m)와 허용 오차 band.
_TARGET_ALT_M = 30.0
_ALT_TOL_M = 5.0


def _tool_for(rule: str, priors: dict) -> Optional[str]:
    """priors 를 통한 rule -> response_tool (docker_pause / nsenter_input_drop / send_signed_mode)."""
    row = priors.get(rule) or {}
    return row.get("response_tool")  # type: ignore[return-value]


def _container_for(rule: str, priors: dict) -> Optional[str]:
    """rule -> enforce_at 컨테이너 키 (== 이 규칙들의 netns_prefix_map / docker-inspect 키)."""
    row = priors.get(rule) or {}
    ea = row.get("enforce_at")
    return str(ea) if ea else None


def _observe_pause(rule: str, docker: Any, priors: dict) -> bool:
    """backdoor_pause: enforce_at 컨테이너의 ``.State.Paused`` 가 True."""
    container = _container_for(rule, priors)
    if not container or docker is None:
        return False
    inspect_paused = getattr(docker, "inspect_paused", None)
    if inspect_paused is None:
        return False
    try:
        return inspect_paused(container) is True
    except Exception:
        return False


def _input_source_drop_installed(ipt_s_stdout: str) -> bool:
    """``iptables -S INPUT`` 출력에 INPUT ``-s <src> -j DROP`` 규칙이 있으면 True — 즉 회복
    DROP 이 대상 netns 에 실제 설치되어 있다. 이는 지연되는 ESTAB 해제와 무관하게 즉시 참이 되는
    nsenter_input_drop 확인 (규칙 존재)이다."""
    for line in (ipt_s_stdout or "").splitlines():
        toks = line.split()
        if not toks or toks[0] not in ("-A", "-I"):
            continue
        # SOURCE 를 필터링하고 target 이 DROP 인 INPUT append/insert == 우리의 봉쇄 규칙
        if "INPUT" in toks and "-s" in toks and "DROP" in toks:
            return True
    return False


def _observe_drop(rule: str, netns_prefix_map: dict, backend: Optional[Backend],
                  priors: dict) -> bool:
    """enforce_at 컨테이너의 netns 안에 회복 강제가 설치되면 nsenter_input_drop 확인: INPUT
    DROP 규칙이 설치됨 (``iptables -S INPUT``) — 이것이 ``already_applied`` 를 True 로 뒤집고
    비멱등 ``-I`` 재삽입을 멈춘다. 규칙이 (아직) 관측되지 않으면 미확인 (DROP 이 효력을 낸
    뒤에도 ESTAB 은 수 분 지연될 수 있어 부재-기반 신호는 신뢰하지 않는다)."""
    container = _container_for(rule, priors)
    if not container or backend is None:
        return False
    prefix = (netns_prefix_map or {}).get(container)
    if not prefix:                                  # 미해석 netns -> inert (오확인 절대 없음)
        return False
    # DROP 규칙이 설치됨. ``iptables -S`` 는 사실상 read-only (규칙 나열, 변경 없음);
    # read_only fast-path allowlist 에는 없으므로 allow_live=False 에서는 operator-go DRY 로
    # 유지된다 (그때는 DROP 자체도 DRY 이므로 확인할 것이 없음 — 안전).
    try:
        rules = backend.run(ExecRequest(argv=[*prefix, "iptables", "-w", "-S", "INPUT"],
                                        timeout_s=6.0))
    except Exception:
        return False
    return (rules is not None and not getattr(rules, "dry_run", False)
            and getattr(rules, "ok", False)
            and _input_source_drop_installed(rules.stdout or ""))


def _observe_signed(telemetry: Optional[Callable[[], Optional[dict]]],
                    target_alt_m: float, alt_tol_m: float) -> bool:
    """signed_*: rel_alt 이 target±tol 로 회복 AND mode != LAND (비행 재확립)."""
    if telemetry is None:
        return False
    try:
        snap = telemetry()
    except Exception:
        return False
    if not snap:
        return False
    alt = snap.get("rel_alt")
    if alt is None:
        return False
    mode = snap.get("mode", snap.get("flight_mode"))
    # 양성 mode 판독이 필수: 고도 단독은 너무 희소하므로 (기체가 하강 중에 30 m band 를
    # 통과), 결측 mode 는 회복 아님, LAND 도 회복 아님.
    if mode is None or str(mode).strip() == "" or str(mode).upper() == "LAND":
        return False
    try:
        return abs(float(alt) - target_alt_m) <= alt_tol_m
    except (TypeError, ValueError):
        return False


def make_effect_observer(docker: Any = None, netns_prefix_map: Optional[dict] = None,
                         backend: Optional[Backend] = None,
                         telemetry: Optional[Callable[[], Optional[dict]]] = None,
                         priors: Optional[dict] = None,
                         *, target_alt_m: float = _TARGET_ALT_M,
                         alt_tol_m: float = _ALT_TOL_M) -> Callable[[str], bool]:
    """``effect_confirm`` (deps["observe"])에 주입되는 ``observe(rule) -> bool`` 클로저를 만든다.

    ``docker``           : ``inspect_paused(container) -> bool|None`` 를 노출하는 duck-typed 백엔드
                           (safe-exec docker 백엔드; read-only ``inspect``).
    ``netns_prefix_map`` : container -> nsenter prefix (대상 netns 안의 ss probe 용).
    ``backend``          : 단일 safe-exec ``Backend`` (유일 spawn 지점; ss 는 이를 통과).
    ``telemetry``        : signed_* 비행 회복용 선택적 ``() -> {"rel_alt": float,
                           "mode"/"flight_mode": str}|None`` 스냅샷. live_autorun 이 여기에
                           AirTelemetryTap.snapshot (14560/14550 디코드)를 배선; None -> signed
                           경로는 미확인으로 유지, 안전.
    ``priors``           : rule -> {response_tool, enforce_at, ...} (기본값 RECOVERY_PRIORS).

    반환된 클로저는 live world 하에서 결정론적이며 (불변식1.) probe 는 read-only 전용이다
    (불변식2.). 미지 rule / 의존성 결여 / 임의 에러 -> False (허위 확인 절대 없음)."""
    priors = priors if priors is not None else RECOVERY_PRIORS

    def observe(rule: str) -> bool:
        tool = _tool_for(rule, priors)
        if tool == "docker_pause":
            return _observe_pause(rule, docker, priors)
        if tool == "nsenter_input_drop":
            return _observe_drop(rule, netns_prefix_map or {}, backend, priors)
        if tool == "send_signed_mode":
            return _observe_signed(telemetry, target_alt_m, alt_tol_m)
        return False                                 # 미지/미매핑 rule -> 미확인

    return observe
