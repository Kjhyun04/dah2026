"""합법성 게이트 (H-F/H-G) — 순수 precondition 검사. select_policy 가 legal set 을
구성하는 데 사용하고 AND act 가 pre-hook (PA-6)으로 현재 worldstate + 고정된
config_version (X7 TOCTOU)에 대해 재검사한다.

결정론적, side effect 없음. Illegal -> CRSError 발생 (act 가 side-effect-0
early return 으로 변환).
"""
from __future__ import annotations

from ..tools.defresult import CRSError
from ..tools.registry import REGISTRY
from .state import Action, MDGState
from .worldstate import WorldState, signing_enforced


def _resolve_role_key(action: Action | None, alias: str) -> str:
    """registry role_verified.<alias> 술어를 선택된 액션이 실제로 작동하는
    CONTAINER KEY 로 매핑한다 (step 10 — dynamic binding).

    registry 는 LITERAL alias('role_verified.target' / '.gcs')를 placeholder 로 고정한다;
    REAL 셀렉터는 액션의 enforce_at ENFORCEMENT-container 키 (finding P4-2 —
    액션이 자세를 바꾸는 netns/entity)이며, enforce_at 가 없으면 target 셀렉터로
    폴백한다. role_verified 는 CONTAINER-keyed (uav_ue/gcs_proxy/web_backend)이므로,
    fictional alias 가 아니라 구체적인 params 키가 검증되어야 하는 대상이다.
    Fail-closed: 액션 없음 또는 구체적 container 셀렉터 없음 -> "" -> caller 가 illegal 로 읽는다
    (fictional alias 키가 더 이상 후보를 허용할 수 없다; self-DoS 게이트가 닫힌 채 유지)."""
    if action is None:
        return ""
    params = getattr(action, "params", None) or {}
    for k in ("enforce_at", "target"):
        v = params.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _predicate_holds(world: WorldState, pred: str, action: Action | None = None) -> bool:
    """'reach.gcs14556' / 'signing' / 'role_verified.target' 같은 closed 술어 문자열을
    worldstate 에 대해 평가한다."""
    if "." not in pred:
        # 스칼라 술어
        if pred == "signing":
            # P2-Q2: CONFIRMED_ON 만 강제된다. UNKNOWN (unconfirmed)은 legal 아님 —
            # send_signed_mode 는 unconfirmed auth 컨트롤에 의존해선 안 된다 (보수적).
            return signing_enforced(world.signing)
        if pred == "config_version":
            return bool(world.config_version)
        # capability precond (ingest_key/operator_cert)은 environment-provided;
        # world 계층에서 satisfied 로 취급 (다른 곳에서 검증).
        return pred in ("ingest_key", "operator_cert")
    head, key = pred.split(".", 1)
    if head == "role_verified":
        # DYNAMIC binding (step 10): LITERAL registry alias('target'/'gcs')를 선택된 액션의
        # REAL enforcement-container KEY (params.enforce_at, 없으면 params.target)로 해석하고
        # role_verified[<그 container>] 를 검증한다. role_verified 는 CONTAINER-keyed; alias 는
        # placeholder 일 뿐이므로 fictional 키는 더 이상 legality 를 만족시키지 않는다. Fail-closed:
        # 해석 안 된 셀렉터 OR container 부재/False -> illegal (self-DoS 게이트가 닫힌 채 유지).
        # 결정론적 — 단일 bool 을 읽음, LLM 필드 없음 (불변식1.).
        real = _resolve_role_key(action, key)
        if not real:
            return False
        return bool((world.role_verified or {}).get(real))
    table = {
        "reach": world.reach,
        "threat": world.threat,
    }.get(head)
    if table is None:
        return False
    val = table.get(key)
    if head == "threat":
        return val not in (None, "none")
    return bool(val)


def is_legal(action: Action, world: WorldState, config_version: str) -> tuple[bool, str]:
    """(legal, reason) 반환. 3중 closed: registered id ∧ preconds ∧ config pin."""
    spec = REGISTRY.get(action.tool_id)
    if spec is None:
        return False, f"unregistered tool_id: {action.tool_id}"                 # ghost/dangling
    if config_version and world.config_version and config_version != world.config_version:
        return False, "config_version mismatch (TOCTOU pin, X7)"
    for pred in spec.requires:
        # env-provided capability precond 는 통과; posture 술어는 반드시 성립해야 한다
        if pred in ("config_version",):
            continue
        if not _predicate_holds(world, pred, action):
            return False, f"unmet precondition: {pred}"
    return True, "legal"


def assert_legal(action: Action, state: MDGState) -> None:
    """act pre-hook (PA-6): 현재 worldstate + 고정된 version 에 대해 재검사.
    Illegal -> CRSError (def_tool_wrap veto / act early return, side-effect 0)."""
    world: WorldState = state.get("worldstate") or WorldState()
    cfg = state.get("config_version", world.config_version)
    ok, reason = is_legal(action, world, cfg)
    if not ok:
        raise CRSError(f"illegal action blocked: {reason}")


def legal_actions(candidates: list[Action], world: WorldState, config_version: str) -> list[Action]:
    out: list[Action] = []
    for act in candidates:
        ok, _ = is_legal(act, world, config_version)
        if ok:
            out.append(act)
    return out
