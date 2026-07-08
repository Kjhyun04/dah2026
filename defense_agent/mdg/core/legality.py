"""Legality gate (H-F/H-G) — pure precondition check. Used by select_policy to
build the legal set AND re-checked by act as a pre-hook (PA-6) against the CURRENT
worldstate + pinned config_version (X7 TOCTOU).

Deterministic, no side effects. Illegal -> raise CRSError (act converts to
side-effect-0 early return).
"""
from __future__ import annotations

from ..tools.defresult import CRSError
from ..tools.registry import REGISTRY
from .state import Action, MDGState
from .worldstate import WorldState, signing_enforced


def _resolve_role_key(action: Action | None, alias: str) -> str:
    """Map a registry ``role_verified.<alias>`` predicate to the CONTAINER KEY the chosen
    action actually operates on (step 10 — dynamic binding).

    The registry pins a LITERAL alias ('role_verified.target' / '.gcs') as a placeholder; the
    REAL selector is the action's ``enforce_at`` ENFORCEMENT-container key (finding P4-2 — the
    netns/entity whose posture the action changes), falling back to the ``target`` selector when
    ``enforce_at`` is absent. ``role_verified`` is CONTAINER-keyed (uav_ue/gcs_proxy/web_backend),
    so the concrete params key — NOT the fictional alias — is the thing that must be verified.
    Fail-closed: no action or no concrete container selector -> "" -> caller reads illegal (a
    fictional alias key can no longer admit a candidate; self-DoS gate stays closed)."""
    if action is None:
        return ""
    params = getattr(action, "params", None) or {}
    for k in ("enforce_at", "target"):
        v = params.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _predicate_holds(world: WorldState, pred: str, action: Action | None = None) -> bool:
    """Evaluate a closed predicate string like 'reach.gcs14556' / 'signing' /
    'role_verified.target' against worldstate."""
    if "." not in pred:
        # scalar predicates
        if pred == "signing":
            # P2-Q2: only CONFIRMED_ON is enforced. UNKNOWN (unconfirmed) is NOT legal —
            # send_signed_mode must not depend on an unconfirmed auth control (conservative).
            return signing_enforced(world.signing)
        if pred == "config_version":
            return bool(world.config_version)
        # capability preconds (ingest_key/operator_cert) are environment-provided;
        # treated as satisfied at the world layer (verified elsewhere).
        return pred in ("ingest_key", "operator_cert")
    head, key = pred.split(".", 1)
    if head == "role_verified":
        # DYNAMIC binding (step 10): resolve the LITERAL registry alias ('target'/'gcs') to the
        # chosen action's REAL enforcement-container KEY (params.enforce_at, else params.target)
        # and verify role_verified[<that container>]. role_verified is CONTAINER-keyed; the alias
        # is only a placeholder, so a fictional key no longer satisfies legality. Fail-closed:
        # unresolved selector OR container absent/False -> illegal (self-DoS gate stays shut).
        # Deterministic — reads a single bool, NO LLM field (불변식①).
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
    """Return (legal, reason). Closed 3-fold: registered id ∧ preconds ∧ config pin."""
    spec = REGISTRY.get(action.tool_id)
    if spec is None:
        return False, f"unregistered tool_id: {action.tool_id}"                 # ghost/dangling
    if config_version and world.config_version and config_version != world.config_version:
        return False, "config_version mismatch (TOCTOU pin, X7)"
    for pred in spec.requires:
        # capability preconds that are env-provided pass; posture preds must hold
        if pred in ("config_version",):
            continue
        if not _predicate_holds(world, pred, action):
            return False, f"unmet precondition: {pred}"
    return True, "legal"


def assert_legal(action: Action, state: MDGState) -> None:
    """act pre-hook (PA-6): re-check against current worldstate + pinned version.
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
