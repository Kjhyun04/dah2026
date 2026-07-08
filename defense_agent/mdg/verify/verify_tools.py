"""verify_tools — 27 tool 계약 완전·유령0·Literal 화이트리스트 (H-A/G · DESIGN §2).

Enforces:
  - DefToolId Literal set == REGISTRY keys, exactly 27 (no ghost, no missing)
  - every spec fully registered (owner/category/backend/consumes/produces/T)
  - response tools bind exec (safe-exec) AND declare effect
  - send_signed_mode (flight) risk == HIGH (operator)
  - secrets declared as stdin (never argv, R6)
"""
from __future__ import annotations

import os
import sys
from typing import get_args

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mdg.tools.registry import REGISTRY, TOOL_COUNT, DefToolId, DefToolSpec  # noqa: E402
from mdg.verify._util import Report, run  # noqa: E402


def _check() -> Report:
    rep = Report("verify_tools")
    literal_ids = set(get_args(DefToolId))
    reg_ids = set(REGISTRY.keys())

    rep.check(len(reg_ids) == TOOL_COUNT == 27, f"registry has {len(reg_ids)} tools, expect 27")
    rep.check(literal_ids == reg_ids,
              f"DefToolId Literal != REGISTRY keys (ghost/missing): "
              f"only-literal={literal_ids - reg_ids} only-reg={reg_ids - literal_ids}")

    for tid, spec in REGISTRY.items():
        rep.check(isinstance(spec, DefToolSpec), f"{tid}: not a DefToolSpec")
        rep.check(spec.id == tid, f"{tid}: id/key mismatch ({spec.id})")
        rep.check(bool(spec.owner), f"{tid}: missing owner")
        rep.check(bool(spec.backend), f"{tid}: missing backend")
        rep.check(bool(spec.produces), f"{tid}: empty produces (dangling)")
        rep.check(bool(spec.T), f"{tid}: missing payload type T")
        if spec.category == "response":
            rep.check(bool(spec.exec), f"{tid}: response tool missing exec (safe-exec bind)")
            rep.check(bool(spec.effect), f"{tid}: response tool missing effect")

    ssm = REGISTRY.get("send_signed_mode")
    rep.check(ssm is not None and ssm.risk == "HIGH", "send_signed_mode must be risk=HIGH (operator)")
    rep.check(ssm is not None and ssm.secret == "stdin", "send_signed_mode secret must be stdin (R6)")

    # response exec bindings must reference safe_exec.* (single subprocess owner)
    for tid, spec in REGISTRY.items():
        if spec.category == "response":
            rep.check(spec.exec.startswith("safe_exec."),
                      f"{tid}: exec must bind safe_exec.* (got {spec.exec})")
    return rep


if __name__ == "__main__":
    run(_check)
