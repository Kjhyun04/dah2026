"""verify_tools — 26 tool 계약 완전·유령0·Literal 화이트리스트 (H-A/G · DESIGN §2).

강제:
  - DefToolId Literal 집합 == REGISTRY keys, 정확히 26 (유령 없음, 누락 없음)
  - 모든 spec 완전 등록 (owner/category/backend/consumes/produces/T)
  - response 도구는 exec(safe-exec)를 바인딩 AND effect 를 선언
  - send_signed_mode (flight) risk == HIGH (operator)
  - secret 은 stdin 으로 선언 (argv 절대 금지, R6)
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

    rep.check(len(reg_ids) == TOOL_COUNT == 26, f"registry has {len(reg_ids)} tools, expect 26")
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

    # response exec 바인딩은 safe_exec.* 를 참조해야 한다 (유일한 subprocess 소유자)
    for tid, spec in REGISTRY.items():
        if spec.category == "response":
            rep.check(spec.exec.startswith("safe_exec."),
                      f"{tid}: exec must bind safe_exec.* (got {spec.exec})")
    return rep


if __name__ == "__main__":
    run(_check)
