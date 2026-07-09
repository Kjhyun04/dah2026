"""tighten_only 병합 — LOCKED 구현(core.advice, PA-5)의 재-export.

DESIGN_DECISIONS PA-5는 monotone 병합을 ``mdg/core/advice.py``에 고정한다(결정론적 core
내부의 orient node가 import하며, 이 core는 선택적 llm/ 의존성을 import해선 안 된다).
P3 범위는 이 파일을 ``llm/apply_advice.py``로 명명하지만, 동일한 단일 구현을 노출한다 —
분기된 복사본도, raise-only 공식의 두 번째 소스도 없다. 병합은 impact.band를
severity_bump(<=1)만큼만 올린다; ``assert new_band >= old_band``가 어떤 하향도 금지하므로,
LLM advice는 결정론적 공식을 관대한 쪽으로 뒤집을 수 없다.
"""
from __future__ import annotations

from ..core.advice import apply_advice, tighten_only

__all__ = ["apply_advice", "tighten_only"]
