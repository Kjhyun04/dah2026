"""core.common.models — MODEL_MAP 로더 (A5 · 07 §4 · 08 litellm · aixcc configs/models-final.toml).

역할: agent-role → **litellm-routable 모델 id** 매핑을 config 밖(`configs/models.yaml`)으로
  외부화한다(하드코딩 0). live 캠페인에서 `driver.build_orchestrator` 가 이 맵으로
  AttackOrchestrator 의 실제 모델 문자열을 해석한다.

설계 정합:
  - aixcc `configs/models-final.toml` 의 MODEL_MAP[AgentName] 패턴을 YAML 로 미러.
  - LLM 은 1곳(AttackOrchestrator, 07 §1.5). Planner/Evidence 분리 시 확장 슬롯만 추가.
  - 비밀 0: API 키는 여기 없다. `config.llm.api_key_env` 가 가리키는 **env 이름**으로만
    (litellm 이 런타임에 그 env 를 읽어 provider 인증). 모델 문자열엔 비밀 미포함.
  - friendly名(예: 'claude-opus-4-8') → provider-routable('openrouter/anthropic/...') 는
    `aliases` 로 해석(config.llm.model 이 friendly名이어도 live 에서 라우팅 가능).

정직한 한계(A5 미결 유래): OpenRouter/Anthropic 의 정확한 provider slug 는 런타임 카탈로그
  종속이라 `configs/models.yaml` 값은 **운영자가 자기 계정 카탈로그로 확정**해야 한다.
  본 로더는 '맵을 읽어 라우팅한다'만 보장하고 slug 정확성은 강제하지 않는다.
작성 2026-07-06.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field


class ModelParams(BaseModel):
    """live 호출 기본 파라미터(오케스트레이터가 필요 시 참조). temp 0.7 고정(18 A6)."""

    model_config = ConfigDict(extra="forbid")

    temperature: float = 0.7
    tool_choice: str = "required"


class ModelMap(BaseModel):
    """MODEL_MAP 정본(`configs/models.yaml`).

    default : role 미등록 시 폴백 routable id.
    models  : {agent-role: routable id}. AttackOrchestrator 필수 권장.
    aliases : {friendly名: routable id}. config.llm.model(friendly) 해석용.
    params  : live 기본 파라미터.
    """

    model_config = ConfigDict(extra="forbid")

    default: str
    models: dict[str, str] = Field(default_factory=dict)
    aliases: dict[str, str] = Field(default_factory=dict)
    params: ModelParams = Field(default_factory=ModelParams)

    def route(self, name: str) -> str:
        """friendly名이면 alias 로 routable 치환, 이미 routable 이면 그대로."""
        return self.aliases.get(name, name)


def load_model_map(path: str | Path) -> ModelMap:
    """`configs/models.yaml` → ModelMap. 설정됐는데 파일 부재 → FileNotFoundError(명시 실패).

    스키마 위반 → pydantic ValidationError(열린값/오타 거부). 비밀 미포함(모델 문자열만).
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"models_path 지정됐으나 파일 없음: {p}")
    data: Any = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"models.yaml 최상위는 매핑이어야 함: {p}")
    return ModelMap(**data)


def resolve_model(
    role: str, mm: ModelMap, *, override: Optional[str] = None
) -> str:
    """role → routable 모델 id. 해석 우선순위(결정론):

    ① override(=config.llm.model) 가 주어지면 그것을 alias 라우팅해 우선(운영자 명시 존중).
    ② 아니면 models[role] → ③ 없으면 default. 전부 alias 라우팅.
    """
    if override:
        return mm.route(override)
    if role in mm.models:
        return mm.route(mm.models[role])
    return mm.route(mm.default)


__all__ = ["ModelMap", "ModelParams", "load_model_map", "resolve_model"]
