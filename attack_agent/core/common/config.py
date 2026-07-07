"""core.common.config — InputSpec 입력 규격 + config/goal 로더 (문서 10 정본).

심사원이 "무엇을 입력하면 되는지"를 완전히 명시(doc10). 두 파일 + env + 실행인자:
  ① config.yaml → InputSpec (환경·타깃·실행제어).  load_config(path) -> InputSpec
  ② goal.yaml   → Goal      (선언적 목표).           load_goal(path)  -> kb.Goal
  ③ env vars    → 비밀(값)  . config 엔 env var **이름**만 저장(resolve_secret 로 조회).

원칙(doc10 §3, D3 계승):
  - 하드코딩 0 : 코드에 IP/키/경로/컨테이너명 0개 — 전부 InputSpec 입력.
  - 비밀 = env var **이름** 참조 : llm.api_key_env·supervisor.aria_key_env 는 이름만.
  - 필수 누락 → 즉시 ValidationError : 완전명시 강제(doc15 §3-A). 기본값 금지 필드 존재.
  - 닫힌 어휘 : exec.mode·goal.{defense,success}·llm.mode 는 Literal 로 오타/열린값 거부.

설계 결정(gap 해소):
  - G34(exec 스키마 상반): doc10 §2-A 표(정본)의 `exec.vantage.{ue,sgi,core}`(구조형)를
    정본으로 채택. §5 예시의 `exec.sidecar`(단수)는 sgi/core 를 표현 못해 폐기.
  - targets 스키마(doc10 §2-B): 고정 role 키 10종(TgtSpec)으로 닫음(extra=forbid, 오타 검출).
    값은 컨테이너 **이름** 권장 — IP 는 런타임 docker inspect 해석(P3 스코프 밖).
  - 필드 그룹핑(doc10 §2-F): viewer.port·supervisor.* 는 **최상위**(doc10 정본 그룹핑).
  - termination_timeout : '30s'(문자열)·30(정수) 모두 수용(_parse_duration).
  - goal.target : 'mode=4'(문자열) · {mode: 4}(매핑) 둘 다 수용(parse_goal_target, G27).

작성 2026-07-05.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, Mapping, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from core.common.types import Fact, container_access, host_access, weakcred
from core.modules.kb import Goal

# ═══════════════════════════════════════════════════════════════════════════
# 0. 유틸 — duration 파싱 / 술어 문자열 분해
# ═══════════════════════════════════════════════════════════════════════════


def _parse_duration(v: Any) -> int:
    """종료 타임아웃 정규화 (doc10 '30s' 문자열 ↔ doc15 30 정수). 초 단위 int 반환.

    수용: 30 / 30.0 / '30' / '30s' / '2m'. bool 은 거부(오매칭 방지).
    """
    if isinstance(v, bool):
        raise ValueError(f"invalid duration: {v!r}")
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if not s:
            raise ValueError("empty duration")
        if s.endswith("ms"):
            return int(round(int(s[:-2]) / 1000))
        if s.endswith("s"):
            return int(s[:-1])
        if s.endswith("m"):
            return int(s[:-1]) * 60
        if s.endswith("h"):
            return int(s[:-1]) * 3600
        return int(s)
    raise ValueError(f"invalid duration: {v!r}")


def _split_pred(raw: str) -> tuple[str, Optional[str]]:
    """'name(arg)' → ('name','arg'), 'name' → ('name', None). 공백 정리."""
    s = str(raw).strip()
    if s.endswith(")") and "(" in s:
        name, rest = s.split("(", 1)
        arg = rest[:-1].strip()
        return name.strip(), (arg or None)
    return s, None


# ═══════════════════════════════════════════════════════════════════════════
# 1. 하위 모델 (doc10 §2 표 — 필수/기본값 정확 반영)
# ═══════════════════════════════════════════════════════════════════════════


class TestbedSpec(BaseModel):
    """2-A 환경/접속. 3필드 전부 필수(완전명시 강제)."""

    model_config = ConfigDict(extra="forbid")

    host: str
    user: str
    ssh_key: str


class VantageSpec(BaseModel):
    """2-A exec.vantage. ue·sgi 필수, core 옵션(pivot 후 net_core)."""

    model_config = ConfigDict(extra="forbid")

    ue: str
    sgi: str
    core: Optional[str] = None


class ExecSpec(BaseModel):
    """2-A 실행제어 묶음. mode 기본 docker_exec (닫힌 어휘)."""

    model_config = ConfigDict(extra="forbid")

    vantage: VantageSpec
    mode: Literal["docker_exec", "ssh", "host"] = "docker_exec"


class ImageSpec(BaseModel):
    """2-A tools.image. air 필수(MAV 툴링), pfcp 옵션."""

    model_config = ConfigDict(extra="forbid")

    air: str
    pfcp: Optional[str] = None


class ToolsSpec(BaseModel):
    """2-A tools. image 하위(tools.image.air)."""

    model_config = ConfigDict(extra="forbid")

    image: ImageSpec


class TgtSpec(BaseModel):
    """2-B 타깃. 고정 role 키 10종(doc10 §2-B). 값=컨테이너 이름 권장(IP 런타임 해석).

    전부 옵션(None) — 목표별로 필요한 키만 채우면 됨(예: c2_disrupt 는 signkey 불요).
    extra=forbid 로 오타 role 검출(닫힌 어휘).
    """

    model_config = ConfigDict(extra="forbid")

    uav5762: Optional[str] = None   # A: SITL 시리얼 직결
    s1u: Optional[str] = None       # A: SGW-U(S1-U 캡처)
    mongo: Optional[str] = None     # B: 가입자DB
    pfcp_upf: Optional[str] = None  # B: PFCP
    pivot: Optional[str] = None     # B: 측면이동 pivot
    uav_proxy: Optional[str] = None  # C: ARIA키 docker inspect 대상
    signkey: Optional[str] = None   # C: 서명키 노출 경로
    oracle: Optional[str] = None    # D: 평문 오라클
    cipher: Optional[str] = None    # D: ARIA 암호문
    web: Optional[str] = None       # D: web /api/cmd


class SupervisorSpec(BaseModel):
    """2-B/2-F 감독. tap_container=복호 tap netns, aria_key_env=ARIA 키 env **이름**."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    tap_container: Optional[str] = None
    aria_key_env: Optional[str] = None  # env var 이름(값 아님)


class ObserverSpec(BaseModel):
    """Passive observer assist (non-load-bearing, default OFF)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    iface: str = "any"
    port: int = 14555
    sample_s: int = 2
    gap_s: int = 8
    quiet_pps: float = 0.5
    tcpdump_bin: str = "tcpdump"
    max_packets: int = 400


class EvidenceSpec(BaseModel):
    """LLM evidence narration assist (non-load-bearing, default OFF)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    temperature: float = 0.2
    max_chars: int = 260


class LlmSpec(BaseModel):
    """2-D LLM. 3필드 필수. api_key_env 는 env var **이름**(값은 config 미기재)."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    mode: Literal["live", "replay"]
    model: str
    api_key_env: str
    # (옵션·비파괴) MODEL_MAP 경로. 지정 시 driver 가 configs/models.yaml 로 role→routable
    #   모델을 해석(A5·07 §4). 미지정=None 이면 model 문자열을 그대로 사용(하위호환).
    models_path: Optional[str] = None


class RunSpec(BaseModel):
    """2-E 실행제어(전부 기본값). termination_timeout 은 '30s' 문자열도 수용."""

    model_config = ConfigDict(extra="forbid")

    max_iters: int = 30
    max_pivots: int = 8
    termination_timeout: int = 30
    hitl: bool = False
    budget: Optional[int] = None

    @field_validator("termination_timeout", mode="before")
    @classmethod
    def _norm_timeout(cls, v: Any) -> int:
        return _parse_duration(v)


class OutSpec(BaseModel):
    """2-F 산출. log=viewer 소스 JSONL."""

    model_config = ConfigDict(extra="forbid")

    log: str = "./run.jsonl"


class ViewerSpec(BaseModel):
    """2-F 뷰어. 최상위 viewer.port(doc10 정본 그룹핑)."""

    model_config = ConfigDict(extra="forbid")

    port: int = 8090


class PremiseSpec(BaseModel):
    """2-G 전제(APT 초기 발판, doc12). footholds 없는 계층은 정직히 봉쇄.

    footholds 예: ['container_access(sgi)', 'host_access(uav_proxy)'].
    weakcred_pivot=true → weakcred('pivot') 사실 추가(T2 측면이동 전제).
    """

    model_config = ConfigDict(extra="forbid")

    footholds: list[str] = []
    weakcred_pivot: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# 2. InputSpec — 최상위 규격 (config.yaml 전체)
# ═══════════════════════════════════════════════════════════════════════════


class InputSpec(BaseModel):
    """config.yaml 정본(doc10 §2). 필수 누락 → ValidationError.

    필수: testbed{host,user,ssh_key} · exec.vantage{ue,sgi} · tools.image.air ·
          llm{mode,model,api_key_env}. 나머지는 기본값.
    goal 은 여기 없음 — 별도 goal.yaml(load_goal)로 분리(doc10 §1).
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    testbed: TestbedSpec
    exec_: ExecSpec = Field(alias="exec")  # 'exec'(파이썬 빌트인) 회피 → 별칭
    tools: ToolsSpec
    tgt: TgtSpec = Field(default_factory=TgtSpec)
    supervisor: SupervisorSpec = Field(default_factory=SupervisorSpec)
    observer: ObserverSpec = Field(default_factory=ObserverSpec)
    evidence: EvidenceSpec = Field(default_factory=EvidenceSpec)
    llm: LlmSpec
    run: RunSpec = Field(default_factory=RunSpec)
    out: OutSpec = Field(default_factory=OutSpec)
    viewer: ViewerSpec = Field(default_factory=ViewerSpec)
    premise: PremiseSpec = Field(default_factory=PremiseSpec)

    def premise_facts(self) -> list[Fact]:
        """premise → Fact 리스트(WorldState.initial(footholds=...) 주입용)."""
        return footholds_to_facts(self.premise.footholds, self.premise.weakcred_pivot)


# ═══════════════════════════════════════════════════════════════════════════
# 3. GoalSpec — goal.yaml (kb.Goal 상위집합. to_goal() 로 축약 브리지)
# ═══════════════════════════════════════════════════════════════════════════


def parse_goal_target(raw: str | dict | None, goal_type: Optional[str]) -> dict[str, Any]:
    """G27 파싱 규약. 'mode=4'→{'mode':'4'} · 'artifact=sign_key'→{...} · dict 통과.

    '='로 key=value 분할. '=' 없는 bare 문자열은 goal_type 로 키 추론
      (exfil→artifact, mode_set/signing_bypass→mode). int 강제는 하류 kb._as_int 위임.
    """
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {}
        if "=" in s:
            k, v = s.split("=", 1)
            return {k.strip(): v.strip()}
        if goal_type == "exfil":
            return {"artifact": s}
        if goal_type in ("mode_set", "signing_bypass"):
            return {"mode": s}
        return {"value": s}
    # 숫자 등 스칼라 — 목표별 기본 키로 감쌈
    if goal_type in ("mode_set", "signing_bypass"):
        return {"mode": raw}
    return {"value": raw}


def parse_goal_expr(expr: str) -> dict[str, Any]:
    """CLI goal 문자열 파서.

    형식:
      "<type> <target-or-kv> [defense=on|off|auto] [success=ack|ground_truth] [scope=A,B,C]"

    예:
      "mode_set mode=4"
      "signing_bypass mode=5 defense=on success=ack scope=A,C,D"
      "exfil artifact=sign_key"
    """
    s = str(expr).strip()
    if not s:
        raise ValueError("empty goal expression")
    toks = s.split()
    gtype = toks[0]
    target_tokens: list[str] = []
    meta: dict[str, Any] = {}
    for tok in toks[1:]:
        if "=" not in tok:
            target_tokens.append(tok)
            continue
        k, v = tok.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k in {"defense", "success", "scope"}:
            meta[k] = v
        else:
            target_tokens.append(tok)
    target_raw = " ".join(target_tokens).strip()
    node: dict[str, Any] = {"type": gtype, "target": target_raw}
    if "defense" in meta:
        node["defense"] = meta["defense"]
    if "success" in meta:
        node["success"] = meta["success"]
    if "scope" in meta:
        node["scope"] = [x.strip() for x in str(meta["scope"]).split(",") if x.strip()]
    return node


class GoalSpec(BaseModel):
    """2-C 목표(선언적). type·target 필수. kb.Goal 상위집합(+defense/success/scope).

    to_goal() 로 기존 kb.Goal(type,target,scope) 축약 — goal_reached()/kb 경로 불변.
    defense/success 는 부트스트랩 후속(signing 시드·판정모드) 소비처가 P3 스코프 밖이라
    여기 보존만 하고 to_goal() 에는 싣지 않음(하위호환).
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["mode_set", "c2_disrupt", "exfil", "signing_bypass"]
    target: dict[str, Any] = {}
    defense: Literal["on", "off", "auto"] = "auto"
    success: Literal["ack", "ground_truth"] = "ack"
    scope: list[str] = []

    @field_validator("target", mode="before")
    @classmethod
    def _parse_target(cls, v: Any, info: ValidationInfo) -> dict[str, Any]:
        return parse_goal_target(v, info.data.get("type"))

    @field_validator("scope")
    @classmethod
    def _norm_scope(cls, v: list[str]) -> list[str]:
        # 계층코드 정규화(대문자 트림). 빈 리스트=전체(미지정 등가).
        return [str(s).strip().upper() for s in v if str(s).strip()]

    def to_goal(self) -> Goal:
        """하위호환 브리지 → kb.Goal. scope 빈 리스트는 None(=전체)로 축약."""
        return Goal(type=self.type, target=self.target, success=self.success, scope=self.scope or None)


# ═══════════════════════════════════════════════════════════════════════════
# 4. premise → Fact 매핑 (footholds → WorldState.initial)
# ═══════════════════════════════════════════════════════════════════════════


def _foothold_to_fact(item: str) -> Optional[Fact]:
    """단일 foothold 문자열 → Fact. 닫힌 어휘 {host_access, container_access, weakcred}.

    인자 없는 host_access/container_access 는 대상 컨테이너 미상 → 보수적 skip(None)
      (하드코딩 0: 임의 기본 컨테이너명 금지). weakcred 는 라이브러리 기본 'pivot' 사용.
    어휘 밖 이름 → skip(None) — 정직성(fact 미주입=해당 계층 봉쇄).
    """
    name, arg = _split_pred(item)
    if name == "host_access":
        return host_access(arg) if arg else None
    if name == "container_access":
        return container_access(arg) if arg else None
    if name == "weakcred":
        return weakcred(arg) if arg else weakcred()
    return None


def footholds_to_facts(
    footholds: list[str], weakcred_pivot: bool = False
) -> list[Fact]:
    """premise → Fact 리스트. types.py 헬퍼 재사용. 중복 제거, 순서 보존.

    weakcred_pivot=True 면 weakcred('pivot') 추가. 파싱 불가 항목은 조용히 skip(정직).
    """
    facts: list[Fact] = []
    seen: set[Fact] = set()
    for item in footholds or []:
        f = _foothold_to_fact(item)
        if f is not None and f not in seen:
            seen.add(f)
            facts.append(f)
    if weakcred_pivot:
        wf = weakcred("pivot")
        if wf not in seen:
            seen.add(wf)
            facts.append(wf)
    return facts


# ═══════════════════════════════════════════════════════════════════════════
# 5. 비밀 해석 — env var 이름 → 값 (config 엔 값 미기재)
# ═══════════════════════════════════════════════════════════════════════════


def resolve_secret(env_name: str, env: Optional[Mapping[str, str]] = None) -> str:
    """env var **이름** 참조 규칙(doc10 §3·4). 부트스트랩 시점에 값 조회.

    env 미지정 시 os.environ 사용. 이름 비었거나 미설정/빈값 → 명시적 에러.
    """
    e: Mapping[str, str] = os.environ if env is None else env
    if not env_name:
        raise ValueError("resolve_secret: empty env var name")
    if env_name not in e:
        raise KeyError(f"secret env var not set: {env_name}")
    val = e[env_name]
    if val == "":
        raise ValueError(f"secret env var is empty: {env_name}")
    return val


# ═══════════════════════════════════════════════════════════════════════════
# 6. 로더 (YAML → 검증된 모델). PyYAML safe_load.
# ═══════════════════════════════════════════════════════════════════════════


def _load_yaml(path: str | Path) -> Any:
    import os
    import re

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config file not found: {p}")
    text = p.read_text(encoding="utf-8")

    # ${VAR} / ${VAR:-default} → os.environ 치환. 배포 의존값(테스트베드 IP·SSH키 등)을
    #   .env 로 외부화(하드코딩 0). 미설정+기본없음 → 원문 유지(명시 실패 유도).
    def _sub(m):  # type: ignore[no-untyped-def]
        val = os.environ.get(m.group(1))
        if val:
            return val
        return m.group(2) if m.group(2) is not None else m.group(0)

    text = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}", _sub, text)
    return yaml.safe_load(text)


def load_config(path: str | Path) -> InputSpec:
    """config.yaml → InputSpec. 필수 누락/오타 → ValidationError(완전명시 강제)."""
    raw = _load_yaml(path)
    if not isinstance(raw, dict):
        raise ValueError(f"config root must be a mapping: {path}")
    return InputSpec.model_validate(raw)


def load_goal(path: str | Path) -> Goal:
    """goal.yaml → kb.Goal. 최상위 'goal:' 래퍼 수용(없으면 플랫 매핑으로 간주)."""
    raw = _load_yaml(path)
    if not isinstance(raw, dict):
        raise ValueError(f"goal root must be a mapping: {path}")
    node = raw.get("goal", raw)
    if not isinstance(node, dict):
        raise ValueError(f"goal.* must be a mapping: {path}")
    return GoalSpec.model_validate(node).to_goal()


def load_goal_spec(path: str | Path) -> "GoalSpec":
    """goal.yaml → GoalSpec 전체(defense/success 보존). defense→signing 시드 배선용."""
    raw = _load_yaml(path)
    node = raw.get("goal", raw) if isinstance(raw, dict) else raw
    if not isinstance(node, dict):
        raise ValueError(f"goal.* must be a mapping: {path}")
    return GoalSpec.model_validate(node)


def load_input(
    config_path: str | Path,
    goal_path: Optional[str | Path] = None,
    cli_goal: Optional[str] = None,
) -> tuple[InputSpec, Optional[Goal]]:
    """부트스트랩 로더(doc10 §1). config + (goal.yaml | --goal 문자열) 병합.

    cli_goal 형식(옵션): 'mode_set mode=4' — 첫 토큰=type, 나머지=target 문자열.
    goal_path·cli_goal 모두 없으면 goal=None(호출자가 별도 주입).
    """
    cfg = load_config(config_path)
    goal: Optional[Goal] = None
    if goal_path is not None:
        goal = load_goal(goal_path)
    elif cli_goal:
        goal = GoalSpec.model_validate(parse_goal_expr(cli_goal)).to_goal()
    return cfg, goal


__all__ = [
    "TestbedSpec",
    "VantageSpec",
    "ExecSpec",
    "ImageSpec",
    "ToolsSpec",
    "TgtSpec",
    "SupervisorSpec",
    "ObserverSpec",
    "EvidenceSpec",
    "LlmSpec",
    "RunSpec",
    "OutSpec",
    "ViewerSpec",
    "PremiseSpec",
    "InputSpec",
    "GoalSpec",
    "parse_goal_target",
    "parse_goal_expr",
    "footholds_to_facts",
    "resolve_secret",
    "load_config",
    "load_goal",
    "load_input",
]
