"""core.common.types — attack_agent 공통 타입 정본.

설계 정본: 06(tool 인터페이스) · 11(KB/Legality) · 04(레지스트리) · 18/19(구현결정).
아카이브 규격 계승: crs/common/core.py 의 ToolSuccess[T]|ToolError · AgentAction ·
Message · ToolCall (동일 봉투 / 이질 payload).

원칙(06):
  P2 공격자-가시 폐포 — 결과 타입에 ground-truth 필드 없음(완전분리를 타입으로 보장).
  P3 닫힌 행동 — id는 Literal 화이트리스트, Planner는 고를 수만 있음.

PEP695 제네릭(py3.12+) 사용. 아카이브 core.py 미러.
작성 2026-07-05.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import Annotated, Any, Literal, Mapping, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ═══════════════════════════════════════════════════════════════════════════
# 1. 닫힌 어휘 enum (06 §3 · 04 §1 · 11 §1) — KB·legality·목표판정이 이 어휘로 닫힘
# ═══════════════════════════════════════════════════════════════════════════


class Layer(str, Enum):
    """공격 계층 (02). RECON = 각 계층의 상태불변 첫 단계."""

    A = "A"          # 무선·단말
    B = "B"          # 코어망
    C = "C"          # 암호·키
    D = "D"          # C2 응용
    RECON = "RECON"  # 정찰 (전 계층 공용)


class ToolKind(str, Enum):
    """상태불변(PROBE/COLLECT=RO) vs 상태변경(INJECT) 1차 구분 (06 §2-1)."""

    PROBE = "PROBE"      # 정찰 (상태불변)
    COLLECT = "COLLECT"  # 수집 (RO exfil/inspect)
    INJECT = "INJECT"    # 주입 (상태변경)


class Risk(str, Enum):
    """HITL 게이트 결정 (06). HIGH -> 승인 필요 (04 불변식 2)."""

    LOW = "LOW"
    MED = "MED"
    HIGH = "HIGH"


class WinCause(str, Enum):
    """보고서/BlockProof 라벨. 흐름엔 미사용 (06 §2-1: 정직성—판정과 분리)."""

    CRYPTO_BREAK = "crypto-break"
    KEY_LEAK = "key-leak"
    CONFIG_FLAW = "config-flaw"
    BASELINE = "baseline"
    DEFENSE_PROOF = "defense-proof"
    NONE = "none"  # recon 등 판정 무관


class BlockedBy(str, Enum):
    """ADAPT 피벗 키 (06 §2-3). 파싱응답에서 도출(하드코딩 금지—정직)."""

    SIGNING = "signing"
    AUTH = "auth"
    NO_EFFECT = "no_effect"
    TIMESTAMP = "timestamp"
    BASELINE = "baseline"


class Status(str, Enum):
    """실행 결과 대분류 (06 §2-3, 흐름 분기)."""

    OK = "OK"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


class ReachTarget(str, Enum):
    """reach(X) 대상 (04 §1 · 11 §1-A). 도달가능 노드."""

    NET_CORE = "net_core"
    MONGO = "mongo"
    # DEPRECATED: 어떤 tool 도 reach(upf_pfcp) 를 산출하지 않아 precond 로 쓰면 dead.
    #   pfcp_delete/pfcp_flood 는 reach(NET_CORE) 로 통일됨(registry.py). 하위호환 위해 값만 유지.
    UPF_PFCP = "upf_pfcp"
    S1U = "s1u"
    PIVOT = "pivot"
    SGI = "sgi"
    GCS14555 = "gcs14555"
    GCS14556 = "gcs14556"
    WEB8080 = "web8080"
    UAV5762 = "uav5762"
    TELEMETRY_TAP = "telemetry_tap"


class Artifact(str, Enum):
    """보유 아티팩트 (04 §1 · 11 §1-B). produces<->consumes 연결점."""

    K_OPC = "k_opc"
    IMSI = "imsi"
    ARIA_KEY = "aria_key"
    SIGN_KEY = "sign_key"
    CIPHERTEXT = "ciphertext"
    PCAP = "pcap"
    SEID = "seid"


class PredKind(str, Enum):
    """환경 술어 종류 (06 §3 Predicate). Fact.pred.

    signing 은 boolean-presence 술어가 아니라 3-값 scalar(on/off/unknown)이므로
    Scalars.signing 으로만 표현(PredKind.SIGNING 제거 — 정보 술어 중복 정리).
    """

    ATTACHED = "attached"
    REACH = "reach"                        # arg = ReachTarget value
    UNAUTH = "unauth"                      # arg ∈ {mongo, web}
    IN_FLIGHT = "in_flight"
    HOST_ACCESS = "host_access"            # arg = 호스트/컨테이너 명
    CONTAINER_ACCESS = "container_access"  # arg = zone
    WEAKCRED = "weakcred"                  # arg = pivot


# ═══════════════════════════════════════════════════════════════════════════
# 2. Fact — boolean-presence 술어 (11 §1-A). frozen -> set/subset 판정 가능.
# ═══════════════════════════════════════════════════════════════════════════


class Fact(BaseModel):
    """세계상태 KB의 참인 boolean 사실. 없으면 '미확인'(보수원칙, 11 §1-D).

    frozen=True -> hashable -> WorldState.facts: set[Fact], `f in facts` 판정.
    """

    model_config = ConfigDict(frozen=True)

    pred: PredKind
    arg: Optional[str] = None

    def __str__(self) -> str:  # 로그/missing 힌트 표시용
        return self.pred.value if self.arg is None else f"{self.pred.value}({self.arg})"


# ── Fact 생성 헬퍼 (04/11 어휘. 임의 문자열 방지) ──
ATTACHED = Fact(pred=PredKind.ATTACHED)
IN_FLIGHT = Fact(pred=PredKind.IN_FLIGHT)


def reach(t: ReachTarget | str) -> Fact:
    return Fact(pred=PredKind.REACH, arg=t.value if isinstance(t, ReachTarget) else t)


def unauth(svc: str) -> Fact:
    return Fact(pred=PredKind.UNAUTH, arg=svc)


def host_access(c: str) -> Fact:
    return Fact(pred=PredKind.HOST_ACCESS, arg=c)


def container_access(zone: str) -> Fact:
    return Fact(pred=PredKind.CONTAINER_ACCESS, arg=zone)


def weakcred(x: str = "pivot") -> Fact:
    return Fact(pred=PredKind.WEAKCRED, arg=x)


# ═══════════════════════════════════════════════════════════════════════════
# 3. Effect — 상태 전이 선언 (06 §3). SetMode / Disrupt / Cond (조건부).
# effect_eval(11 §2)의 입력. 조건부로 방어상태 의존성 인코딩 -> ADAPT 유도.
# ═══════════════════════════════════════════════════════════════════════════


class CondWhen(str, Enum):
    """Cond.when 닫힌 조건 (감사가능). 결정론 legality가 scalars에 평가."""

    SIGNING_OFF = "signing==off"  # 서명 off일 때만 효과 성립 (oracle/forge_aria/replay)
    NEVER = "never"               # 항상 미성립 (naive baseline — 대조군)


class SetMode(BaseModel):
    """mode := param 값. ack.accepted 시 KB.scalars.mode 갱신 (11 §3-A)."""


    model_config = ConfigDict(frozen=True)
    kind: Literal["set_mode"] = "set_mode"
    mode_param: str = "mode"  # params 중 mode 값을 읽는 키


class Disrupt(BaseModel):
    """c2 := disrupted. ack 시 KB.scalars.c2 갱신."""


    model_config = ConfigDict(frozen=True)
    kind: Literal["disrupt"] = "disrupt"


class SetFlag(BaseModel):
    """flag := true. ack 시 KB.flags 에 flag 추가 (04 §1 효과상태: subscriber_written 등).

    boolean-presence 세계상태 플래그(mode/c2 처럼 scalar 아님). goal 판정엔 미사용.
    """


    model_config = ConfigDict(frozen=True)
    kind: Literal["set_flag"] = "set_flag"
    flag: str  # 예: "subscriber_written"


class Cond(BaseModel):
    """조건부 효과. when 충족 -> then, 아니면 Blocked(else_blocked) (06 §3).

    effect_eval: signing==on -> Blocked / off -> then / unknown -> Uncertain (11 §2).
    """


    model_config = ConfigDict(frozen=True)
    kind: Literal["cond"] = "cond"
    when: CondWhen
    then: Union[SetMode, Disrupt] = Field(discriminator="kind")
    else_blocked: BlockedBy


Effect = Annotated[Union[SetMode, Disrupt, SetFlag, Cond], Field(discriminator="kind")]


# ═══════════════════════════════════════════════════════════════════════════
# 4. ParamSpec / ExecBinding — ToolSpec 구성요소
# ═══════════════════════════════════════════════════════════════════════════


class ParamSpec(BaseModel):
    """타입된 파라미터 명세 (06 §2-1 params). 스키마 검증으로 오·주입 방지."""


    model_config = ConfigDict(frozen=True)
    type: Literal["int", "str", "bool"]
    choices: Optional[tuple[Union[int, str], ...]] = None  # enum 제약 (예: mode ∈ {0,4,5,9})
    required: bool = True
    default: Union[int, str, bool, None] = None
    desc: str = ""


class ExecBinding(BaseModel):
    """safe-exec 바인딩 (06 §2-1 exec · 04 §4). 닫힘 강제점 2.: 이 경로로만 실행.

    exec_binding 정본 = 사이드카 baked 스크립트 (19 PART2 C5).

    secret_params (R6·ADV-F5): vault->**stdin** 라우팅되는 비밀 param/artifact 이름.
      argv 금지(누수). 이 이름들은 args_template 에 **원문이 나타나면 안 됨**;
      실행기가 vault 에서 값을 읽어 `printf %s | docker exec -i … --<name>-stdin` 로 주입.
      (예: forge_sign 의 sign_key, forge_aria 의 aria_key, replay 의 ciphertext.)
    """
    model_config = ConfigDict(frozen=True)
    sidecar: Literal["ue", "core", "sgi", "host"]  # 실행 발판 사이드카(vantage)
    script: str         # 이미지 baked 스크립트 경로 (04 §4)
    args_template: str = ""  # "{...}" params 치환 템플릿 (06 §5 예시). 비밀 원문 금지.
    secret_params: tuple[str, ...] = ()  # vault->stdin 라우팅 (argv 노출 금지, R6)


# ═══════════════════════════════════════════════════════════════════════════
# 5. ToolSpec — 정적 선언 = 레지스트리 1행 (06 §2-1)
# ═══════════════════════════════════════════════════════════════════════════

# 닫힘 강제점 1. (06): Planner 출력 id가 이 Literal 밖이면 거부. 22 원시 전량 (04 §5, V2-D36).
ToolId = Literal[
    # RECON (상태불변 · 각 계층 첫 단계)
    "recon_reach",
    "recon_defense",
    "recon_session",
    "capture_downlink",
    "observe_mode",
    # 계층 A — 무선·단말
    "serial5762",
    "s1u_capture",
    # 계층 B — 코어망
    "subdb_dump",
    "subdb_canary",
    "pfcp_delete",
    "pfcp_flood",
    "pivot_exploit",
    # 계층 C — 암호·키
    "key_extract",
    "signkey_leak",
    "nonce_scan",
    # 계층 D — C2 응용
    "oracle",
    "webcmd",
    "forge_sign",
    "forge_aria",
    "replay",
    "peer_flood",
    "forceland",
    "naive",
]


class ToolSpec(BaseModel):
    """레지스트리 1행. '무엇을 필요로/바꾸는가'만 선언(P1 선언적>절차적).

    조합('어떻게')은 미포함 -> 레시피 없이 precond/consumes/produces/effect로 창발.
    """

    model_config = ConfigDict(frozen=True)

    id: ToolId
    layer: Layer
    kind: ToolKind

    # ── 조합 필드 (04 §3) ──
    precond: tuple[Fact, ...] = ()               # 환경 전제 (AND · Legality 게이트 입력)
    require_any: tuple[tuple[Fact, ...], ...] = ()  # 사실 OR-그룹들 (각 그룹 ≥1, 그룹 간 AND)
    require_any_artifact: tuple[tuple[Artifact, ...], ...] = ()  # 아티팩트 OR-그룹 (nonce_scan)
    consumes: tuple[Artifact, ...] = ()          # 필요 아티팩트 (produces->consumes 창발 엣지)
    produces: tuple[Artifact, ...] = ()          # 산출 아티팩트 -> KB 갱신·후속 tool 활성
    produces_facts: tuple[Fact, ...] = ()        # recon류 산출 사실(백워드체이닝 표시용)
    effect: Optional[Effect] = None              # 상태 전이 (목표도달 판정 대상)

    # ── 메타 (06 §2-1) ──
    params: Mapping[str, ParamSpec] = Field(default_factory=dict)
    risk: Risk = Risk.LOW
    reversible: bool = True
    win_cause: WinCause = WinCause.NONE
    exec_binding: ExecBinding

    @model_validator(mode="after")
    def _freeze_params(self) -> ToolSpec:
        # frozen 모델에서도 내부 dict 변조를 막기 위해 read-only view로 고정한다.
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))
        return self


class ToolCall(BaseModel):
    """Planner 출력 (06 §2-2). id는 고를 수만 있음(생성 불가). params=열린 조합 축.

    주의 의도적 부재(03): '왜 이 조합인가'·다음단계 힌트를 Call에 넣지 않음 -> 레시피 차단.
    """

    model_config = ConfigDict(extra="ignore")

    id: ToolId
    params: dict[str, Any] = Field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════
# 6. 아카이브 봉투 계승 (crs/common/core.py) — AgentAction · Message · ToolResult
# 동일 봉투 / 이질 payload T. Ok->ToolSuccess / Err->ToolError (tool_wrap).
# ═══════════════════════════════════════════════════════════════════════════


class ToolCallFunction(BaseModel):
    """OpenAI tool-call 포맷 (core.py 미러)."""

    model_config = ConfigDict(extra="ignore")
    name: str
    arguments: str  # JSON str


class LLMToolCall(BaseModel):
    """LLM 응답의 tool_call (OpenAI 포맷, core.py ToolCall 미러).

    주의: 우리 Planner용 닫힌 ToolCall(위)과 구분. 이건 wire 포맷.
    """

    model_config = ConfigDict(extra="ignore")
    id: str
    function: ToolCallFunction
    type: Literal["function"] = "function"


class Message(BaseModel):
    """대화 메시지 (core.py Message 미러). viewer 로그 스키마 계승 (REF §6)."""

    model_config = ConfigDict(extra="ignore")
    role: str
    content: Optional[str] = None
    thinking_blocks: Optional[list[dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None
    tool_calls: Optional[list[LLMToolCall]] = None


class AgentAction(BaseModel):
    """tool이 루프를 제어 (core.py 미러). HITL·중단 표현.

    default []·AgentAction()는 pydantic magic deepcopy로 안전 (core.py 주석).
    """

    stop: bool = False
    append: list[Message] = []
    rewind: int = 0


class ToolError(BaseModel):
    """실패 통일 (core.py 미러). 모든 tool 실패 = ToolError."""

    error: str
    extra: Optional[dict[str, Any]] = None
    action: AgentAction = AgentAction()

    def __init__(
        self,
        error: str,
        extra: Optional[dict[str, Any]] = None,
        action: Optional[AgentAction] = None,
    ) -> None:
        super().__init__(error=error, extra=extra, action=action or AgentAction())


class ToolSuccess[T](BaseModel):
    """성공 payload는 제네릭 T (kind별 이질: ReconResult/CollectResult/InjectResult).

    core.py ToolSuccess[T] 미러 (PEP695).
    """

    result: T
    action: AgentAction = AgentAction()

    def __init__(self, result: T, action: Optional[AgentAction] = None) -> None:
        super().__init__(result=result, action=action or AgentAction())


# 모든 tool의 통일 반환 봉투 (REF §1). 동일 봉투 / 이질 내용.
type ToolResult[T] = ToolSuccess[T] | ToolError





