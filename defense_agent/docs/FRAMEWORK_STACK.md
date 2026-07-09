# 방어 에이전트 프레임워크 스택 — LangGraph 기준 설계 (착수 스펙)

> 작성 2026-07-07 · 확정: **오케스트레이션 = LangGraph**, 관심사별 OSS 스택 채택.
> 대상: `DEFENSE_AGENT_V3_DESIGN.html`(도메인·형식 정본)의 §1 프레임워크 결정을 본 문서로 교체.
> 원칙: **"루프를 소유하는 단일 에이전트 프레임워크"가 아니라 "관심사별 라이브러리로서의 프레임워크"** — 2대 불변식만 손수 소유하면 나머지는 OSS로 가도 채점(결정론·replay·leak-0·grep0)이 안 깨진다.

---

## 0. 결정 요약

| 항목 | 결정 |
|---|---|
| **오케스트레이터** | **LangGraph `StateGraph`** (결정론 라우팅 규약 준수) |
| **LLM 접근(2 phase)** | **litellm** (LangChain LLM 래퍼 미사용) · models.yaml 역할별 폴백 |
| **타입/닫힌 행동공간/config** | **pydantic v2** + pyyaml |
| **Ingest 제어평면 :50051** | **grpcio + protobuf** (mTLS + 전체봉투 HMAC) |
| **Collector 폴링/파싱** | **httpx** · **pymavlink 2.4.49** · **scapy**(PFCP/GTP) · asyncio(stdlib) |
| **Verifier·Viewer(3패널)** | **FastAPI + uvicorn** (testbed 기존 스택 재사용) |
| **검증 스위트** | **pytest** |
| **실행/teardown** | ★ **프레임워크 없음 — 손수(Robo Duck safe-exec 계승)** |

**★ 2대 불변식(프레임워크 금지 구역):**
1. **결정론 제어흐름** — 분기는 결정론 파이프라인 수치로. LLM은 2노드만, temp=0, 조언 전용.
2. **누수-0 실행/teardown** — 도구 부작용은 손수 safe-exec 백엔드 경유. 프레임워크 subprocess 미사용. Verifier 별 프로세스(grep0).

---

## 1. LangGraph 그래프 설계

### 1.1 State 스키마 (pydantic / TypedDict)
```python
class MDGState(TypedDict):
    config_version: str          # 결정별 config 핀(X7 TOCTOU 방지)
    worldstate: WorldState       # 닫힌 술어/아티팩트(H-E): reach/signing/role_verified/threat/applied + ip_map/pid/baseline
    evidence: list[SensorEv]      # sense가 큐에서 드레인(비적재)
    trust: dict[str, TrustObj]    # 5도메인
    impact: ImpactObj             # 0-100, Green/Yellow/Red(M5)
    incidents: list[Incident]
    decisions: list[Decision]
    ledger: list[Intent]          # record_intent(guard 밖)
    verifier_truth: list[Truth]   # grep0 별경로 산출
    orient_note: OrientNote|None  # LLM1 조언(비권위)
    goal_reached: bool
```

### 1.2 노드 (결정론 기본 · LLM 2개만 명시)
```
recon        [결정론] 부팅 baseline: role→container→IP resolve+verify(H-I) · signing/nas/port맵 · InputSpec 로드 · provenance
sense        [결정론] Collector가 async push한 Evidence를 턴경계에서 WorldState merge (non-blocking, fail-open, G4)
correlate    [결정론] 시간창 동시발생(source_ip 조인 불가 — FEASIBILITY §2)
compute_trust[결정론] Trust 파이프라인(E5 conf 적대항만·E6 포화·E7 band→sev→dev표)
compute_impact[결정론] Impact 0-100 표준화(M5) + confidence 보수마진(E8 1회)
orient       ★LLM1  correlate/trust/impact 결과 위에 근거·신규성·모호성 1회. temp=0·structured·조언전용(E12)
select_policy[결정론] Legality 게이트로 legal 대응 집합 산출(H-F)
rank_recovery[결정론] recovery prior 정렬(FEASIBILITY §3)
decide       ★LLM2  6단계 래더+게이트 1회 판단. 경계 상향만·더 관대 자동 불가(E12)
act          [결정론] tool_wrap: pre[legality] → record_intent(guard밖) → safe-exec → post[world_update]
verify       [결정론·별경로] effect-confirm: ss/pcap/:9090/14560 HB+uav_ue lo:14550 교차탭(D-1)
```

### 1.3 조건부 엣지 (★결정론 라우팅 — LLM 자유선택 금지)
```
recon → sense
sense → correlate → compute_trust → compute_impact
compute_impact ──[band==Green]──▶ sense            # Green 틱은 LLM 미호출(E13/G6)
compute_impact ──[band∈{Yellow,Red}]──▶ orient
orient → select_policy → rank_recovery → decide
decide ──[legal ∧ risk≤MED ∧ reversible]──▶ act    # 가역 AUTO는 verifier 생존 무관(D-3)
decide ──[risk==HIGH(비행)]──▶ escalate(operator)   # 비행모드=operator-gate(X2), 키홀더 shim 강제(D-2)
decide ──[no legal action]──▶ sense
act → verify → sense
드라이버: goal_reached ∨ max_iters/max_pivots/k_dry → END. 안전행동(operator LAND)은 예산면제(G10)
```
> **핵심:** `add_conditional_edges`의 분기함수는 `impact.band`·`spec.risk`·`legal` **수치/불린**을 읽는다. **모델이 다음 노드를 못 고른다** → 바이트 replay·재현성 보존.

---

## 2. 2대 불변식 가드 (상세)

### 2.1 결정론 제어흐름
- 라우팅 = 결정론 파이프라인 출력. LLM 출력은 `orient_note`/`decide`의 **조언 필드**로만 상태에 들어가고, **엣지 조건에 안 쓰인다**.
- LLM 노드: litellm, `temperature=0`, pydantic `response_model`(structured), StrictUndefined 프롬프트(H-P), 빈프롬프트 가드. 렌더실패/오류 → 결정표 폴백(G6).
- LLM 권한(E12): (a)근거 서술 (b)주의 **상향만** (c)신규성 플래그. 수식보다 관대한 행동 자동유발 불가.

### 2.2 누수-0 실행/teardown (프레임워크 금지 구역)
- LangGraph `act` 노드는 nsenter/docker/tcpdump를 **직접 안 부른다**. 손수 `Backend.run(ExecRequest)`(timeout+setsid+라벨 reap, Robo Duck R1~R6 계승)에 위임.
- `record_intent(ledger)`는 **guard 밖**·실행 직전 항상 기록{rule,revert_cmd,ts,decision_id}. `recover_on_boot`가 이전 run 스캔→누수 정리(G3).
- LangGraph `checkpointer`는 revert/operator-gate 시맨틱을 모르므로 **actuation 원장으로 안 쓴다**(상태 영속·recover 편의로만 보조 가능, 원장은 우리 ledger가 정본).
- Collector는 **그래프 밖** 장수 async 데몬. sense가 큐를 non-blocking 드레인. 관측은 read-only·pool=1.

### 2.3 grep0 (Verifier 분리)
- Verifier는 **별 프로세스/별 그래프**. `verify_grep0`(정적)로 core 그래프가 verifier 판정권을 import 못 함을 강제.
- Verifier는 결정론(LLM 아님). 가역 AUTO 대응은 verifier 생존과 무관 집행, fail-closed는 비가역(이미 operator)만(D-3) → grep0∧X10 모순 해소.

---

## 3. replay / verify-suite
- **replay(H-J):** 노드 I/O(evidence→decision→verifier_truth)를 JSONL 녹화. 심사원은 `--replay run.jsonl`로 FastAPI 뷰어 3패널 재생. **pip-free보다 이게 이식성의 본선.**
- **verify-suite(GATE0/1, pytest):** `verify_tools`(26 tool 계약·유령0) · **`verify_graph`(LG: compile·11노드·엣지 도달성)** · **`verify_routing`(불변식①: 조건부 엣지 LLM 미참조·수치 분기)** · **`verify_no_fw_subproc`(불변식②: 노드 subprocess 0·safe-exec만)** · `verify_grep0`(Verifier↛decider) · `verify_keys`(3키 분리·argv 누수0) · `verify_parsers`(regex vs fixture) · `verify_leak0`(GATE1 통합).

---

## 4. mdg 컨테이너 · 의존성 (IMPLEMENTATION_GAPS D-2 해소)
- **base:** `python:3.12-slim` (서버 라이브 Python 3.12.3 정합). 로컬 3.14 pip-free 목표는 폐기(replay가 이식성 본선).
- **멀티홈:** net_sgi + net_cellular + net_core (각 Collector가 자기 로컬망 접속).
- **requirements(핀 고정·lockfile):**
  `langgraph` · `litellm` · `pydantic>=2` · `pyyaml` · `grpcio` · `grpcio-tools` · `protobuf` · `httpx` · `pymavlink==2.4.49` · `scapy` · `fastapi` · `uvicorn` · `pytest`
- **도구 바이너리:** 이미지에 `nsenter`(util-linux)·`iproute2(ss/ip)`·`tcpdump`·docker CLI(또는 /var/run/docker.sock 마운트). air 이미지엔 curl 부재 → 폴링은 httpx(python).
- **자기 공격표면(E9/E10/X1):** 의존성 위 목록으로 **한정**, lockfile 고정. LLM 통과 신뢰불가 입력은 pydantic 경계에서 이스케이프·길이상한·null-strip(H-P).

---

## 5. V3 검증항목 매핑 (프레임워크 이행 후에도 유지)

| 항목 | LangGraph 스택에서의 실현 |
|---|---|
| H-A DefResult/tool_wrap | pydantic 반환봉투 + act 노드 pre/post 훅. 예외는 CRSError-only |
| H-B ReAct+결정론종료 | 그래프 END 조건 = 결정론 goal_reached(LLM-terminate 아님) |
| H-C 프레임워크+참조 | **LangGraph(오케스트레이션)** + Robo Duck(safe-exec/pool=1 패턴만 이식) |
| H-D LLM 2 phase | orient·decide 2노드, Green 틱 미호출 |
| H-E~G WorldState/Legality/닫힘 | State.worldstate + select_policy의 Legality 게이트 + pydantic Literal 화이트리스트 |
| H-H~J InputSpec/해석/replay | pydantic DefInputSpec(하드코딩0) · recon 노드 role→IP · JSONL 녹화 |
| G1/G2/G4 teardown/누수0/async | ★손수 safe-exec + 그래프밖 Collector + GATE1 통합 |
| G3/G7 record_intent/watchdog | act 밖 ledger + 독립 watchdog 스레드 |
| G5 verify-suite | pytest 8종(신규 LG 3종 포함) |

---

## 6. 열린 결정 (착수 전 확정)
1. **LangGraph checkpointer 사용 범위** — 상태 영속/recover 보조까지만, actuation 원장은 우리 ledger(중복 진실원 금지).
2. **models.yaml** — Orient=Sonnet(경량)/Decide=Opus 배치 확정 + ANTHROPIC_API_KEY 프로비저닝(D-1).
3. **Collector↔graph 큐** — in-proc asyncio.Queue vs gRPC. ingest 인증(E9/X1)은 gRPC :50051 유지, 로컬 Collector는 in-proc도 가능.
4. **scapy 권한** — PFCP/GTP 파싱은 :9090 metric 우선(scapy는 보조), 캡처 필요 시 netns pcap.

> 운영 제약(불변): 인가 샌드박스 · read-only/가역 · 컨테이너 stop 금지 · 키 반출 금지 · 검증 중 상태변경 금지.
