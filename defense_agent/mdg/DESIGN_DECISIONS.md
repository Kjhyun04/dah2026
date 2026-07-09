# DESIGN_DECISIONS.md — MDG 방어 에이전트 락된 설계결정 (구속 계약)

> 생성 2026-07-07 · 통합 근거: 3검증자 패널결과(P.AI LangGraph 위상 / P.SEC 자기보안 / P4 4G 관측).
> 지위: **이 파일은 이후 전 Phase(P0~P6)의 구속 계약이다.** 여기 박힌 파일/클래스/함수 계약을 위반하는 구현은 검증 게이트에서 실패로 처리한다.
> 정본 종속: `docs/FRAMEWORK_STACK.md`(LangGraph 착수 정본) · `docs/DEFENSE_AGENT_V3_DESIGN.html`(도메인 정본) · `docs/IMPLEMENTATION_GAPS_20260707.md`(§P 패널·라이브 실측).
> 충돌 해소 원칙: **2대 불변식 우선.** 충돌 시 아래 두 불변식이 정본 문서·이전 설계 문구를 이긴다.

---

## 0. 2대 불변식 (위반 금지 — 모든 결정의 상위 규범)

- **불변식① 결정론 제어흐름.** 조건부 엣지 분기함수는 `impact.band`·`chosen_action_risk`·`chosen_action_reversible`·`chosen_action is None`·`spec.risk`·`legal` 의 **수치/불린만** read 한다. LLM은 `orient`/`decide` 2노드·`temperature=0`·structured·**조언(경계 상향만) 전용**이며 엣지에 절대 미참여한다.
- **불변식② 누수-0 실행.** 도구 부작용은 손수 safe-exec 백엔드(`Backend.run(ExecRequest)`)만 경유한다. 그래프 노드가 subprocess를 직접 실행하는 경로는 0이며, Verifier는 core를 import하지 않는 별 프로세스다.

정본 문서와의 명시적 supersession(패널 확정):
- `docs/FRAMEWORK_STACK.md §1.2`의 `verify` 노드 → **`effect_confirm`으로 개명**(PA-2). `§1.3`의 `act → verify → sense` 및 되돌이 엣지 → **전부 `→END`로 재배선**(PA-1). `§1.1`의 `verifier_truth` 채널 → **MDGState에서 완전 제거**(PA-2/PA-3).
- in-graph 노드 로스터는 **11노드**(recon 제외·escalate 편입·verify→effect_confirm): sense, correlate, compute_trust, compute_impact, orient, select_policy, rank_recovery, decide, act, effect_confirm, escalate (PA-8).

---

## 표준 모듈 레이아웃 (계약 앵커 — 모든 "구현 계약"이 이 경로 규약을 참조)

```
mdg/
  core/                     # 결정론 그래프. verifier·docker sdk·비밀 필드 미import (불변식 경계)
    state.py                # MDGState(TypedDict) + pydantic 모델 전부
    graph.py                # build_graph(): set_entry_point('sense'), 11노드, →END 엣지
    driver.py               # 그래프 밖 while 루프(되돌이 소유자)
    edges.py                # 조건부 엣지 분기함수(수치/불린만 read)
    advice.py               # apply_advice()/tighten_only() 단조 병합
    clock.py                # Clock 프로토콜(주입) — time.* 직접호출 금지
    nodes/                  # 11개 노드 각 1파일. def <node>(state)->dict
  safe_exec/
    backend.py              # Backend.run(ExecRequest): 유일 subprocess 경로
    docker_backend.py       # docker-socket-proxy 소비 단일 프로세스
    nsenter_helper.py       # netns 집행(sock 미경유, 최소 cap)
  collector/                # 그래프 밖 장수 데몬. keyring 소유
    ingest.py               # SensorEv 봉투 + HMAC/seq
  ledger/
    intent_ledger.py        # record_intent JSONL + recover_on_boot + seq HWM
  verifier/                 # 별 프로세스/별 그래프. replay JSONL만 소비. core 미import
  config/
    thresholds.yaml         # FIXED 상수(seq W, band 임계, RTT baseline …)
    models.yaml             # Orient/Decide 역할별 모델·폴백
tests/                      # verify_* 게이트(pytest)
```

---

# 섹션 ① LangGraph 위상 (PA-1 ~ PA-8)

## PA-1 — 틱 위상 = 1 invoke = 1 틱, in-graph 사이클 0

**결정.**
1. `recon`은 그래프 밖 boot 1회: `state0 = recon_boot(cfg)` 직접호출. tick 그래프에 recon 노드 **없음**.
2. tick 그래프 진입점 `graph.set_entry_point('sense')` (START=sense).
3. §1.3 되돌이 엣지 전부 →END 재배선: `compute_impact[band==Green]→END`, `decide[no legal action]→END`, `effect_confirm→END` (구 `act→verify→sense`의 sense 복귀 삭제). 그래프 내부 사이클 0 → `recursion_limit=16`(노드수 상한, 사이클 방지 가드).
4. 되돌이는 그래프 밖 드라이버 while 루프가 소유:
   ```python
   while True:
       state = graph.invoke(None, {'configurable': {'thread_id': run_id}, 'recursion_limit': 16})
       if state['goal_reached'] or state['tick_i'] >= max_iters \
          or state['pivots'] >= max_pivots or state['dry_streak'] >= k_dry:
           break
   ```
   틱 간 상태 연속성 = checkpointer(thread_id 고정) + `invoke(None, ...)`(누적채널 재주입 방지).
5. 카운터 증가 주체: `tick_i`는 sense 첫 노드에서 +1; `dry_streak`는 decide의 no-legal/Green-END 경로에서 +1·act에서 0 리셋; `pivots`는 correlate/orient에서 incident 대상 변경 시 +1. 드라이버는 **읽기만**. 안전행동(operator LAND)은 예산 면제(G10).

**구현 계약.**
- `mdg/core/graph.py::build_graph()` — `set_entry_point('sense')`, 되돌이 타깃 없음, 위 3개 →END 엣지, compile 시 `recursion_limit=16` 가드.
- `mdg/core/recon.py::recon_boot(cfg) -> MDGState` — 그래프 밖 1회.
- `mdg/core/driver.py::run_driver(graph, run_id, cfg)` — while 루프, `invoke(None, ...)`, break 조건 4개, 드라이버는 카운터 read-only.
- 검증: `tests/verify_graph.py` — in-graph 사이클 0 도달성 검사.

**근거.** 되돌이 엣지를 전부 END로 잘라 in-graph 사이클을 0으로 만들면 recursion_limit 무한루프가 원천 차단되고, 각 invoke가 정확히 1틱 → 바이트 replay·재현성 보존(불변식①). checkpointer를 틱 간 carrier로만 쓰는 것은 FRAMEWORK_STACK §2.2(checkpointer=상태영속 보조, 원장 아님)와 정합.

---

## PA-3 — MDGState 채널 타입·default·리듀서 확정

**결정.** MDGState = pydantic v2 기반 TypedDict 채널.
- 누적 list = `operator.add` 리듀서:
  `ledger: Annotated[list[Intent], operator.add] = []`, `decisions: Annotated[list[Decision], operator.add] = []`, `incidents: Annotated[list[Incident], operator.add] = []`.
- 교체(LastValue 기본):
  `evidence: list[SensorEv] = []`(sense가 틱마다 큐 드레인 후 전량 교체), `worldstate: WorldState`(sense가 merge한 단일 권위객체 교체), `trust: dict[str, TrustObj] = {}`, `impact: ImpactObj`, `orient_note: OrientNote|None = None`, `decide_note: DecideNote|None = None`, `config_version: str`, `goal_reached: bool = False`.
- 카운터(int LastValue=교체, 노드가 read-modify-return): `tick_i: int = 0`, `pivots: int = 0`, `dry_streak: int = 0`.
- 행동선택 필드(PA-4): `chosen_action: Intent|None = None`, `chosen_action_risk: Literal['LOW','MED','HIGH'] = 'LOW'`, `chosen_action_reversible: bool = True`, `legal_actions: list[Action] = []`.
- 실체 pydantic 모델 필수 생성: `WorldState`(reach/signing/role_verified/threat/applied/ip_map/pid/baseline 닫힌 술어), `TrustObj`, `ImpactObj`(score:int 0-100, band:Literal['Green','Yellow','Red'], confidence_margin:float), `Intent`, `Incident`, `Decision`, `SensorEv`, `OrientNote`, `DecideNote`.
- `verifier_truth` 채널 **제거**(PA-2). 비밀(LLM키·operator토큰·HMAC키)은 State 미경유(PS-3 계약).

**구현 계약.**
- `mdg/core/state.py::MDGState(TypedDict)` — 위 필드/어노테이션 정확히. 누적 3채널만 `Annotated[..., operator.add]`, 나머지 LastValue.
- `mdg/core/state.py` 내 pydantic v2 BaseModel: WorldState, TrustObj, ImpactObj, Intent, Incident, Decision, SensorEv, OrientNote, DecideNote.
- `verifier_truth` 심볼이 state.py에 부재.
- 검증: `tests/verify_graph.py`(채널 리듀서 존재) + `tests/verify_grep0.py`(verifier_truth 채널 부재).

**근거.** 누적 list에 리듀서 미지정 시 LangGraph 기본 LastValue가 조용히 덮어써 원장/incident 유실. add 리듀서는 checkpointer(thread_id)+invoke(None)와 결합해야 틱 간 중복적재 없이 누적. evidence는 틱 스냅샷이라 교체가 정확. 카운터를 State에 두면 replay/recover에 포함되고 노드가 tick_i+1 return하므로 LastValue로 충분.

---

## PA-2 — effect_confirm(노드) ≠ Verifier(별프로세스) 분리

**결정.**
1. 구 `verify` 노드 → **`effect_confirm`** 개명. 그래프 내부 결정론 노드로, act 직후 관측 델타(피벗신호) 산출: ss/pcap/:9090 diff(s5c_rx_deletesession)/14560 HB/uav_ue lo:14550 교차탭(D-1). 출력은 `worldstate.applied[rule].confirmed: bool`과 관측 델타만 기록, 다음 틱 sense가 재관측. 가역 AUTO 대응의 실행 허가를 게이트하지 **않음**(이미 실행됨, D-3). `effect_confirm→END`.
2. `verifier_truth` 필드 MDGState에서 완전 제거.
3. Verifier = 별 프로세스/별 그래프, **replay JSONL만 소비**(오프라인·사이드채널), 자기 Truth 저장소에 기록. core 그래프는 Verifier를 import 안 하고 Verifier도 core를 import 안 함.
4. `verify_grep0`(정적) 갱신: `mdg.core.*`가 `mdg.verifier.*` 미import + MDGState에 verifier_truth 부재 + Truth 타입이 core에서 미참조 강제.

**구현 계약.**
- `mdg/core/nodes/effect_confirm.py::effect_confirm(state) -> dict` — 관측 델타·`worldstate.applied[rule].confirmed`만 반환, 실행 게이트 없음. `graph.py`에서 `effect_confirm→END`.
- `mdg/verifier/*` — replay JSONL consumer 전용, `import mdg.core` 0.
- 검증: `tests/verify_grep0.py::test_core_no_verifier_import`, `::test_no_verifier_truth_channel`, `::test_truth_type_not_in_core`.

**근거.** verifier_truth가 decider의 State 필드면 grep0(Verifier↛decider) 즉시 실패. in-graph effect-confirm(피벗신호)과 out-graph Verifier(replay 판정)를 이름·경계로 분리해 FRAMEWORK_STACK §2.3과 정합. State에서 verifier_truth 제거로 core가 판정권을 못 import.

---

## PA-4 — decide→act 엣지는 결정론 필드만 read

**결정.**
1. 행동선택은 `rank_recovery`(결정론)가 소유: recovery prior 정렬 후 top 후보를 `chosen_action`에 바인딩하고, 번들 수준 `chosen_action_risk = max(atomic ops risk)`, `chosen_action_reversible = all(op.reversible)`를 State 필드로 승격. 후보 없으면 `chosen_action = None`.
2. `decide`(LLM2)는 조언(tighten)만, chosen_action/risk/reversible을 **절대 설정 안 함**.
3. decide발 조건부 엣지 분기함수는 오직 `state['chosen_action_risk']`, `state['chosen_action_reversible']`, `state['chosen_action'] is None`만 read:
   - `legal ∧ risk in {LOW,MED} ∧ reversible → act`
   - `risk == 'HIGH' → escalate`
   - `chosen_action is None → END`
   orient_note/decide_note 등 LLM 필드 미참조.
4. `verify_routing` 정적검사: 이 엣지함수 AST가 위 수치/불린 키만 참조하고 LLM 파생 필드 0 강제.

**구현 계약.**
- `mdg/core/nodes/rank_recovery.py::rank_recovery(state) -> dict` — chosen_action/chosen_action_risk(max)/chosen_action_reversible(all) 세팅.
- `mdg/core/edges.py::route_after_decide(state) -> Literal['act','escalate','__end__']` — 위 3키만 read.
- `mdg/core/nodes/decide.py` — chosen_* 필드 write 0(decide_note만).
- 검증: `tests/verify_routing.py` — `route_after_decide` AST가 허용 키셋만 참조, LLM 파생 필드 참조 0.

**근거.** risk/reversible이 LLM 선택에 오염되면 결정론 라우팅이 깨짐. rank_recovery가 행동을 고르고 번들 risk=max·reversible=all로 보수 집계, 엣지는 이 수치/불린만 읽어 모델이 다음 노드를 못 고름(불변식①·FRAMEWORK_STACK §1.3 핵심).

---

## PA-5 — LLM 노드 스키마 + tighten_only 병합함수

**결정.**
- `OrientNote`(pydantic response_model, temp=0 structured): `rationale: constr(max_length=800)`, `novelty_flag: bool`, `ambiguity: bool`, `severity_bump: Literal[0,1]`(상향만·크기 1 상한), `suggested_focus: list[constr(max_length=64)]`(len≤8).
- `DecideNote`: `rationale: constr(max_length=800)`, `escalate_recommended: bool`, `caveats: list[...]`.
- 병합함수 `apply_advice(state, note) = tighten_only`(순수·단조): impact.band를 `max(band, band+severity_bump)`로만 올림(Green→Yellow→Red 허용, 하향 절대 금지, `assert new_band >= old_band`), risk 하향·legal set 확장·escalation 하향 금지.
- LLM note는 엣지함수에 절대 미투입(엣지는 결정론 impact.band/chosen_action_risk만 read).
- PS-7 보강: 신뢰불가 필드는 파생 수치로만 LLM 전달, 대응은 결정론 임계 재확인 + 디바운스(dry_streak 게이트) + provenance 게이트로 과잉대응 인젝션(자해 DoS) 차단.
- 렌더실패/빈프롬프트/스키마오류 → 결정표 폴백(G6).

**구현 계약.**
- `mdg/core/state.py::OrientNote`, `::DecideNote` — 위 constr/Literal 제약.
- `mdg/core/advice.py::apply_advice(state, note) -> dict` — 단조, `assert new_band >= old_band`, 하향 경로 없음.
- `mdg/core/nodes/orient.py`·`decide.py` — litellm temp=0 structured(response_model), 예외 시 결정표 폴백.
- 검증: `tests/verify_routing.py`(엣지에 note 미투입) + apply_advice 단조성 property 테스트.

**근거.** structured output만으론 병합규칙 부재. tighten_only 단조함수 + assert로 E12(상향만) 집행. Green틱은 orient 前 END라 orient 미호출과 정합. 올리기만 가능하므로 라우팅이 더 관대해질 수 없어 불변식① 보존.

---

## PA-6 — act 노드 실행 순서: legality 선체크 → record_intent → tool_wrap

**결정.** `def act(state) -> dict`.
1. **legality 선체크**(tool_wrap 밖·guard 밖 순수 체크): select_policy 결과를 현재 worldstate + `config_version`(X7 TOCTOU 핀)으로 재확인, 불법이면 **부작용 0으로 즉시 반환**.
2. **record_intent**(guard 밖·실행 직전 항상): `Intent{rule, revert_cmd, ts, decision_id, config_version}`를 디스크 원장 JSONL과 State `ledger` 채널(add 리듀서)에 **실행 전** 기록 → recover_on_boot가 누수 정리(G3).
3. **tool_wrap** = `Backend.run(ExecRequest)`(safe-exec: timeout+setsid+라벨 reap, Robo Duck R1~R6) + post `world_update`(worldstate.applied merge)만 감쌈. legality/record_intent는 tool_wrap 안에 넣지 않음. safe-exec가 유일 subprocess 경로.

**구현 계약.**
- `mdg/core/nodes/act.py::act(state) -> dict` — 위 3단계 정확한 순서. legality 실패 시 side-effect 0 early return.
- `mdg/ledger/intent_ledger.py::record_intent(intent)` — JSONL append + State ledger add. `recover_on_boot()`가 부팅 시 스캔·revert.
- `mdg/safe_exec/backend.py::Backend.run(req: ExecRequest)` — 유일 subprocess 경로(timeout/setsid/reap).
- 검증: `tests/verify_no_fw_subproc.py` — 노드 subprocess 0, safe-exec만.

**근거.** legality(pre_hook=guard 안) vs record_intent(guard 밖)이 원 설계에서 뒤엉킴. legality를 tool_wrap 밖 선체크로 올리면 불법행동이 원장에 기록되기 전에 차단되고, record_intent를 guard 밖·실행 직전에 두면 부작용 발생 시 항상 revert 근거가 선기록(불변식② 누수-0).

---

## PA-7 — 실행 경계: 동기 sense, 가상시계, 녹화훅

**결정.**
1. `sense` = **동기 노드**: Collector(그래프 밖 장수 데몬 스레드)가 push한 `queue.Queue`를 `get_nowait()` 루프로 non-blocking 드레인, Empty→fail-open(G4), 드레인 시점에 HMAC/seq 검증(PS-2, 소비계층). 그래프 내 async 금지(async 노드 0).
2. **가상시계**: `Clock` 프로토콜을 config 주입, 노드는 `clock.now()/clock.sleep()`만 호출, `time.*` 직접호출 AST 금지(verify). replay는 JSONL ts를 읽는 `VirtualClock` 주입.
3. **녹화훅**: 드라이버가 `graph.stream(..., stream_mode='updates')`로 각 노드 업데이트 dict를 `run.jsonl`에 append(노드 I/O replay 원천, 녹화시점 secret redact — PS-3).

**구현 계약.**
- `mdg/core/nodes/sense.py::sense(state) -> dict` — 동기, `queue.get_nowait()` 드레인, 드레인 시점 HMAC/seq 검증, async 없음.
- `mdg/core/clock.py::Clock`(Protocol), `::VirtualClock` — config 주입, 노드는 `clock.*`만.
- `mdg/core/driver.py` — `graph.stream(..., stream_mode='updates')` → `run.jsonl` append(redact 후).
- 검증: `tests/verify_routing.py`/전용 AST 체크 — 노드 내 `time.*` 직접호출 0, async 노드 0.

**근거.** 동기 sense+queue.Queue non-blocking 드레인은 그래프 결정론과 async 데몬을 양립. Clock 주입은 replay 시간 결정론, stream_mode=updates는 이식성 본선 replay JSONL을 확정.

---

## PA-8 — v2 로직 노드매핑 + escalate 로스터 + HITL

**결정.**
- 매핑: `compute_confidence`→`compute_trust`(E5 conf 적대항)+`compute_impact`(E8 마진 1회) 흡수 · `build_evidence`→`sense`(드레인 시 Evidence 조립) · `gate_evaluate`→`select_policy`(Legality 게이트)+decide엣지(band/risk 게이트)로 분해 · `emit_trace`→노드 아님, 횡단 녹화훅(stream_mode=updates).
- `escalate` = **실제 종단 노드**로 로스터 편입: operator-gate Intent를 record_intent(자동 부작용 0, 실제 서명명령=operator-go 유보)로 기록하고 OperatorRequest를 원장/posture에 기록 후 →END.
- HITL은 MVP에서 LangGraph `interrupt()` **미사용**(interrupt는 replay 결정론·1invoke=1틱 복잡화) → `escalate→END` + 그래프 밖 operator 처리로 대체, interrupt() 연기.
- 최종 in-graph 노드 로스터(**11**): sense, correlate, compute_trust, compute_impact, orient, select_policy, rank_recovery, decide, act, effect_confirm, escalate (recon은 boot·그래프 밖).
- `verify_graph`는 이 11노드·엣지 도달성 검사하도록 갱신.

**구현 계약.**
- `mdg/core/nodes/escalate.py::escalate(state) -> dict` — operator-gate Intent record_intent(부작용 0), OperatorRequest 기록, →END.
- `mdg/core/nodes/` — 정확히 11개 파일(recon 제외).
- `interrupt()` 심볼이 core에 부재.
- 검증: `tests/verify_graph.py` — 노드 11개·전 노드 도달성.

**근거.** escalate를 실노드로 만들면 엣지타깃이 유효해지고, interrupt() 대신 escalate→END+out-of-band는 1invoke=1틱(PA-1)·replay 결정론을 안 깬다. verify(11)→effect_confirm 개명·recon 제외·escalate 추가로 노드수 11 불변 유지.

---

# 섹션 ② 자기보안 (PS-1 ~ PS-9)

## PS-1 — docker.sock 분할 격리

**결정.**
1. 실제 `/var/run/docker.sock`은 오직 별도 `docker-socket-proxy` 컨테이너에만 `:ro` 마운트.
2. 프록시는 HTTP 메서드+경로 화이트리스트만 통과, 그 외 403. 허용 = `GET /containers/json`, `GET /containers/{id}/json`, `GET /containers/{id}/logs`(read-only; P1-Q1 추가 — mongo/후속 SMF·MME 로그테일), `POST /containers/{id}/pause`, `POST /containers/{id}/unpause`. 명시 거부 = exec/start/stop/kill/restart/remove/images/build/volumes/networks/commit/attach/auth/info.
3. 프록시 리슨 = 내부 docker 네트워크 loopback 전용, `0.0.0.0` 금지.
4. docker API 소비자 = 오직 safe-exec 백엔드 프로세스 1개(`mdg.safe_exec.docker_backend`). core 11노드·orient/decide·signer/operator-gate 모듈은 프록시 주소·docker SDK import/참조 0.
5. netns 집행(DROP/tcpdump/nsenter)은 docker.sock 미경유, CAP_NET_ADMIN·CAP_SYS_ADMIN만 가진 별도 `nsenter-helper`(최소권한)로 분리.
6. 검증: `verify_no_sock_in_core`(정적 AST/import 스캔: core+signer에 docker sdk·sock 경로·프록시 URL 리터럴 0).

**구현 계약.**
- `docker-socket-proxy` 컨테이너(compose) + `mdg/safe_exec/docker_backend.py` — 4엔드포인트만, loopback 바인드.
- `mdg/safe_exec/nsenter_helper.py` — sock 미경유, 최소 cap.
- 검증: `tests/verify_no_sock_in_core.py`.

**근거.** docker.sock=분할불가 root. 프록시가 API 표면을 pause/inspect 4엔드포인트로 축소하고 접근점을 safe-exec 단일 프로세스로 좁혀야 D-2 권한분리가 성립. pause 대상해석은 inspect+P4-1 IMSI세션테이블로 충족되므로 exec 제외 가능.

---

## PS-2 — 소비계층 ingest 인증 (전송계층 아님)

**결정.**
1. 모든 Collector(gRPC :50051 및 in-proc `asyncio.Queue` 공히)는 SensorEv를 봉투로 인큐: `{payload, source_id, kid, seq, ts, nonce, hmac}`, `hmac = HMAC-SHA256(key[kid], canonical(payload)||source_id||seq||ts||nonce)`.
2. `sense`가 큐를 non-blocking 드레인하는 **바로 그 시점**에 HMAC+seq 검증 후에만 WorldState merge. 실패 → evidence 폐기 + tamper Incident 발행(merge·trust·impact·auto-격리에 미반영), 드레인은 계속(빈 큐 fail-open 유지, 위조는 fail-closed 폐기).
3. seq는 PS-6 high-watermark 윈도우로 리플레이 판정.
4. provenance 게이트: HMAC 미통과 evidence는 correlate/compute_trust 입력에서 구조적 배제.
5. 검증: `verify_ingest_hmac` — 위조 봉투 fixture가 WorldState에 미도달, tamper Incident만 남음.

**구현 계약.**
- `mdg/collector/ingest.py::SensorEnvelope` + `verify_envelope(env, keyring)` — 봉투 스키마·HMAC 계산.
- `mdg/core/nodes/sense.py` — 드레인 시점 `verify_envelope` 호출, 실패 시 tamper Incident.
- 검증: `tests/verify_ingest_hmac.py`.

**근거.** 사이드카 장악 시 in-proc 큐로 위조 Evidence 직접주입→오탐 auto-격리(자해 DoS). mTLS/전송계층은 in-proc 경로를 우회하므로 인증을 '소비 시점'으로 내려야 양 경로가 동일 신뢰기준. PS-7 provenance 게이트와 동일 앵커.

---

## PS-3 — secret-free State/JSONL + 녹화시점 redact + 카나리

**결정.**
1. 3비밀류(ANTHROPIC_API_KEY, operator 토큰, HMAC/ingest 키)는 MDGState·노드 입출력·replay JSONL·checkpointer 직렬화를 경유하는 **필드가 아예 없다**(구조적 보장). 각 비밀은 소유 서브시스템 프로세스 메모리/전용 keyring에만: LLM키=litellm 클라이언트 생성자 env 주입(프롬프트 렌더러 미접근), operator토큰=operator-gate verifier, HMAC키=Collector+sense keyring.
2. State 직렬화는 명시 `to_record()` 허용필드 projection만 방출(미선언 필드 기록 불가).
3. 녹화훅(stream_mode=updates)은 record **생성 시점**에 `redact()` 통과(허용필드 projection + 잔여 비밀패턴 regex 스크럽). 뷰어 표시시점 redact는 폐기.
4. 카나리: env에 `MDG_CANARY_LLM/OP/HMAC` 주입 → `verify_replay_leak0`이 전체 실행 후 JSONL+checkpoint 파일 스캔해 카나리 및 실비밀 패턴 0 강제. verify_keys(소스 리터럴)와 병행.

**구현 계약.**
- `mdg/core/state.py::MDGState.to_record()` — 허용필드 projection.
- `mdg/core/driver.py::redact(record)` — 녹화 생성 시점 스크럽.
- 비밀은 각 서브시스템 keyring/env: `mdg/collector/`, operator-gate, litellm 생성자.
- 검증: `tests/verify_replay_leak0.py`(카나리) + `tests/verify_keys.py`(소스 리터럴).

**근거.** replay JSONL/State가 비밀 원문을 디스크 영속하고 'Viewer redact'는 표시시점이라 디스크는 노출. verify_keys는 소스 리터럴만 봐 런타임 유입 미포착. 구조적 미경유(필드 부재)를 1차 보장, 녹화시점 redact+카나리를 검증 앵커.

---

## PS-4 — 공급망 핀 + egress allowlist

**결정.**
1. 의존성 설치 = `pip install --require-hashes -r requirements.lock`, lockfile은 `pip-compile --generate-hashes`로 전 추이트리 해시핀. 해시 불일치 시 빌드 실패. CycloneDX SBOM 생성.
2. MDG 컨테이너 egress = 정확히 `api.anthropic.com:443` + 관측 대상 내부망(net_sgi/net_cellular/net_core)만 허용, 그 외 아웃바운드 전부 DROP. api.anthropic.com은 부팅 시 고정 리졸버 해석→IP셋 핀(TTL 재해석). DNS도 고정 리졸버만.
3. 이는 MDG 자기 컨테이너 대상이나 **라이브 네트워크 상태변경**이므로 코드+compose 정책까지 확정하고 실제 적용은 **operator-go 유보**.
4. 검증: `verify_egress_allowlist`(dry/sandbox: 비-anthropic 호스트 아웃바운드 실패 확인).

**구현 계약.**
- `mdg/config/requirements.lock`(해시핀) + 빌드 SBOM 스텝.
- compose/iptables OUTPUT allowlist 정책 파일(적용은 operator-go 유보 주석 명시).
- 검증: `tests/verify_egress_allowlist.py`(dry).

**근거.** host-root 에이전트의 대형 공급망 표면 + litellm 잠재 exfil 채널. 해시핀은 변조를, egress allowlist는 변조 성공 시 유출을 각각 차단(방어심층). 운영 제약상 실적용은 유보로 못박음.

---

## PS-5 — 키 부트스트랩·회전 (E11 재현 방지)

**결정.**
1. 3비밀류는 이미지에 굽지 않고 런타임 tmpfs 시크릿 마운트(0400, 호스트 시크릿스토어/docker secret 유래) 주입.
2. :50051 mTLS = 단기수명 인증서 발급 CA + 폐기목록(handshake 시 검사). HMAC 키는 봉투 `kid`로 버전화 → verifier가 current+previous kid 동시 보유해 무중단 회전, grace 후 old drain. operator 토큰 회전 = 새 토큰파일 + reload 시그널.
3. C-2(signer-shim 키 비확산)와 정합: `/sign.key` 신규 확산 금지, operator-gate는 서명키를 더 퍼뜨리지 않는 배치에서만(별도 C-2 결정에 종속).
4. 검증: `verify_no_key_in_image`(빌드 시 이미지 레이어 비밀패턴·카나리 스캔 0).

**구현 계약.**
- compose tmpfs 시크릿 마운트(0400) + CA/CRL 배치.
- `mdg/collector/ingest.py` keyring — `kid` 버전화(current+previous).
- 검증: `tests/verify_no_key_in_image.py`(빌드 후크).

**근거.** 키 부트스트랩/회전이 명칭만 존재→'이미지에 키 굽기'(E11) 위험. tmpfs 주입+kid 버전화로 회전 계약화, 이미지 스캔으로 굽기 회귀 차단.

---

## PS-6 — 안티리플레이 seq high-watermark ledger 영속

**결정.**
1. source_id(kid)별 단조 seq + 슬라이딩 윈도우 W=1024 + high-watermark HWM. 수락: `seq>HWM`(HWM 전진) 또는 `(HWM-W < seq ≤ HWM ∧ seen-bitmap 미표시)`. 거부(리플레이): `seq ≤ HWM-W`(과노후) 또는 seen 표시됨. ts는 ±W초 clock skew 허용.
2. HWM+compact bitmap을 source별로 **ledger**(우리 durable 원장)에 전진 시 fsync-배치 영속.
3. 크래시/부팅 시 `recover_on_boot`가 sense 드레인 개시 **이전**에 source별 HWM 재로드 → 리플레이 윈도우 재개방 차단.
4. DoS 상한: seen 캐시는 윈도우 W bitmap으로 유한(무한 set 금지), 윈도우 슬라이드로 자동 evict.
5. 파라미터는 `thresholds.yaml` FIXED 상수.
6. 검증: `verify_seq_persist` — 실행 중 크래시→재기동 후 크래시 이전 seq 재전송이 거부됨.

**구현 계약.**
- `mdg/ledger/intent_ledger.py::SeqWatermark` — source별 HWM+bitmap, fsync 영속. `recover_on_boot()`가 sense 개시 전 재로드.
- `mdg/config/thresholds.yaml` — `seq_window: 1024`, skew 상수 FIXED.
- 검증: `tests/verify_seq_persist.py`.

**근거.** seq/윈도우 미확정 + 크래시 시 HWM 미영속→리플레이 재개방 + 캐시 무한증가 DoS. HWM을 actuation ledger에 영속하고 부팅 재로드를 sense 개시 전으로 순서화, bitmap 윈도우로 DoS 상한.

---

## PS-7 — 인젝션·과잉대응 게이트

**결정.**
1. 신뢰불가 필드(wire/telemetry 문자열, LLM 도달가능 입력)는 LLM에 **원문 자유텍스트 전달 금지**, 파생 수치/enum(카운트·band·불린)으로만 orient/decide에 투입.
2. '상향만'(E12) 조언은 그 자체로 행동 트리거 불가 — 대응은 결정론 임계 재확인 + N틱 디바운스 + provenance 게이트(PS-2 HMAC/seq 통과 evidence만) 통과 후에만 auto 대응.
3. 이로써 인젝션이 severity를 부풀려도 엉뚱 대상 auto-격리(자해 DoS) 불가.
4. 검증: `verify_injection_gate` — 신뢰불가 provenance발 위조 고-severity 신호가 act에 미도달.

**구현 계약.**
- `mdg/core/nodes/orient.py`·`decide.py` — 입력 프롬프트는 파생 수치/enum만(자유텍스트 wire 필드 미투입).
- `mdg/core/edges.py`·`rank_recovery.py` — 결정론 임계 재확인 + dry_streak 디바운스 게이트 + provenance 게이트.
- 검증: `tests/verify_injection_gate.py`.

**근거.** structured output은 인젝션을 못 막고 '상향만'은 과잉대응 유발 인젝션을 통과시켜 자해 DoS. 수치화+디바운스+provenance로 신뢰불가 입력이 제어흐름을 조종하지 못하게 함(불변식① 보강).

---

## PS-8 — 관리 인터페이스 바인드·인증·DoS 상한

**결정.**
1. FastAPI viewer와 gRPC :50051은 loopback(127.0.0.1) 또는 전용 관리 netns에만 바인드, `0.0.0.0` **절대 금지**(공격자 UE 10.45.0.x 도달 차단).
2. viewer는 bearer 토큰 인증(constant-time 비교), 무인증 posture 유출 0.
3. gRPC pre-auth DoS 상한: mTLS 선행 강제(RPC 처리 전), max_message_length(256KB), 최대 동시연결·요청 rate limit.
4. 검증: `verify_bind_iface`(0.0.0.0 바인드 0), `verify_viewer_auth`(무토큰 요청 거부).

**구현 계약.**
- `mdg/verifier/viewer.py`(FastAPI) — loopback 바인드, bearer 토큰 constant-time.
- gRPC 서버(:50051) — loopback, mTLS 선행, max_message_length=256KB, rate limit.
- 검증: `tests/verify_bind_iface.py`, `tests/verify_viewer_auth.py`.

**근거.** 바인드 인터페이스 미명세면 공격자 UE 도달, viewer 무인증은 posture 유출, gRPC 무상한은 pre-auth DoS. loopback+토큰+한도로 관리평면 격리.

---

## PS-9 — checkpointer at-rest + operator 토큰 명령바인딩

**결정.**
1. checkpointer 백엔드 = 고정경로 로컬 SQLite/파일, mode 0600, 비공유 볼륨(다른 컨테이너 재마운트 불가), owner-only. State는 PS-3로 secret-free이므로 at-rest 노출면이 구조적으로 유한.
2. operator 승인 = 단순 존재 토큰이 아니라 `(decision_id, command_digest, nonce, expiry)`에 대한 HMAC/서명 → 캡처 토큰으로 다른 서명명령 승인 불가(토큰=명령스코프 인가, 존재증명 아님). nonce 단회성 + 단기 expiry.
3. checkpointer는 actuation 원장이 아님(FRAMEWORK §2.2·§6#1) — 승인 원장은 우리 ledger가 정본.
4. 검증: `verify_operator_binding` — 캡처 승인을 다른 command_digest로 재사용 시 거부.

**구현 계약.**
- checkpointer 파일 0600 비공유 볼륨(compose) + `mdg/core/driver.py` 고정경로.
- operator-gate 모듈 — `(decision_id, command_digest, nonce, expiry)` HMAC 검증, nonce 단회.
- 검증: `tests/verify_operator_binding.py`.

**근거.** checkpointer 저장소 미명세=at-rest 유출면, operator 토큰 명령 다이제스트 미바인딩→캡처 토큰 임의 서명명령 승인 가능. 0600 비공유+secret-free State로 at-rest를, digest 바인딩으로 토큰 오남용을 각각 봉쇄. C-2 signer-shim/operator-gate 설계의 전제 계약.

---

# 섹션 ③ 4G 코어망 관측 (P4-1 ~ P4-6) — 순수 모니터링, 상태변경 없음

## P4-1 — IMSI↔동적IP 세션테이블 (SMF 로그 테일)

**결정.** MDG Collector가 `docker logs -f epc_smf` stdout(로그파일 부재)을 테일하여 IMSI↔tun-IP 세션테이블 유지.
- 생성 정규식 `UE IMSI\[(\d+)\].*IPv4\[(10\.45\.\d+\.\d+)\]` 매치 시 imsi→ip / ip→imsi 양방향 딕셔너리 add.
- 삭제 정규식 `Removed Session: UE IMSI:\[imsi-(\d+)\].*IPv4:\[(10\.45[^\]]*)\]` 매치 시 remove.
- 파싱 전 ANSI-strip(`\x1b\[[0-9;]*m`) **필수**.
- 용도: (1) command_source vantage별 귀속, (2) docker pause 대상해석(UE풀 소스IP 10.45.0.x→IMSI→후보 컨테이너 `ip -4 addr show tun_srsue` exec-scan 역매핑, A-1/C-3), (3) 교차평면 correlation 조인의 단일 조인키. 순수 관측 파생물·상태변경 없음.

**구현 계약.**
- `mdg/collector/smf_session.py::SmfSessionTable` — 양방향 dict, add/remove 정규식, ANSI-strip 선적용. `docker logs -f epc_smf` 테일(그래프 밖 Collector 데몬).
- 검증: `tests/verify_parsers.py`(SMF fixture: ANSI 포함 라인 → 정규식 매치).

**근거.** FEASIBILITY §2 'IMSI 조인 불가→시간창만'을 정정: SMF 로그가 IMSI↔할당IP 바인딩 실발행. mongo subscribers엔 IMSI만, tun_srsue IP는 inspect 부재(A-1) → SMF 로그 테일이 유일 소스. 라이브서 ANSI 컬러 확인 → strip 미적용 시 정규식 전멸.

---

## P4-2 — metric→NF 폴링표 (:9090 urllib 멀티홈)

**결정.** Collector가 net_core(10.50.0.0/24) 멀티홈으로 3개 NF의 :9090을 python `urllib`(air 이미지 curl/nc 부재, B-2)로 폴링, NF별 소스 고정:
- SMF `10.50.0.4:9090` → s5c_rx_deletesession·s5c_rx_createsession·s5c_rx_parse_failed·gtp_node_{gn,s5c}_rx_parse_failed·pfcp_sessions_active(참고용, 임계 금지)·fivegs_smffunction_sm_sessionnbr(참고용).
- UPF `10.50.0.7:9090` → fivegs_ep_n3_gtp_in/outdatapktn3upf(N3 데이터평면 볼륨)·pfcp_peers_active·session/qos.
- MME `10.50.0.2:9090` → enb·enb_ue·mme_session(희소).
- PCRF 빈 metric → 소스 제외.
- localhost:9090 아님 — NF의 net_core IP.

**구현 계약.**
- `mdg/collector/metric_poller.py::MetricPoller` — NF별 IP:9090 고정표, urllib 폴링(httpx도 허용, curl/nc 미사용). net_core 멀티홈.
- 검증: `tests/verify_parsers.py`(Prometheus 텍스트 fixture → 카운터 파싱).

**근거.** 라이브: SMF 10.50.0.4:9090이 카운터 실반환, air 사이드카 curl 부재로 urllib 필수. 컨테이너 IP 라이브 대조 일치(SMF=10.50.0.4, UPF=10.50.0.7, MME=10.50.0.2). delete=SMF·peers=UPF 분산이라 매핑 없이는 오폴링.

---

## P4-3 — 신뢰 트립신호 = 단조 카운터 diff

**결정.** 모든 트립 판정은 counter형 metric의 틱당 **양의 diff**로만.
- PFCP 세션삭제 트립 = `s5c_rx_deletesession diff>0`.
- `*_active` 게이지(pfcp_sessions_active, fivegs_smffunction_sm_sessionnbr)는 임계·트립에 **절대 미사용**.
- 카운터 diff<0(NF 재시작/리셋)은 baseline 리시드로 처리, 음수를 신호로 안 씀.
- 확장 방어신호: s5c_rx_parse_failed·gtp_node_*_rx_parse_failed·gtp_new_node_failed(변형 GTP-C=이상), UPF fivegs_ep_n3_gtp_* 데이터평면 볼륨이상도 counter diff로 편입.

**구현 계약.**
- `mdg/collector/metric_poller.py::counter_diff(prev, cur)` — 양의 diff만 신호, diff<0→baseline 리시드. 게이지 트립 경로 부재.
- `mdg/config/thresholds.yaml` — 카운터 diff 임계(게이지 임계 없음).

**근거.** 라이브서 pfcp_sessions_active=-9(버그성 음수 게이지) 재확인 → 세션수 임계 붕괴. s5c_rx_deletesession=9는 단조 counter로 안정. parse_failed/gtp_new_node_failed는 변형 GTP-C 공격 직접 관측면이라 확장 편입이 오탐 없이 탐지폭 확대.

---

## P4-4 — 세션삭제 소스귀속

**결정.** 세션삭제 이벤트의 UE/세션 귀속은 metric이 아니라 **P4-1 SMF 로그 `Removed Session: UE IMSI:[…] IPv4:[…]` 테일을 유일 귀속원**으로. per-peer metric `gtp_node_s5c_rx_deletesession{addr="10.50.0.3"}`은 SGWC 단일 peer 구분만 가능하므로 트립 '발생' 신호(P4-3)로만 쓰고, '어느 IMSI/IP 세션인지'는 SMF 로그 세션테이블 delete 이벤트와 시간 조인.

**구현 계약.**
- `mdg/core/nodes/correlate.py` — 세션삭제 발생(metric diff) + 귀속(SmfSessionTable delete 이벤트) 2계층 시간 조인. 조인키 = P4-1 세션테이블.

**근거.** 라이브 metric은 per-peer(addr=10.50.0.3, SGWC)까지만 세분→개별 UE 식별 불가. P4-1 동일 소스(SMF 로그)가 IMSI+IPv4 함께 발행하므로 metric(발생량)+로그(귀속) 2계층이 정합.

---

## P4-5 — attach/IMSI = MME 로그, 공통 ANSI-strip

**결정.** attach/IMSI/service-request 관측은 `docker logs -f epc_mme` stdout 테일을 **유일 소스**로(MME metric은 enb/enb_ue/mme_session만으로 희소). Rogue-UE attach(TM3) 탐지 = MME 로그 테일. EPC 로그 파서는 SMF·MME·UPF 전부에 공통 ANSI-strip(`\x1b\[[0-9;]*m`) 선적용 후 정규식 매치. 타임스탬프 포맷 `MM/DD HH:MM:SS.mmm`(예 `07/07 03:39:36.461`)을 파서에 고정.

**구현 계약.**
- `mdg/collector/mme_log.py::MmeLogTail` — `docker logs -f epc_mme` 테일, ANSI-strip 선적용, ts 포맷 고정.
- `mdg/collector/log_common.py::ansi_strip(s)` — SMF/MME/UPF 공통.
- 검증: `tests/verify_parsers.py`(MME fixture: ANSI 포함 → IMSI 정규식 매치).

**근거.** 라이브 MME metric 희소, attach 이벤트는 로그에만. SMF 로그 ANSI 컬러 실측 확인 → 동일 Open5GS 포맷 MME 로그도 ANSI 포함이므로 strip 미적용 시 IMSI 정규식 실패.

---

## P4-6 — RTT baseline = 창+지터 허용

**결정.** 셀룰러 RTT는 단일 임계가 아니라 슬라이딩 창 EWMA baseline + 지터 허용대(`baseline + k·mdev`)로 이상 판정. 라이브 uav_ue→gcs_proxy 실측 14.5/30.2/38.6ms, mdev≈11ms를 초기 baseline/지터 상수로 config화. 문서값 21~28ms는 과협(오탐)으로 폐기. RTT는 순수 관측 보조신호로만, 단독 트립 금지(다신호 correlation 게이트).

**구현 계약.**
- `mdg/collector/rtt_baseline.py::RttBaseline` — EWMA + mdev 지터 대역.
- `mdg/config/thresholds.yaml` — `rtt_baseline_ms`, `rtt_mdev_ms≈11`, `rtt_k` FIXED.
- `mdg/core/nodes/correlate.py` — RTT는 다신호 correlation 게이트 입력, 단독 트립 경로 부재.

**근거.** 라이브 mdev 11ms(고지터)로 단일임계는 정상 변동을 오탐. 창+지터 대역만이 셀룰러 자연변동 흡수. 문서 21~28ms 대비 실측 변동폭이 커 정본을 실측값으로 이관.

---

# 부록 A — 검증 게이트 매핑 (verify-suite)

| 게이트 | 강제 대상 | 근거 결정 |
|---|---|---|
| `verify_graph` | compile·11노드·엣지 도달성·in-graph 사이클 0·채널 리듀서 | PA-1/PA-3/PA-8 |
| `verify_routing` | 조건부 엣지 AST가 수치/불린만 read, LLM 파생 필드 0, time.* 직접호출 0 | PA-4/PA-5/PA-7 |
| `verify_no_fw_subproc` | 노드 subprocess 0, safe-exec만 | PA-6 |
| `verify_d11_collector_disjoint` | collector netns가 pause/net-disconnect 대상과 비공존(container-lifecycle는 AUTO 0·OPER self-impact 게이트) + netns DROP argv가 INPUT `-s <UE-pool>` 전용(:50051 ingest/mgmt CIDR 미교차, distinct 2-endpoint)로 self-DoS 차단 | 불변식② E9/X1/G4/D11 |
| `verify_grep0` | core↛verifier import, verifier_truth 채널 부재, Truth 타입 core 미참조 | PA-2 |
| `verify_no_sock_in_core` | core+signer에 docker sdk·sock·프록시 URL 리터럴 0 | PS-1 |
| `verify_ingest_hmac` | 위조 봉투가 WorldState 미도달, tamper Incident만 | PS-2 |
| `verify_replay_leak0` | JSONL+checkpoint에 카나리/실비밀 0 | PS-3 |
| `verify_keys` | 소스 리터럴 3키 분리·argv 누수 0 | PS-3 |
| `verify_egress_allowlist` | 비-anthropic 아웃바운드 실패(dry) | PS-4 |
| `verify_no_key_in_image` | 이미지 레이어 비밀·카나리 0 | PS-5 |
| `verify_seq_persist` | 크래시 후 이전 seq 재전송 거부 | PS-6 |
| `verify_injection_gate` | 신뢰불가 고-severity가 act 미도달 | PS-7 |
| `verify_bind_iface` / `verify_viewer_auth` | 0.0.0.0 바인드 0 / 무토큰 거부 | PS-8 |
| `verify_operator_binding` | 캡처 승인 다른 digest 재사용 거부 | PS-9 |
| `verify_parsers` | SMF/MME regex vs ANSI fixture, metric 파싱 | P4-1/P4-2/P4-5 |

# 부록 B — 라이브 상태변경 유보 항목 (operator-go)

아래는 코드+하네스+dry/read-only 검증까지만 확정하고 실집행은 **operator-go 유보**(운영 제약: testbed <TESTBED-IP> 상태변경 자동실행 금지):
- PS-4 egress allowlist iptables 실적용.
- 모든 actuation(DROP·docker pause·서명명령·컨테이너 stop·설정수정) — GATE1 누수0 실측·GATE2 효력·E2E 실집행.
- escalate 노드의 실제 서명명령 발행(PA-8) — record_intent까지만, 발행은 operator-go.

---

# 섹션 ④ Phase P0 패널 확정 (PP-1 ~ PP-3)

> 2026-07-07 P0 3검증자 패널 합의 반영. 각 항은 정본 문구를 **supersede**하는 락된 계약이며 이후 Phase는 이 결정에 대해 생성한다. 2대 불변식 우선.

## PP-1 — recovery 피저빌리티 게이트 = success_probability (recovery_score는 랭킹 전용) [M6/E-2]

**Supersession.** 프로토타입 §5의 "recovery_score ≥ 0.7 = 실현가능" 조항 **삭제/폐기**. 두 개념을 분리한다.
1. **피저빌리티 게이트(admissibility, 이진)** = `success_probability >= success_prob_feasible_min(0.70)`. success_probability는 recovery_type별 FIXED prior(FEASIBILITY §3, 0.80~0.95). 7개 실행가능 타입 전부 통과 → 영구-infeasible 데드락 해소.
2. **recovery_score 복합식(§5, 불변)** = `clamp(succ·(0.6·Σtrust_rec/100 + 0.4·mission_rec/100)·(1−risk)/(1+cost), 0, 1)`. 피저블 후보의 **정렬(RANK) 키로만** 사용, admissibility를 절대 게이트하지 않음. 20~40pt trust-delta priors가 이 값을 ~0.14~0.38로 상한하므로 0.7 게이트는 모든 대응을 영구 infeasible로 만든다(수학적 모순).

**구현 계약(이미 구현·확정).**
- `mdg/core/nodes/rank_recovery.py::rank_recovery` — `feasible = [a for a in legal if _succ(a) >= feasible_min]` 게이트 후 `recovery_score` 정렬. prior 없는 타입은 succ=0.5 기본 → 게이트에서 배제.
- `mdg/core/scoring.py::recovery_score` — docstring "RANKING-ONLY; not a feasibility threshold" 명시(회귀 방지).
- `mdg/config/recovery_priors.yaml`·`loader.py`·`defaults.py` — 게이트 키를 `feasible_min` → **`success_prob_feasible_min`**로 개명(미래 리팩터가 게이트를 recovery_score로 재배선 못 하게 라벨 고정). rank_recovery는 legacy 키 폴백 유지.
- 검증: `mdg/tests/test_recovery_gate.py` — (a) 전 prior가 게이트 통과, (b) 전 recovery_score < 0.70(분리 핀), (c) 개명 키 존재, (d) unknown 타입 게이트 배제.

**Amendment(패널-1 binding step d + risk-note 3 이행, 2026-07-07).** 랭킹 정렬을 단일 `key=score, reverse=True`(Python 정렬 안정성 = 입력순서 의존)에서 **명시적 결정론 키튜플** `(-recovery_score, risk_order, 0 if reversible else 1, recovery_type)`로 교체. recovery_score가 ~0.14~0.38로 압축돼 동점이 흔하므로 `legal_actions` 순열에 top이 좌우되면 replay 재현성(불변식①)이 깨진다. 순서 = recovery_score desc → 낮은 risk → reversible-first → recovery_type명. `mdg/core/nodes/rank_recovery.py::rank_recovery` 내 `_sort_key`. 순열-불변 확인(backdoor_pause vs pfcp_firewall 양방향 입력 → 동일 top). 순수·subprocess 0.

**불변식.** 게이트(수치 ≥ 비교)·랭킹(수치 정렬) 모두 결정론 rank_recovery 내부, LLM/Note 필드 미참조. 엣지는 여전히 chosen_action_risk/reversible/None만 read(PA-4 불변). subprocess 0. ①② PASS.

## PP-2 — to_record = 모듈레벨 함수 + 직렬화 최종 스크럽(default=str 우회 봉인) [PS-3]

**표기 정정.** PS-3 #1의 `mdg/core/state.py::MDGState.to_record()` 점표기는 **메서드 바인딩이 아니라 state.py 네임스페이스 소속 심볼**을 가리키는 약칭이다. MDGState는 LangGraph가 `__annotations__`를 채널로 introspect하는 TypedDict(total=False)이므로 메서드/비-annotation 속성을 얹을 수 없다. 확정 형태 = 모듈레벨 순수함수 `to_record(state: MDGState) -> dict`(state.py, `__all__` export, driver 소비). 심볼 존재·형태만 상이 → 계약 위반 아님.

**실 갭 수정(패널 발견).** driver 녹화 경로 `json.dumps(safe, default=str)`가 redact **이후** 실행되어, `_json_safe`가 놓친 비-BaseModel/dict/list 객체를 default=str가 직렬화 시점에 새 문자열로 합성 → 그 문자열은 지나간 redact를 재통과하지 않아 `__str__` 내 비밀이 스크럽 우회. 계층 순서 불변식(허용투영→스크럽→기록)의 구멍.
- **수정**: `mdg/core/driver.py::_record` — 직렬화 후 라인 전체에 최종 스크럽 1패스 추가: `line = _scrub_str(json.dumps(safe, ensure_ascii=False, default=str)); fh.write(line + "\n")`. `[REDACTED]` 치환은 따옴표/역슬래시 미생성 → JSON 유효성 보존.
- 검증: `mdg/tests/test_record_contract.py` — (a) `_RECORD_ALLOW ⊆ MDGState.__annotations__`(팬텀 키 0), (b) 비밀류 필드명 부재, (c) 미선언 키 투영 후 드롭, (d) default=str 우회가 최종 스크럽으로 봉인·JSON 유효.

**불변식.** to_record 순수(I/O·clock·subprocess 0), 비밀보유 모듈 import 0. 화이트리스트 default-deny 유지. ①② PASS.

## PP-3 — overall_impact = max(weighted_mean, criticality_floor) [E8/M5]

**Supersession.** 제안식 `Σ mission_weight[d]·(100−trust[d])/100` 단독 사용은 **보안 결함**으로 금지(보상적 가중평균이 단일 안전-핵심 도메인 전면침해를 희석: command weight=20, command trust=0, 나머지 100 → 20=Green인데 명령채널 완전 장악). base term으로만 채택하고 criticality floor와 결합.

**확정식.** distrust[d]=100−trust[d], 활성집합 D=present(non-stale) 도메인.
1. `weighted_mean = Σ(w[d]·distrust[d] for d∈D) / Σ(w[d] for d∈D)` — 실제 Σw 정규화(≈100 가정 금지, Σw>0 가드). 부재/스테일 도메인은 D에서 **제외**(distrust=0/trust=100으로 주입 금지 — dead-collector가 만점으로 읽혀 impact 은폐하는 fail-open 차단).
2. `floor = max over d∈D of crit_floor(d, distrust[d])` — mission_weight와 **독립**(weight=0이어도 발동 → config 변조로 안전도메인 무력화 불가).
3. `overall = clamp(int(floor(max(weighted_mean, floor))), 0, 100)`. band = Green0-30/Yellow31-70/Red71-100.
4. E8 1회: 최저 confidence<임계면 band 한 단 상향(tighten-only), 정수 불변.
5. 전 도메인 stale이면 직전 band 홀드(Green이면 Yellow로 상향, Green 산출 금지) + sensor-loss Incident.

**crit_floor 기본표(mission_profile.yaml·defaults.py, [distrust_thr, floor] high→low).** command/session_network: `[[71,71],[40,45]]`; identity_access: `[[71,45]]`; communication/mission: `[]`. 검증: command 반례 mean=20·floor=71 → overall=71=Red(교정).

**구현 계약.**
- `mdg/core/scoring.py::crit_floor(domain, distrust, table)`·`::overall_impact(distrust_by_domain, weights, floor_table) -> (int, float)` — 순수·단조 비감소.
- `mdg/core/nodes/compute_impact.py::compute_impact` — present-set distrust 조립(부재 도메인 제외), agg_overall 호출, all-stale 홀드+sensor-loss Incident.
- `mdg/config/mission_profile.yaml`·`defaults.py` — `criticality_floor` 표.
- 검증: `mdg/tests/test_impact_floor.py` — command 반례→Red, weight=0 floor 발동, present-set 재정규화, 단조성, clamp, all-stale 홀드, 노드 통합.

**불변식.** 순수 산술(LLM 미참여), 단조성으로 주입 허위신호는 impact를 올릴 수만 있고 은폐 불가(PS-7 정합). 엣지는 impact.band만 read(불변). secret-free(PS-3). ①② PASS.

**잔여(operator/후속 패널 확정 권장, BLOCKED 아님).** crit_floor 임계(71/45)는 발명 시드값 → network-vuln-detector/uav 패널 검증 필요. mission 도메인 이중계상(E22 rollup vs mission_weight) 및 v2 MissionImpactObject 4차원(availability/integrity/safety/continuity) 매핑은 v2 정본 대조 후 별도 확정. stale 판정의 라이브 liveness 신호(collector 사멸 감지)는 현재 파이프라인 미보유 → present-set 제외 구조만 배선, 감지신호 배선은 후속.

---

# 섹션 P1 — 관측엔진 배선 (P1 검증자 패널 확정, 2026-07-07)

## P1-Q1 — sock-proxy 화이트리스트에 read-only `GET /containers/{id}/logs` 추가 (사이드카 폐기) [PS-1/A-2]

**결정.** docker-logs 의존 collector(mongo, 후속 SMF/MME)의 PS-1 충돌을 **Option A**로 해소: sock-proxy 화이트리스트에 read-only `GET /containers/{id}/logs` 엔드포인트를 추가한다. 로그-shipping 사이드카는 **폐기**.

**근거.** `inspect`(`GET /containers/{id}/json`)는 이미 화이트리스트에 있고 컨테이너 stdout보다 **더 많은 정보를 노출**한다 → read-only logs GET은 신뢰경계를 넓히지 않는다(순증 0). 사이드카는 별도 프로세스/볼륨/수명주기를 추가해 공격표면과 운영복잡도만 키운다. `docker logs`가 그대로 메커니즘으로 남고 프록시에서 라우팅되며, 동일 경로가 후속 SMF/MME 로그테일에도 재사용된다.

**구현 계약.**
- `DESIGN_DECISIONS PS-1 #2` 허용목록 4→5 엔드포인트로 갱신(`GET /containers/{id}/logs` 추가). 명시 거부목록 불변(logs는 거부에 없었음).
- `mdg/collector/mongo.py` 헤더 NOTE를 "PS-1 tension(open)"→"PS-1 resolution(locked, Option A)"로 확정. `_docker_logs_argv`(`docker logs --since`) 불변 — argv는 그대로, 배포 시 DOCKER_HOST가 프록시를 가리킴.
- 파서(`parse_mongo_line`)는 소켓 독립·기 단위검증됨(회귀 없음).

**불변식.** GET(read-only)만 추가, 상태변경 메서드 0. core/signer는 여전히 프록시 URL·docker sdk 미참조(verify_grep0 284 checks PASS). ①② 불변.

## P1-Q2 — netns 진입 = `nsenter --target <pid> --net --`, recon PID 해석→collector 주입, 미해석 시 inert [A-1/B-2/불변식②]

**결정.**
1. **정본 진입 = `["nsenter","--target",str(pid),"--net","--"]`** (net ns 단독). `ip netns exec <container>` **폐기**: 도커는 컨테이너 netns를 `/var/run/netns`에 미등록 → 부팅 심링크(상태변경, 운영제약 저촉) 없이는 실패. `nsenter --target`은 `/proc/<pid>/ns/net` 직행, 상태변경 0.
2. **`--net`만 진입, mount ns=mdg 유지** → 대상 netns 안에서 **mdg 이미지의 tcpdump/ss/pymavlink** 실행. B-2(air 이미지 curl/nc 부재)를 원천 회피(대상 바이너리 미사용).
3. **PID 취득 = sock-proxy `inspect .State.Pid`(read-only)** → `WorldState.pid[container]`, `RoleBinding.provenance="inspect"`. `docker exec`/raw sock 미경유.
4. **미해석 = inert.** `netns_prefix or ["ip","netns","exec",container]` 폴백 **제거**. 센티널 3분기: `None`=미해석(collect()→`[]`, Backend 미호출) · `[]`=현재 netns · non-empty=대상 진입. 오대상 라이브 탭을 구조적으로 차단(누수-0 정합).
5. **실행경로 불변식②:** nsenter argv는 recon/런처가 조립·주입만, spawn은 기존 `Backend.run(ExecRequest(read_only=True))` 단일 경로. core/collector는 docker.sock 미접근.

**구현 계약(본 P1에서 구현).**
- **NEW `mdg/safe_exec/nsenter_helper.py`** — `netns_prefix_for(pid)->list|None`(순수 빌더), `resolve_netns_targets(docker, containers)->dict[str,int]`(sock-proxy inspect, fail-closed 누락), `build_netns_prefix_map(pidmap)->dict[str,list]`(런처 브리지). docker sdk import·sock/proxy 리터럴 0(duck-typed `inspect_pid`).
- `mdg/core/recon.py::recon_boot(cfg, seqwm, ledger, docker=None)` — `NETNS_CONTAINERS=["gcs_proxy","uav_ue","web_backend"]` PID 해석→`world.pid.update`+`RoleBinding.provenance="inspect"`. `docker=None`(기본)이면 pid 비움=전 netns collector inert.
- `mdg/collector/__init__.py::build_collectors(..., netns_prefix_map=None)` — 누락됐던 recon→collector 스레딩 배선. `m.get("gcs_proxy"/"uav_ue"/"web_backend")`를 air 2·web에 주입. network/mongo/mission은 netns 무관.
- `mdg/collector/air_side.py`·`web.py` — 폴백 제거 + `if netns_prefix is None: return []` inert 선가드.
- 검증: `mdg/tests/test_p1_engine.py::test_netns_prefix_builder_and_inert_collectors` — 빌더 정본형/None, resolve fail-closed(pid=0/미존재/None docker 누락), inert 시 3 collector 모두 `collect()==[]` 且 backend 미호출. 기존 air/web 라이브 테스트는 `netns_prefix=_NSPREFIX` 주입으로 갱신.

**배포 잔여(operator-go 유보, BLOCKED 아님).**
- `nsenter --target <pid>`는 대상 PID가 mdg PID ns에서 보여야 함 → mdg를 `pid:host` 또는 host-pid 사이드카로. CAP: netns 진입=CAP_SYS_ADMIN(+NET_ADMIN), 대상 tcpdump=CAP_NET_RAW → 최소권한 nsenter-helper에만 부여, core/signer 미부여(PS-1 권한분리).
- `docker.inspect_pid()` 구현체 `mdg/safe_exec/docker_backend.py`는 별도 P0(D-2 잔여) — 본 P1은 duck-typed 소비자·빌더·주입 경로까지만. 라이브 PID 해석·nsenter 실 tcpdump는 GATE1(누수-0 실측) 이전 **operator-go 유보**(코드+mock/dry 검증까지만).

**불변식.** PID 취득 read-only, 미해석 inert=오대상 탭 구조차단(운영제약 정합). argv 조립≠spawn(불변식②, Backend 단일경로). core sock 미접근(verify_grep0 PASS). ①② PASS.

## P1-Q3 — P1은 5 collector만 출하, SMF/MME 로그 collector는 파서 페이즈로 이월 [P4-1/P4-5]

**결정.** P4-1/P4-5가 락한 SMF IMSI↔IP 세션테이블(`smf_session.py`)·MME attach 로그테일(`mme_log.py`)은 **P1에서 미구현**, 후속 파서/verify_parsers 페이즈로 이월. P1 출하 = 기존 5 collector(air 2·network·mongo·mission).

**근거.** 둘 다 mongo와 동일한 docker-logs 메커니즘의 추가 collector이나 (a) P1이 아직 보류한 sock-proxy logs 접근에 의존(P1-Q1로 경계는 확정됐으나 구현은 파서 페이즈), (b) bounded `collect()` 모델과 별도 파싱 계약 필요, (c) IMSI PII 취급 → 누수-0 리뷰 대상. P1 관측엔진 골격을 5종으로 고정하고 세션-상관 collector는 파서 확정과 함께 배선.

**불변식.** 신규 collector 0 추가로 P1 스코프 불변. 5 collector 계약(HMAC 봉투·bounded collect·inert 가드) 유지. ①② 불변.

---

# 섹션 P2 — recon/타깃 베이스라인 (P2 검증자 패널 확정, 2026-07-07)

> 2026-07-07 P2 3검증자 패널 합의 반영. 각 항은 정본 문구를 **supersede**하는 락된 계약. 2대 불변식·운영제약(testbed 상태변경 자동실행 금지) 우선. 본 P2는 코드+계약까지만 — 라이브 상태변경(netns 진입 실행·서명 확정 tail) 실집행은 **operator-go 유보**.

## P2-Q1 — stage-2 메커니즘 = 전송만 교체(nsenter --net) + 2계층 pause 대상해석(L1 SMF-log/정적맵, L2 tun-scan 보조) [A-1/C-3/PS-1/P4-1]

**충돌 해소.** IMPLEMENTATION_GAPS A-1/C-3·P4-1은 stage-2를 `docker exec ip addr show tun_srsue`로 명시했으나 PS-1 프록시 화이트리스트가 `exec`를 명시 거부 → 두 락 계약 충돌. **전송(transport)만 교체·관측 시맨틱 유지**로 화해: `docker exec` → `nsenter --target <pid> --net -- ip -4 addr show <tun>`(P1-Q2 정본 진입, mount ns=mdg 유지→mdg `ip` 바이너리, B-2 무력화). PS-1 화이트리스트 개정 불요. 이미 `resolve.py`가 nsenter로 구현되어 있었고 본 P2에서 계약을 명문화.

**2계층 pause 대상해석(락).** `resolve.reverse_container_for_ip(ip, result, smf_table=None)`:
1. **Layer 1 (PRIMARY, netns 진입 0)** — IP → IMSI [`SmfSessionTable.imsi_for_ip`, SMF 로그 P4-1] → 컨테이너 [정적 IMSI↔컨테이너 부팅상수 `spec.imsi_container_map()`]. 화이트리스트 endpoint(inspect+logs)만으로 대상 확정 → exec·nsenter 불요. netns 진입 표면 최소화(자기보안 우월).
2. **Layer 2 (SECONDARY, ground-truth 교차검증)** — 라이브 nsenter tun-scan 역 ip_map + 명시 binding 스캔. SMF 테이블 바인딩 공백(세션 미생성/로테이션/idle) 시 유일 ground-truth. **1차 단독 불가 → 2계층 병존.** tun exec-scan은 "유일 역매핑"에서 **"ground-truth 교차검증(2차)"로 강등**(삭제 아님).

**정본 supersede.** A-1/C-3·P4-1 use-case(2)의 "docker exec ip addr show tun_srsue" 문구는 (a) 전송 = nsenter --net(exec-free)로, (b) tun exec-scan = 2차 ground-truth 교차검증으로, 1차 = SMF-log IMSI 세션테이블 + 정적 IMSI↔컨테이너 맵으로 정정된다. 미개정 시 문구 그대로 옮긴 구현자가 exec→프록시 403(load-bearing).

**구현 계약(본 P2에서 구현).**
- `mdg/targets/inputspec.py::RoleSpec.imsi` — 정적 IMSI↔컨테이너 부팅상수(ue.conf/ue2.conf host bind-mount source; exec/nsenter 0). `DefInputSpec.imsi_container_map()` 접근자(imsi 미선언 role은 배제, fail-closed to L2).
- `mdg/config/defaults.py` INPUT_SPEC roles — uav_ue imsi=001010000000001, attacker_ue imsi=001010000000002. 동적 tun IP은 여전히 미핀(stage-2 라이브).
- `mdg/targets/resolve.py` — `ResolveResult.imsi_container`(spec에서 조립), `reverse_container_for_ip(..., smf_table=None)` 2계층(L1 SMF→정적맵, L2 tun-scan 역맵+binding 스캔). 모듈 docstring에 2계층 framing·전송교체 명문화.
- `mdg/collector/smf_session.py` — 용도(2) docstring를 L1 primary(정적맵)/L2 secondary(tun-scan)로 갱신.
- 검증: `mdg/tests/test_p2_recon.py::test_imsi_container_map_is_boot_constant`·`::test_reverse_layer1_smf_imsi_to_static_container`(L1이 netns 진입 0으로 attacker_ue 해석, 미지 IP fail-closed, smf_table 부재 시 L2 폴백).

**불변식.** nsenter·inspect·logs 전부 safe-exec 경유(단일 subprocess). core·orient/decide·signer는 sock/exec/nsenter 참조 0(verify_grep0 288 PASS). 순수 관측·상태변경 0. 라이브 netns 진입 실 tun-scan은 **operator-go 유보**(비-allow_live Backend DRY-RUN). ①② PASS.

**잔여.** (1) mdg 컨테이너 그린필드(D-2 잔여) — nsenter-helper 실경로 재실증은 GATE0/1. (2) nsenter는 대상 PID(inspect) 필요·재기동 시 불안정 → 캐시 금지, 매 해석 재-inspect(C-3). (3) SMF-log L1 공백 시 L2가 유일 ground-truth이므로 2계층 병존 필수.

## P2-Q2 — 부팅 signing = 관측 3치 `SigningObs.UNKNOWN`, 기대치(spec)와 타입분리, uav_proxy 권위신호로만 승격 [MEMORY/§9-B/A-2]

**Supersession.** `WorldState.signing`을 bare `bool` → 3치 관측 enum `SigningObs`(UNKNOWN/CONFIRMED_ON/CONFIRMED_OFF)로 승격. bool-False 인코딩은 **"confirmed OFF"와 "아직 미관측"을 뭉개는 보안 결함**: (a) §9-B 서명은 토글식(실 OFF 가능)이고, (b) 관측이 비대칭(드롭로그=ON 양성증거 / 드롭부재≠OFF)이라 bool로는 표현 불가. UNKNOWN(부팅기본, ≠off)이 confirmed-OFF로 오독되면 command 무인증 과잉대응 자해DoS(PS-7).

**전이 권위 게이트(락).** `signing`은 오직 **uav_proxy 출처 관측**으로만 전이:
- `→ CONFIRMED_ON`: uav_proxy 드롭로그 `⛔ 서명검증 실패 → SITL 차단 (누적 N)` / `🔒 서명 강제 ON` 기동배너 / `/api/signing` enforced(실집행 증명). §A-2대로 서명 **성공은 per-packet 로그 부재** → 성공스트림 파싱 금지, 실패카운터/기동배너/API만 admissible. (드롭카운터 재시작 리셋 위험은 기동배너/API 병용으로 완화.)
- `→ CONFIRMED_OFF`: uav_proxy OFF배너 / 미서명 명령 SITL 도달·actuate 관측만. 침묵으로 추론 금지.
- **전이 없음(UNKNOWN 유지)**: gcs_proxy env·uav env·docker inspect·드롭0(증거부재). **env-ON은 승격 근거로 불충분**(설정의도≠실집행; 검증기 사망 시 false-confidence). MEMORY 오판가드 코드화.

**기대치≠관측치(핵심).** `spec.signing_expected`(§9-B 정책 기대치, config-only 불변)는 trust prior로만, `world.signing`을 **절대 미세팅**(expected=on→CONFIRMED_ON 자동승격 금지 = gcs env 오판/기대치=진실 혼동 원천차단). recon은 out-of-graph라 로그테일 안 함 → 부팅 확정소스 부재가 아키텍처적으로 정당(확정은 P3+ col_uav 드롭로그/배너/API 수집기 위임).

**legality.** `pred=="signing"` → `signing_enforced(world.signing)`(오직 CONFIRMED_ON). `send_signed_mode`(requires `["signing","role_verified.gcs"]`)는 CONFIRMED_ON일 때만 합법. 무공격 run UNKNOWN이면 서명명령 불가 = 보수적 정당(미확정 인증 의존 금지). **락**.

**구현 계약(본 P2에서 구현).**
- `mdg/core/worldstate.py` — `SigningObs(str,Enum){UNKNOWN,CONFIRMED_ON,CONFIRMED_OFF}` + `signing_enforced(obs)->bool`. `WorldState.signing: SigningObs = UNKNOWN`(bool 리터럴 제거). 술어명 `signing` 보존(PA-3 vocab 불변).
- `mdg/core/recon.py::recon_boot` — `signing=SigningObs.UNKNOWN`(현행 `signing=False` 제거), docstring UNKNOWN 명문화.
- `mdg/core/legality.py:21` — `signing_enforced(world.signing)`(현행 `bool(world.signing)` 대체).
- `mdg/config/defaults.py`·`inputspec.py` — `signing_expected: bool`(정책 기대치, 관측 미세팅) 유지·주석 명문화.
- 검증: `test_p2_recon.py:171,184`(`w.signing is SigningObs.UNKNOWN`으로 정정). 라이브 legality: UNKNOWN/CONFIRMED_OFF send_signed_mode ILLEGAL, CONFIRMED_ON+role_verified.gcs LEGAL 확인.

**전이 소비(P4 forward 계약, 본 P2 미배선).** expected↔observed 델타는 **수치로만** 결정론 채점에 유입(엣지는 impact.band만 read, 불변식①). CONFIRMED_ON→페널티0. UNKNOWN∧expected=on→상한있는 confidence-margin 페널티 1회(band 단독상승·라우팅 없음, PS-7 자해DoS 방지). CONFIRMED_OFF∧expected=on→command threat 결정론 상승 허용(실 posture 회귀 HIGH). 현재 `world.signing` 소비처는 legality 단독(compute_trust 미참조)이라 델타 스코어링은 P3 수집기 착수 후 배선.

**불변식.** signing 델타는 수치로만·엣지 미참조(①). recon out-of-graph·로그테일은 collector(②). 비판단원칙(expected≠observed·uav_proxy만 권위) 준수. secret-free(enum, 키물질 미반입 PS-3). ①② PASS.

**잔여.** (1) CONFIRMED_OFF는 uav_proxy OFF배너 권위신호에만 도달 — 배너 실재는 P3 collector 라이브(read-only) 확인 필요. 미존재 시 토글오프가 UNKNOWN으로만 관측 → 드롭 윈도우 만료를 UNKNOWN 강등이 아닌 freshness 메타로 노출 권고. (2) 드롭카운터 재시작 리셋 → 포스처는 기동배너/API 우선, 드롭은 활동 메트릭으로 분리(수집기 P3+).

## P2-Q3 — inspect_networks 백엔드 계약 락(GET .NetworkSettings.Networks·평탄투영·단일스냅샷·degrade-safe) [PS-1/PS-3/C-3]

**계약(LOCK, 미생성 `safe_exec/docker_backend.py`가 준수).** `resolve.py`가 소비하는 duck-typed `inspect_networks`(cellular IP)의 미확정 노출형태를 6절로 확정:
1. **동일 endpoint, 신규 프록시 표면 0.** `inspect_networks`는 이미 화이트리스트인 `GET /containers/{id}/json` 바디의 `.NetworkSettings.Networks`에서만 취득. docker `/networks`·`/networks/{id}` 라우트 **호출 금지**(PS-1이 "networks" 거부; 메서드명은 misnomer trap). 프록시 허용목록 불변.
2. **반환형 = 평탄 투영 `dict[str,str]`** `{docker_net_name: IPAddress}`(`.NetworkSettings.Networks[name].IPAddress`). raw 서브객체(Gateway/MacAddress/EndpointID/IPAMConfig) 반환 금지. NAME 키(RoleSpec.cellular_network 일치), 빈 IPAddress는 키 생략 → `.get()` None.
3. **하드 투영/비밀위생(load-bearing, PS-3).** private `_inspect`가 `.State.Pid`(→int) + `.NetworkSettings.Networks[*].{name,IPAddress}`만 파싱, `.Config.Env`/`.Mounts`/`.Args`/labels는 **파싱 시점 폐기**(반환·로깅·State·JSONL 미반입). 형제 컨테이너 inspect의 Env가 ANTHROPIC_API_KEY/operator-token/HMAC 키를 정당 보유 → raw 반환 = PS-3 exfil 채널.
4. **duck-typed optional 유지·실백엔드 무조건 구현.** resolve.py `hasattr` 가드 유지(mock/test degrade). 실백엔드는 동일 GET·동일 투영 스냅샷이라 free → 무조건 구현. `inspect_pid`만 하드필수 계약.
5. **단일 스냅샷 TOCTOU 핀.** `GET /containers/{id}/json`을 (container, recon-pass)당 1회 fetch, 그 바디에서 pid AND networks 파생(memoize). 프록시 히트 절반·coherent pid/IP 쌍(X7 config_version TOCTOU 정합).
6. **type-safe degrade, verified 미약화.** 부재 메서드/4xx/malformed → None(raise 0; 미해결 1건이 recon abort 금지). cellular IP는 **advisory only**(인프라 주소+pause 진단), verification predicate 아님. 인프라 role_verified=(pid is not None)(resolve.py:133), UE풀은 stage-2 tun-scan으로 verify → pid-only degrade는 verified 비트 불변.

**구현 계약(본 P2).**
- `mdg/targets/resolve.py::_inspect_cellular_ip` docstring — 위 6절 계약 명문화(미래 backend 준수 앵커).
- **미래 `mdg/safe_exec/docker_backend.py`(D-2 잔여, 본 P2 미생성)** — 6절 준수. `verify_replay_leak0`에 inspect-투영 카나리 fixture 확장(canned inspect JSON `.Config.Env`에 MDG_CANARY_* → `_inspect/inspect_pid/inspect_networks` 출력·resolve 출력·State·JSONL에 카나리 0) — backend 구현 시 필수.

**불변식.** 신규 프록시 endpoint 0(PS-1 표면 불변). 파싱시점 투영으로 비밀 미반입(PS-3). 라이브 상태변경 0(read-only inspect; Backend.allow_live 기본 False → DRY-RUN, operator-go 유보). ①② PASS.

---

# 섹션 P3 — 서명 posture·operator-gate 키위생·LLM 자기표면 (P3 보안 패널 확정, 2026-07-07)

> 2026-07-07 P3 보안 전문가(network-vuln-detector) 패널 확정. IMPLEMENTATION_GAPS **C-2(유일 미해소 설계판단)** 종결 + P2-Q2/PP-3 residual 락. 라이브 read-only 실측(uav_proxy 서명강제·gcs_c2 서명·/sign.key 3마운트) 근거. 2대 불변식·운영제약(testbed 상태변경 자동실행 금지) 우선. 본 P3은 코드+계약+dry/read-only까지만 — 라이브 서명명령 발행은 **operator-go 유보**.

## P3-Q1 — ★ C-2 종결: 권한분리(authorization ⟂ signing), MDG는 /sign.key 미보유·신규확산 0 [C-2/PS-5#3/PS-9/H5/E11]

**충돌의 해소(전제 오류 제거).** C-2가 "operator-gate shim을 gcs_c2 netns에 두되 키 비확산"으로 순환한 이유는 **"operator-gate가 서명키와 공존해야 한다"는 전제가 거짓**이기 때문이다. 라이브 실측이 이를 증명한다:
- `uav_proxy`가 **드론측에서 서명검증을 이미 강제**한다: 기동배너 `[proxy] 🔒 MAVLink2 서명 강제 ON (무서명/오서명/리플레이 → SITL 폐기)` + 드롭카운터 `⛔ 서명검증 실패 → SITL 차단 (누적 N)`(cipher 0.0.0.0:14555 ARIA-256-GCM ← gcs_proxy 172.30.0.10). 무서명 명령은 SITL 미도달.
- `gcs_c2`가 **이미 /sign.key를 보유하고 서명**한다: `[GCS] 🔒 MAVLink2 서명 송신 ON (link_id=0)`.
- `/sign.key` 마운트 = uav_proxy(검증)·gcs_c2(서명)·web_backend **정확히 3곳**, gcs_proxy=none(read-only inspect 확정).

**결정(락).** operator-gate와 서명키를 **직무분리**한다. MDG는 /sign.key를 **어떤 경로로도 마운트/보유/재확산하지 않는다**.
1. **send_signed_mode는 자율경로에 절대 진입 불가.** 레지스트리 실측: `risk=HIGH, tier=OPER, backend="signer-shim"`. 조건부 엣지(PA-4)에서 `risk==HIGH → escalate → END`. 유일 AUTO 응답은 `nsenter_input_drop`(netns DROP, risk=MED/tier=AUTO)이며 이는 /sign.key 무관. **∴ MDG 자율(act) 경로는 서명키를 영원히 필요로 하지 않는다.**
2. **operator-gate = 인가 토큰 발행(서명 아님).** escalate 노드는 서명명령을 만들지 않고 **PS-9 명령바운드 OperatorRequest** `(decision_id, command_digest, nonce, expiry)`를 **operator-gate HMAC 키**(=/sign.key와 **별개 비밀**)로 발행, side-effect 0(현행 escalate.py `operator_gate=True` Intent 계약 유지). 이 토큰은 MDG ledger에만 존재.
3. **서명은 기존 gcs_c2가 out-of-band로 수행.** 실 서명명령 발행은 operator-go 유보(부록B). operator가 토큰 검증 후 **이미 키를 보유한 gcs_c2 서명경로**로 발행 → 신규 사이드카(C-2안 (a)=E11 재확산) 불요, gcs.py(ro) 수정(C-2안 (b)=testbed 오염) 불요. **/sign.key 발자국 = 현행 3곳 불변(순증 0).**
4. **`safe_exec.signer` = 키 미개방 emitter로 재규정.** send_signed_mode의 `exec="safe_exec.signer"`는 /sign.key를 **open/read 하지 않는다**. MVP=Backend.allow_live=False → command_digest 산출(토큰 재료)까지만. 라이브 승격 시에도 gcs_c2 서명 endpoint에 **인증채널 위임**(mTLS+operator토큰), 키 재마운트 절대 금지. `verify_no_key_in_image`(PS-5) + 신규 `verify_signer_no_keyopen`(정적: safe_exec.signer 소스에 sign.key 경로 리터럴·open 0).

**구현 계약.**
- `mdg/core/nodes/escalate.py` — 불변(operator_gate Intent, side-effect 0). PS-9 `(decision_id, command_digest, nonce, expiry)` HMAC 필드를 OperatorRequest에 배선(operator-gate 키는 State 미경유, PS-3).
- **미래 `mdg/safe_exec/signer.py`(D-2 잔여, 미생성)** — /sign.key open 0·경로 리터럴 0, allow_live=False DRY, 라이브 시 gcs_c2 위임(키 재마운트 금지 주석 load-bearing).
- `mdg/tools/registry.py` send_signed_mode — `secret="stdin"`(argv 누수 0, R6) 유지, backend 주석에 "SoD: 키 비보유·gcs_c2 위임" 명문화.
- 검증: `verify_operator_binding`(PS-9, 기존) + `verify_signer_no_keyopen`(신규) + `verify_no_sock_in_core`/`verify_grep0`(core·signer 격리 불변).

**불변식.** send_signed_mode=OPER-only(엣지 risk==HIGH만 read, ①). 서명키 발자국 순증 0(E11 종결). operator-gate 키 ⟂ /sign.key(직무분리·PS-5#3). escalate side-effect 0·발행 operator-go(부록B, ②). ①② PASS.

## P3-Q2 — col_uav 서명 posture 수집기(tail_signing_drops): 배너=권위, 드롭카운터=활동메트릭(posture 아님), 침묵≠OFF [P2-Q2/A-2/PS-1/PS-3]

**결정.** `tail_signing_drops`(owner=col_uav, backend=log-tail, requires=[])를 P2-Q2 `SigningObs` 전이 권위소스로 배선. 소스 = `uav_proxy` stdout(read-only, **P1-Q1 sock-proxy `GET /containers/{id}/logs`** 경유; docker exec 금지·read-only 경계 준수). 파싱 전 **ANSI-strip 필수**(`\x1b\[[0-9;]*m`, log_common.ansi_strip 재사용).
1. **배너 = posture 권위신호.** `🔒 MAVLink2 서명 강제 ON` 기동배너 매치 → `SigningObs.CONFIRMED_ON`. OFF배너 → `CONFIRMED_OFF`. 이것만 posture를 전이(P2-Q2 락).
2. **드롭카운터 = 활동메트릭, posture 아님.** `⛔ 서명검증 실패 → SITL 차단 (누적 N)`의 `누적 (\d+)`는 **공격활동 카운터**로만(counter diff>0=진행중 위조명령). **재시작 리셋**(누적 0으로 복귀)이 있으므로 카운터 부재/감소를 CONFIRMED_OFF로 **절대 추론 금지**(침묵≠OFF, P2-Q2). posture는 배너/API 우선.
3. **성공스트림 파싱 금지.** §A-2: 서명성공은 per-packet 로그 부재 → `Signature_Verified=PASS` 파싱 시도 영구 0. 실패카운터/배너/API만 admissible.
4. **비밀위생(PS-3).** 로그행은 cipher peer 튜플·counter만 보유(라이브 확인, 키물질 0). 수집기는 `SensorEv`에 **파생 enum/수치만** 투영(`{event: "signing_confirmed_on"|"sig_drop", cumulative:int}`), raw 로그행·peer 원문 미반입. HMAC 봉투(PS-2) + sense 드레인시점 검증.

**구현 계약.**
- **미래 `mdg/collector/uav_signing.py`(미생성)** — `docker logs -f uav_proxy` 테일(sock-proxy logs), ansi_strip 선적용, 배너→CONFIRMED_ON/OFF, 드롭카운터→활동 SensorEv(파생수치만). bounded collect·inert 가드·HMAC 봉투(5+1 collector 계약).
- 검증: `verify_parsers`(uav_proxy fixture: ANSI+이모지 배너/드롭행 → 정규식 매치·secret-free 투영), `verify_ingest_hmac`(봉투).

**불변식.** read-only logs(P1-Q1, 상태변경 0). 배너 권위·침묵≠OFF(P2-Q2 비대칭관측 준수). 파생수치만 투영(PS-3 secret-free·PS-7 인젝션게이트). ①② PASS.

## P3-Q3 — 서명 expected↔observed 델타 = 수치 결정론 채점(엣지 미참조) [P2-Q2 forward]

**결정.** P2-Q2 forward 계약을 수치 스코어링으로 배선(수집기 P3-Q2 착수 근거).
- `CONFIRMED_ON` → command 서명 페널티 0.
- `UNKNOWN ∧ spec.signing_expected=on` → confidence-margin 페널티 **1회·상한**(band 단독 1단 상향·라우팅 미유발, PS-7 자해DoS 방지). UNKNOWN은 posture 미확정이므로 threat 상승 금지(보수적).
- `CONFIRMED_OFF ∧ expected=on` → command threat **결정론 상승 허용**(실 posture 회귀 HIGH).
- 델타는 **수치로만** orient/decide/엣지에 유입(불변식①, 엣지는 impact.band·chosen_action_risk만 read).

**구현 계약.**
- `mdg/core/nodes/compute_trust.py`/`compute_impact.py` — signing 델타 수치화(현행 legality 단독소비 → trust 입력 확장).
- 검증: `verify_injection_gate`(위조 signing 신호가 act 미도달), 단조성(델타는 impact 상향만).

**불변식.** 델타 수치·엣지 미참조(①). 서명 posture 은폐 불가·상향만(PS-7). ①② PASS.

## P3-Q4 — crit_floor 임계(71/45) 검증락 + command 무인증-actuation distrust 바인딩 [PP-3 residual, network-vuln-detector 배정]

**검증(공격 시맨틱 대조).** PP-3의 71/45 시드값을 network-vuln-detector 패널이 검증·락. band cut = Green0-30/Yellow31-70/Red71-100.
- `command`/`session_network` `[[71,71],[40,45]]` — **정합·유지.** distrust≥71(command 채널 완전장악: 무서명 명령 SITL actuate / PFCP 세션 강제해제)은 **물리 actuation 직결** → floor 71=Red band 하한과 동일 cut(coherent). distrust 40-70(부분: signing UNKNOWN+의심 미확정)→floor 45(mid-Yellow), 보상적 평균이 반침해를 Green으로 희석 차단.
- `identity_access` `[[71,45]]` — **유지.** subscriber-DB(mongo) 침해는 integrity/recon(직접 flight actuation 아님) → Yellow floor 45가 정합(Red 과대평가 회피).
- `communication`/`mission` `[]` — **유지**(가용성 신호·rollup, 독립 floor 없음).

**추가 락(floor가 아니라 distrust 입력 계약).** command 도메인 distrust는 **무인증 명령의 실 actuation 관측**(CONFIRMED_OFF 하 미서명 명령 SITL 도달, P3-Q3)을 **결정론적으로 distrust≥71로 매핑**해야 floor 71이 발동. 이는 floor 표 변경이 아니라 compute_trust 입력 시맨틱(P3-Q3 latch와 동일 앵커). 서명검증 실패 드롭(누적 N)은 **차단성공=방어 정상**이므로 distrust 가산 금지(드롭=uav_proxy가 막았다는 양성증거).

**구현 계약.**
- `mdg/config/mission_profile.yaml` `criticality_floor` — 71/45 유지, NOTE를 "network-vuln-detector 패널 검증완료(P3-Q4)"로 갱신(회귀 방지 라벨).
- `mdg/core/nodes/compute_trust.py` — command distrust: 무인증-actuation 관측 → ≥71 결정론 매핑, 서명드롭(차단성공) → distrust 가산 0.
- 검증: `test_impact_floor.py`(command 무인증-actuation → overall=71=Red), 드롭카운터 단독 → distrust 미가산.

**불변식.** floor는 순수산술·weight독립(config 변조로 안전도메인 무력화 불가, PP-3). distrust 상향만(은폐 불가). 드롭=방어성공 미가산(오탐 방지). ①② PASS.

**잔여(operator-go 유보·후속).** (1) safe_exec/signer.py·uav_signing.py 실파일 = D-2 mdg 컨테이너 그린필드 후 GATE0/1. (2) OFF배너 실재는 토글 라이브(read-only) 확인 필요 — 미존재 시 토글오프가 UNKNOWN으로만 관측되므로 드롭윈도우 만료를 freshness 메타로 노출(P2-Q2 잔여 유지). (3) 실 서명명령 발행·gcs_c2 위임채널은 operator-go(부록B).

## P3-Q5 — present-set liveness = watchdog HEARTBEAT(sensor_loss)만, evidence.fresh_domains 게이팅 금지 [PP-3 residual/G7]

**결정(락).** compute_trust/compute_impact의 present-set 제외를 **evidence.fresh_domains(마지막-이상증거-ts staleness)로 배선하지 않는다.** liveness의 진짜(그리고 현재 미소비) SOURCE = collector HEARTBEAT을 Watchdog가 침묵-갭에서 서명 `sensor_loss` 봉투로 승격시키는 경로. evidence.fresh_domains/is_fresh/age는 **evidence-filter/TTL primitive로만** 유지(회귀 방지).

**fresh_domains가 잘못된 게이트인 이유.** §P 실측상 대다수 도메인은 event-driven(command/session PFCP=s5c_rx_deletesession 발생시만, 서명드롭=거부시만, Mongo id 22943=미션이벤트시만). 건강하지만 조용한 안전-핵심 collector는 임의 다수 윈도우 동안 evidence 0을 방출 → last-evidence-ts<=TTL로 present-set을 게이팅하면 살아있는 도메인이 impact 분모에서 제외돼 impact를 **과소평가**(PP-3가 금지한 fail-open의 역방향). base.py:17-18(tick_once가 조용한 틱에도 heartbeat 갱신 = liveness와 emission의 의도적 분리)과도 모순.

**correct source(구축됨·미배선).** BaseCollector.heartbeat()는 출력과 무관하게 매 틱 갱신 → Watchdog.check_once가 침묵-갭을 서명 `sensor_loss`(metric=sensor_loss, value=source_id, channel=watchdog) 봉투로 변환(sense 드레인시 PS-2 게이트 통과). watchdog.py:7-8이 이 배선을 P0-panel-3 후속으로 명시.

**배선(불변식·락 테스트 보존).**
1. `mdg/core/worldstate.py::WorldState.dead_domains: list[Domain] = []`(secret-free 파생 enum) 추가. sense가 드레인한 `sensor_loss` evidence의 value(dead source_id)를 **주입된 source→domain 맵**(`build_source_domains(collectors)`, collector `.source_id/.domain`에서 조립)으로 도메인 귀속해 기록. **비대칭 규칙(SigningObs 선례·PS-7):** loss에서 add-only, 해당 도메인의 실 emission(non-sensor_loss verified evidence)이 도착한 틱에만 clear(침묵은 clear 금지).
2. compute_trust는 `state["worldstate"].dead_domains`를 **읽어**(now 대비 상류계산) 해당 도메인 TrustObj를 **미방출**(dict에서 드롭) → compute_impact의 **이미 배선된** `if t is None: continue` 제외 활성화(compute_impact 바이트 불변). compute_trust 시그니처 불변·clock-free·순수(불변식①). **부재 필드→빈 set→전-present 폴백**(락 테스트 test_p1_engine/test_impact_floor 불변).
3. sense에 `source_domains=None` 주입파라미터 추가·graph.py가 `d.get("source_domains")` 스레딩. None(기본/스캐폴드)→liveness 부기 비활성(기존 동작 바이트 불변).

**구현 계약.**
- `mdg/core/worldstate.py::WorldState.dead_domains`, `mdg/core/nodes/sense.py::sense(..., source_domains=None)`, `mdg/core/nodes/compute_trust.py`(dead 도메인 드롭·worldstate에서 read), `mdg/core/graph.py`(source_domains 스레딩), `mdg/collector/__init__.py::build_source_domains(collectors)`.
- 검증: `test_p3_llm.py::test_compute_trust_drops_dead_domains_absent_field_fallback`(부재→전present, dead→드롭), `::test_sense_sensor_loss_marks_dead_and_live_evidence_clears`(loss add-only·live clear·None 비활성), `::test_build_source_domains_from_roster`.

**불변식.** liveness verdict를 State에서 read(compute_trust 재계산 아님)→clock 미도입·replay 결정론 보존(①). sensor_loss는 PS-2 서명봉투로 sense 드레인 통과(②). 비대칭(loss만 제외 추가·침묵은 안전도메인 미제거, PS-7 정합). secret-free(파생 enum, PS-3). ①② PASS.

**거부.** compute_trust에 clock 파라미터 추가해 fresh_domains를 내부계산 — trust를 wall-clock 비결정론화(replay 파괴)·liveness를 잘못된(anomaly) 소스에서 도출·watchdog 소유 TTL 결정 중복·락 계약 위험. **채택 안 함.**

**잔여(operator-go 유보, BLOCKED 아님).** 신규 watchdog→WorldState 배선(source→domain 맵·sense sensor_loss 소비·dead_domains 필드)은 추가 파이프라인 코드 → GATE1 누수0·E2E dead-collector 동작은 코드+dry/read-only로만 <TESTBED-IP> 대상 검증, 실 dead-collector 주입(라이브 상태변경)은 operator-go. 공유 침묵 임계 vs interval_s 튜닝으로 느리지만-살아있는 collector가 제외 전에 dead 오판되지 않게. compute_trust 드롭변경은 부재-필드 폴백 필수(없으면 test_p1_engine 동작 변경).

## P3-Q6 — litellm 구조화출력 = 수동파싱 권위 + 게이트/캡 하드닝(native response_model 금지) [PA-5/PS-3/PS-4/PS-7/E13]

**결정(락).** litellm native `response_model`(instructor 재프롬프트 루프) **미채택.** `litellm.completion(...)` → `resp["choices"][0]["message"]["content"]` → `model_cls.model_validate_json(_extract_json(...))` 수동파싱을 **권위 게이트**로 유지(예외→LLMUnavailable→결정표 폴백 G6). 근거: response_model의 숨은 re-ask는 비결정론·다중호출·temp/5s예산 미보장이라 불변식①(LLM 단일 temp0 조언·엣지 미참여) 위반. 여기에 5절 하드닝을 바인딩. **live 검증은 SAFETY 게이트가 아니라 FUNCTIONALITY 게이트**(apply_advice tighten_only 단조·note 엣지 미투입이라 최악의 hostile parse도 over-tighten만 가능, PA-5).

1. **온도 모델-게이팅(최고가치 수정).** 불변식 temp=0이나 current-gen(Opus 4.8/4.7·Sonnet 5·Fable/Mythos)은 `temperature` HTTP 400 → 강제 temp=0이 매 호출 400→영구 침묵 G6(조언LLM 사망). 계약: `client._emit_temperature(model)`가 sampling-수용 패밀리에만 temperature=0 방출, reject-sampling 패밀리는 **생략**(고정디코딩이 결정론 충족). `_REJECT_SAMPLING=("opus-4-8","opus-4-7","sonnet-5","fable","mythos")` 부분매칭.
2. **num_retries=0.** litellm 내부재시도가 (a) 5s 벽을 무효화(timeout이 실제 데드라인 아님) (b) 비결정론 다중호출 주입. 명시적 `for model in models` 루프가 **유일** 폴백. E13 정합.
3. **drop_params=True.** provider가 미지원 param(temperature/json_schema) 거부시 400 대신 드롭 → 온도게이트 오분류 2차망·폴백슬롯 미소모.
4. **response_format=json_schema(best-effort).** bare json_object는 anthropic provider에서 약한 프롬프트-넛지(서버강제 아님) → `{"type":"json_schema","json_schema":{name,schema=model_json_schema()}}`로 승격. 단 릴리스는 provider 준수에 **의존 안 함** — 로컬 model_validate_json이 권위.
5. **스키마 하드닝(PA-5 확장).** OrientNote/DecideNote에 `model_config=ConfigDict(extra="forbid")`(밀반입 키 거부). parse 전 **원시-바이트 하드캡**(`thresholds.yaml::llm_response_max_bytes=16384` FIXED) — pydantic 필드제한은 parse 후라 커버 못하는 parse측 DoS(깊은중첩/거대스칼라) 상한. `_parse_capped`가 캡→_extract_json→validate.
6. **models.yaml FIX-4(라이브 영향·즉시).** orient.fallback `claude-3-5-haiku-latest`(Haiku 3.5 은퇴 2026-02-19→404) → **`claude-haiku-4-5`**. decide.model `claude-opus-4-1`(폐기, retires 2026-08-05) → **`claude-opus-4-8`**. orient.model `claude-sonnet-4-5`·decide.fallback `claude-sonnet-4-5`(활성·temp수용) 유지. (opus-4-8은 temp reject이므로 FIX-4는 게이트(§1)와 반드시 동반.)

**구현 계약.**
- `mdg/llm/client.py` — `_emit_temperature`·`_response_max_bytes`·`_parse_capped`·`_schema_response_format`; completion에 num_retries=0·drop_params=True·response_format(json_schema)·게이트된 temperature.
- `mdg/core/state.py::OrientNote/DecideNote` — `model_config=ConfigDict(extra="forbid")`.
- `mdg/config/models.yaml`(모델ID FIX-4), `mdg/config/thresholds.yaml::llm_response_max_bytes`.
- 검증(전부 fake-injected·오프라인): `test_p3_llm.py::test_emit_temperature_gate`·`::test_note_extra_forbid_rejects_smuggled_keys`·`::test_parse_capped_rejects_oversize_before_parse`·`::test_complete_structured_kwargs_gate_and_fallback`(temperature/num_retries/drop_params/json_schema/timeout·폴백홉 assert)·`::test_complete_structured_omits_temperature_for_reject_family`.

**불변식.** LLM은 단일 temp0(수용시)·조언전용·엣지 미참여(①). 파싱실패/타임아웃/캡초과/refusal 전부 side-effect 0로 G6 결정표 폴백(노드 raise 0). 비밀위생: 키는 litellm env만·파싱실패 로깅은 예외타입+길이만(원문 미기록, PS-3). ①② PASS.

**잔여(operator-go 유보).** 실 anthropic wire의 json_schema 매핑·400-on-temperature 실거동은 claude-api 레퍼런스 기반 계약(로컬 미관측) — 1회 operator-go live smoke(감독하 단일 라운드트립 파싱 확인, CI 아님·키/egress DROP)로 functionality 확정, safety는 5절 monotone containment로 non-blocking. litellm 버전 bump·모델 repin(특히 reject-sampling로) 시 게이트 자기정합성 재확인 + live smoke 재실행.

---

# 섹션 P4 — 대응 dispatch 타깃바인딩·operator-gate 키위생·승인원장 (P4 구현패널 확정, 2026-07-07)

> 2026-07-07 P4 구현 검증자 패널 확정. response.py 타깃해석 갭 + operator-gate HMAC 키 부트스트랩 + PS-9 승인원장 형태 3건 종결. 2대 불변식·운영제약 우선. 코드+하네스+dry/read-only까지만 — 라이브 IP DROP·실 서명발행·tmpfs 실마운트는 **operator-go 유보**. 검증: `test_p4_response.py` 27/27, 전 verify_* PASS, 전체 133 passed.

## P4-Q1 — pivot 타깃 = 불투명 검증-대상 셀렉터(opaque validated selector)로 chosen_action까지 전파, DROP src는 verified 맵 순수조회로만 바인딩 (fail-closed) [PA-4/PS-7/PS-9/G3]

**갭.** `rank_recovery`가 `top.params`를 버려 `chosen_action` Intent가 `incident.target`을 잃고, `response._resolve_target`이 `pid_map` 첫 원소/하드코딩 `"target"` role을 **추측** → UE풀 소스가 복수면 오대상 DROP이 구조적으로 가능. 게다가 verified 게이트 부재로 미검증 바인딩에도 DROP argv 생성. 보안(PS-7 자해 DoS): `incident.target`은 텔레메트리/상관 유래 **신뢰불가 입력**이라 `iptables -s`에 직접 실으면 공격자가 `target=operator IP`/정상 UE IP를 주입해 MDG가 아군을 스스로 격리(self-DoS).

**결정(락).** pivot 타깃을 **사전해석 라이브 IP가 아니라 불투명 검증-대상 셀렉터**로 chosen_action까지 전파하고, `(pid, src_ip)` 해석은 dispatch 시점 verified WorldState 바인딩 맵의 **순수 조회(lookup)로만** 수행, 미검증/미해석 시 **fail-closed inert(DRY)**. 라이브 IP 확정(stage-2 tun scan)은 그대로 operator-go 유보.
1. **`state.py::Intent` 셀렉터 2필드 추가** — `target:str=""`(신뢰불가; 절대 raw `-s` 미사용), `target_kind:Literal["role","imsi","ip",""]=""`. 순수 data-carrying, 어떤 엣지도 read 금지(불변식① — `verify_routing` FORBIDDEN_KEYS로 강제).
2. **`select_policy::_candidates`** — `params["target"]=inc.target`(기존)에 `params["target_kind"]=_classify_target(inc.target)` 파생 추가(IP정규식→ip, 전부숫자→imsi, else→role; 순수 구문분류, 라이브해석 0).
3. **`rank_recovery`** — Intent 생성 시 `top.params`에서 `target`/`target_kind` 복사(라이브 해석 금지; 노드에 backend/netns 무). **이 3줄이 미해결 배선의 핵심.** risk/reversible 집계 불변.
4. **`response.py::_resolve_target` 시그니처 `(world)->(intent, world)`** + `plan()` 호출부 동반 수정. 셀렉터를 verified 맵의 **KEY로만** 해석: 신설 `_binding_verified(sel, world)`(`world.role_verified[sel]==True` OR `world.roles[*].verified AND sel in {role,container,ip}`) 미충족이면 `(None,"")` → `drop_argv` 미생성 → inert DRY. role/imsi는 KEY 조회, ip는 verified 매치 후에만 리터럴 src 채택. 하위호환: `target` 미설정 시 기존 `"target"` role 폴백(여전히 verified-게이트). imsi는 SMF layer-1 투영 미배선이라 **fail-closed inert**(안전측).
5. **`command_digest`(PS-9)에 `target`/`target_kind` 포함** → operator 승인이 (command, target) 스코프에 바인딩, 캡처 재사용으로 다른 타깃 DROP 승인 불가. (dispatch-해석 라이브 `src_ip` 바인딩은 escalate 경로가 src_ip 미해석이라 operator-go 유보.)
6. **검증** — `verify_routing`(엣지 AST가 target/target_kind 참조 0, FORBIDDEN_KEYS 확장) + `test_p4_response.py`: 셀렉터 전파+verified role 바인딩, 위조(operator IP·풀밖·미검증 role·미투영 imsi)→inert DRY(drop_argv None 강제), rank_recovery 셀렉터 복사, digest 스코핑.

**경계 4분리.** 선택(결정론 core `rank_recovery`) / verified 맵 적재(operator-go safe-exec `resolve.py`) / dispatch 조회(순수, subprocess 0 `response.py`) / 집행(safe-exec Backend, operator-go). core 노드 신규 subprocess 0(불변식②). 셀렉터는 비밀 아님 → State/JSONL 경유 PS-3 안전.

**불변식.** 엣지는 risk/reversible/chosen is None만 read·target 미참조(①). 신뢰불가 문자열이 verified 바인딩으로만 풀리는 KEY라 임의문자열은 미매치→inert(PS-7 self-DoS 봉쇄, ②). 실집행(verified IP DROP)은 stage-2·`Backend.allow_live` 모두 operator-go 유보. ①② PASS.

**잔여(operator-go 유보).** (1) 동적 IP 회전 — UE 재attach 시 stale ip_map DROP 오대상 가능; RoleBinding freshness 스탬프+effect_confirm 재관측 교차확인 후속. (2) provenance — 셀렉터 실은 incident는 PS-2 HMAC/seq 통과 evidence에서만 유래(tamper 배제). (3) `imsi->container` 투영은 recon/sense가 SMF layer-1을 world에 반영하는 배선 의존, 미배선 시 kind=imsi fail-closed. (4) `world.pid`(role→pid) vs `resolve.pidmap`(container→pid) 키규약 상이 → recon 병합에서 통일 필요, 미통일 시 조회실패로 inert(오집행 아님). (5) 라이브 IP DROP은 stage-2 tun scan + Backend.allow_live 모두 operator-go.

## P4-Q2 — operator-gate HMAC 키 부트스트랩: MDG 런타임 key=None이 정상 자세(issue-only), verify fail-closed=계약, env는 dev-only 강등, 실프로비저닝은 operator-go [PS-3/PS-5/PS-9/C-2]

**핵심 발견(결정을 지배하는 자기공격표면).** `OperatorGate.sign()`과 `verify()`가 **같은 `self._key`(대칭 HMAC)**를 쓴다 → **검증가능 주체 = 위조가능 주체**. operator-gate가 통제하려는 대상은 바로 MDG인데, MDG 프로세스에 키를 주입하면 컴프로마이즈된 MDG가 임의 명령에 자기승인 토큰을 `sign()`으로 발권 → 게이트 무력화(PS-9 명령바인딩 전면우회). 관측: 라이브 경로(escalate)는 `issue()`(key-free)만 호출, `sign()/verify()`는 out-of-band(operator-go). **∴ MDG는 애초에 키가 불필요.**

**결정(락).**
1. **MDG 런타임 `key=None`이 정상 자세**(퇴화모드 아님·issue-only). `issue()`(key-free 명령바인딩·digest)는 정상, `sign()/verify()`는 fail-closed. verify가 None에서 fail-closed인 것은 **"자율 런타임이 구조적으로 자기승인 불가"**를 보장하는 **의도된 계약**이며 버그 아님(불변식②·운영제약 정합). MDG 프로세스가 승인비밀 0개 보유 → 위조재료 자체 부재(PS-3 동형 구조적 보장).
2. **승인 검증은 MDG 밖 별도 신뢰도메인**(라이브 명령 발행지점=operator-go 유보 actuator/console)에서 소비. MDG=요청 발권자, 별도 도메인=검증자(SoD를 프로세스 경계로 강제).
3. **env `MDG_OPERATOR_GATE_KEY`는 DEV/replay 전용으로 강등** — env는 `docker inspect` Config.Env로 노출(PS-1 socket-proxy 표면 유출). 코드: env 폴백 시 **경고(`warnings.warn`, "DEV/replay only")** 방출. 프로덕션 키는 env가 아니라 operator/verifier 도메인의 **tmpfs 0400 시크릿**으로 주입(PS-5), MDG는 key-free 유지.
4. **키 생성·회전·영속은 MDG 밖 호스트 시크릿스토어/verifier**(MDG 발자국 순증 0). 대칭 유지 시 kid 버전화 회전은 verifier 소유(PS-5#2).
5. **검증** — `test_p4_response.py`: `test_operator_gate_none_is_fail_closed_normal_posture`(key=None에서 issue OK·sign ''·verify fail-closed), `test_operator_gate_env_is_dev_only_and_warns`(env 폴백 경고). 기존 sign/verify 라운드트립은 **primitive 단위테스트로만 유효**(배포 배선 미대표 — 배포는 key=None).

**대안 검토.** Ed25519 비대칭 승인(verify≠forge, 공개키 tmpfs 불요 → PS-5 비밀표면 축소)은 SoD를 대칭으로 성립불가한 근본해소책으로 **권장**하나, `sign/verify` 본문 교체 + `cryptography`/pynacl 락파일 해시핀 + 기존 HMAC 라운드트립 테스트 갱신을 수반 → 본 P4에서는 계약으로만 명시하고 실전환은 후속(operator-go 유보). MVP는 key=None(issue-only)로 GATE0/1 무블로킹.

**불변식.** 제어흐름·누수0과 직교(비밀위생). MDG key-free화는 PS-3 강화. env 강등으로 inspect 유출면 축소(PS-1). ①② PASS.

**잔여(operator-go 유보).** tmpfs 0400 시크릿 실마운트 + operator 개인키/verifier 프로세스 배치 + CA/CRL은 라이브 상태변경이라 코드+compose+dry까지만; 실 서명발행 경계와 함께 operator-go. HMAC 유지 시 verifier 컨테이너가 forge-capable 비밀 보유 → 그 격리(PS-1/PS-8)가 잔여 신뢰가정.

## P4-Q3 — PS-9 승인원장: 서명토큰(HMAC 출력) NOT-PERSIST, secret-free 승인 receipt + 소비-nonce 집합만 durable 영속(단회성 안티리플레이 크래시 넘김) [PS-9/PS-6/PS-3]

**결정(락).** 서명 승인 토큰(HMAC 출력) 자체는 durable 파일로 **영속하지 않는다(NOT-PERSIST)**. 대신 별도 durable operator-ledger에 **secret-free 승인 receipt + 소비-nonce 집합**을 영속하고, 단회성 안티리플레이를 이 durable nonce 집합으로 구동(PS-6 SeqWatermark와 동형).
- **왜 토큰 비영속:** 토큰=bearer 인가비밀(PS-3상 OperatorGate 메모리 전용). 영속=at-rest 캡처면 순증인데 리플레이 방어 이득 0(리플레이는 nonce 단회+expiry가 막지 토큰 보관이 막는 게 아님). 단회성이 크래시를 넘겨 실재하려면 **소비-nonce 집합이 durable**이어야 함 — 현행 `OperatorGate._seen_nonces`가 인메모리 set이라 재기동 시 리플레이 윈도우 재개방(PS-6가 seq에 지적한 결함과 동형). nonce(비밀 아님)만 영속하면 되지 토큰 영속 이유 아님.

**코드 계약.**
1. **신규 `mdg/ledger/operator_ledger.py`** — `OperatorApprovalReceipt{decision_id, command_digest, nonce, expiry, verdict:Literal[ISSUED,GRANTED,DENIED,EXPIRED,REPLAY_REJECTED], kid, issued_ts, consumed_ts|None}`, **token/hmac/key 필드 절대 부재**(구조적 secret-free). `OperatorLedger`: append-only JSONL, `os.fsync`, mode 0600(best-effort chmod), `record(...)`, `consumed_nonces()->set[str]`, `recover_on_boot()`(소비-nonce 재로드).
2. **`signer_shim.OperatorGate(ledger=None)`** — ledger 주입 시 `_seen_nonces`를 `ledger.recover_on_boot()`로 **시드**(순서 fence); `issue()`가 ISSUED receipt, `verify()` 성공 시 **GRANTED receipt(consumed_ts)를 fsync 기록 후 True 반환**(actuation 직후 크래시가 재승인 못 하도록 선기록); token은 검증에만·미기록; `sign()` 출력은 out-of-band 호출자에게만 반환(현행 유지). ledger=None(기본)이면 기존 인메모리 동작 바이트 불변.
3. **`intent_ledger.boot_recover(..., op_ledger=None)`** — `op_ledger.recover_on_boot()`를 `SeqWatermark.recover_on_boot()`와 나란히(안티리플레이 재로드 → sense/gate 개시 이전). summary에 `op_nonces` 카운트 편입.
4. **이원 원장**(둘 다 `mdg/ledger/`·0600·비공유·checkpointer 별개): `intent_ledger.jsonl`(actuation·G3 revert) / `operator_ledger.jsonl`(승인 receipt+소비-nonce 안티리플레이·PS-9 승인 정본, FRAMEWORK §2.2·PS-9#3).
5. **검증** — `test_p4_response.py`: `test_operator_ledger_receipt_is_secret_free`(token/hmac/key/secret 스캔 0), `test_operator_gate_nonce_survives_reboot_blocks_replay`(consume→재기동 재로드 후 동일(req,token) TTL 내라도 nonce consumed 거부, `verify_seq_persist` 동형).

**불변식.** OperatorGate는 safe_exec 상주, escalate(종단)+out-of-band에서만 평가, verdict=bool; `route_after_decide`는 risk/reversible/chosen만 read·operator 필드 미참조(①). 토큰/HMAC키는 State·JSONL·checkpointer·operator-ledger 어디에도 미기록(receipt는 필드 부재로 구조적 secret-free, ②). operator-ledger append는 ledger 소유자 owner-only 파일쓰기이지 그래프 노드 subprocess가 아니므로 노드 subprocess 0 경계 무관. 실 서명발행은 operator-go 유보. ①② PASS.

**잔여(operator-go 유보).** (1) 비부인성 축소 — 토큰 비영속이라 특정 승인이 유효 operator HMAC 지녔음을 사후 암호학 재증명 불가(receipt=owner-only 0600 원장 자기주장; 본 신뢰모델 수용). 포렌식 요건화 시 audit-only operator 키로 detached 서명(State 미경유) 후속. (2) 신규 at-rest `operator_ledger.jsonl`은 secret-free라 노출 시 command-binding 메타(digest/nonce/expiry/kid)뿐·인가력 0; 0600·비공유·카나리 스캔 강제로 회귀차단. operator-ledger 실기록/실승인은 코드+하네스+dry까지, 라이브 서명발행은 operator-go.

---

# 섹션 P3-R — 재검증 패널 종결 (2026-07-07, correlate SMF 귀속 · crit_floor band-cut 락)

> 2026-07-07 P3 재검증 패널(3검증자). 앞선 P3/P4 락의 잔여 2건을 종결: (R1) correlate SMF-IMSI 귀속 배선, (R2) crit_floor 71/45 시드값 정초. 패널의 노이즈("test") 검증자 답변은 배제하고 실질 합의만 반영. 2대 불변식·운영제약(testbed 상태변경 자동실행 금지) 우선. 코드+오프라인 검증까지만, 라이브 상태변경은 operator-go 유보.

## P3-R1 — correlate SMF-IMSI 귀속: out-of-graph SmfSessionCollector 소유 유지(MAINTAIN, 발명 없음), E2E 셀렉터 배선은 후속 파서 페이즈 [불변식②/P1-Q3/P4-1/P4-4/P4-Q1]

**결정(MAINTAIN·발명 없음).** `correlate` 노드는 `SmfSessionTable`을 **소유하지도 로그를 테일하지도 않는다**. IMSI↔동적IP 귀속은 그래프 밖 `SmfSessionCollector`(P4-1, `mdg/collector/smf_session.py` 그래프 밖 데몬)가 생산하고 correlate에는 오직 `evidence` 필드로만 도달하는 현행 배선을 **그대로 유지**한다. 노드로 테이블을 끌어오는 우회는 **불변식②(그래프 노드 subprocess/로그테일 0)·P1-Q3(SMF/MME 로그 collector 파서 페이즈 이월)·P4-1을 즉시 위반**하므로 금지.

**라이브 실측(E2E 절반 미도달 = 의도된 보수 자세, 설계변경 아님).** read-only 대조 확인:
- `smf_session.py`가 payload에 imsi/ip를 방출하나 `ingest.py::envelope_to_ev`(62-70)가 **미투영 드롭**(metric/value/band/domain/channel/confidence만 투영), `SensorEv`(state.py:34-47)에 귀속 필드 부재, `correlate.py:24`가 PFCP 단일신호 target을 `str(e.value)`(=발생 카운트)로 바인딩.
- ∴ 세션별 pivot 변별과 P4-4 귀속 조인은 아직 **비활성**이고, 세션삭제 incident의 pause/DROP 대상해석은 **fail-closed inert**(P4-Q1 kind=imsi fail-closed와 동일 앵커). 오집행 0 = 안전측, 자해 DoS 불가.

**후속 파서 페이즈가 닫을 지점(operator-go 유보·발명 금지).** (a) evidence payload의 파생 secret-free 귀속 셀렉터, (b) `ingest.py::envelope_to_ev` 명시 투영(현재 imsi/ip 드롭), (c) correlate가 그 셀렉터를 P4-4 조인키(`target_kind`)로 read, (d) SMF layer-1 world 투영 부재 시 `kind=imsi` fail-closed 유지. IMSI는 PII(P1-Q3 누수-0 리뷰 대상)이므로 귀속은 파생 secret-free 셀렉터로만 유입(PS-3/PS-7).

**코드 영향.** **없음(no-op).** 현행 배선이 이미 정합 — 유지가 정답.

**불변식.** correlate는 subprocess/로그테일 0(②). 귀속은 그래프 밖 collector 소유·evidence 경유만(불변식②/P4-1). 미배선 구간은 fail-closed inert(PS-7 자해 봉쇄). ①② PASS.

## P3-R2 — crit_floor 71/45 = band-cut 파생 락 상수로 재정초(값 변경 0, config-only), NOTE 라벨·distrust 입력계약 확정 [PP-3 residual 종결·P3-Q4 강화]

**결정.** 71/45를 "발명 시드"에서 **밴드컷 파생 락 상수**로 재정초하여 유지. **값 변경 0·config-only 가변 보존.** 핵심은 값이 아니라 (a) 근거를 impact_bands 컷에 고정하고 (b) floor를 실제 발동시키는 compute_trust distrust 입력 계약을 못박는 것.
1. **floor = impact_bands 컷 파생(발명 제거).** 상위 floor 71 ≡ `impact_bands.Red[0]`(71), 하위 floor 45 ∈ Yellow 내부[31,70]. 두 값은 자유상수가 아니라 이미 락된 밴드 경계의 함수 → "패널 미검증 시드" 반론이 새 실측 없이 소거(밴드컷 자체가 정본). `command`/`session_network` `[[71,71],[40,45]]`, `identity_access` `[[71,45]]`(integrity/recon→Yellow), `communication`/`mission` `[]` — **전부 유지**.
2. **계약 불변(코드 변경 0으로 값 교체 보존).** `scoring.py::crit_floor/overall_impact`는 table을 인자로 받는 순수·단조·weight독립 함수 유지(floor는 mission_weight 독립, `test_floor_fires_at_zero_weight` 락). 재튜닝 시 config 리터럴만 → 코드 diff 0.
3. **★ 하중부 — floor를 발동시키는 distrust 입력 시맨틱(진짜 레버).** command distrust는 **무인증 명령의 실 actuation 관측**(CONFIRMED_OFF 하 미서명 명령 SITL 도달, P3-Q3 latch 앵커)일 때에만 결정론적으로 **≥71**로 매핑. 단순 의심/signing=UNKNOWN은 40-70 구간(floor 45=mid-Yellow)에 머물러 보상평균 희석은 막되 Red 자동확정은 금지(PS-7 자해 auto-격리 방지). 서명검증 실패 드롭('⛔ 서명검증 실패 → SITL 차단 (누적 N)')은 **차단성공=방어정상** → distrust 가산 0(P3-Q2 활동메트릭, posture 아님; 드롭카운터 단독 floor 발동 금지).
4. **회귀 방지 라벨(적용됨).** `mission_profile.yaml`·`defaults.py`의 NOTE "invented design seeds pending … validation" → "band-cut 파생 락 상수, network-vuln-detector 패널 검증완료(P3-Q4)"로 갱신. `compute_trust.py` docstring에 distrust 입력 계약(무인증-actuation→≥71, 서명드롭→가산0, 소스 uav_signing collector는 D-2 미배선 operator-go) 명문화(behavior 변경 0·문서 계약).

**코드 영향(적용됨).**
- `mdg/config/mission_profile.yaml`·`mdg/config/defaults.py` — NOTE 라벨 갱신(값 변경 0).
- `mdg/core/nodes/compute_trust.py` — distrust 입력 계약 docstring 추가(behavior 불변).
- `mdg/tests/test_impact_floor.py` — `test_floors_are_band_cut_derived`(71≡Red_low·45∈Yellow·identity=45·band-cut identity), `test_partial_command_distrust_stays_yellow_floor_not_auto_red`([40,71)→45=Yellow·자해방지) 추가. 기존 stepwise/반례/weight=0 락 유지. **12/12 pass.**

**불변식.** crit_floor/overall_impact 순수·단조 산술(LLM 미참여·엣지는 impact.band만 read=①). 주입 허위신호는 impact 상향만·은폐 불가. floor는 weight 독립(config 변조 무력화 불가, PP-3). 서명드롭 비가산으로 방어성공 오탐 차단. 순수함수라 누수-0(②) 무관. ①② PASS.

**잔여(operator-go 유보).** (a) 구간 [40,71)은 floor 45(Yellow)에 머물러 '확정 미달' 심각 command 침해가 Yellow 하단에 남을 수 있음 — E8 저신뢰 tighten(+1 band)·P3-Q3 latch가 confirmed 전이를 Red로 승격하므로 의도된 보수성. (b) floor 71의 실효는 compute_trust '무인증 실 actuation→≥71' 매핑 정확도에 의존 → 소스(uav_signing collector)는 D-2 미배선. 그 매핑 실효력(GATE2 가역·E2E 무인증 명령 SITL 도달)은 라이브 상태변경 요 → 코드+dry/read-only까지만, 실집행 operator-go. 값 자체는 config hot-reload로 무코드 조정 가능(후속 uav 패널이 identity_access를 safety-relevant로 재분류 시 회귀비용 낮음).

---

# 섹션 P5 — Verifier 독립 진리술어 확정 (P5 검증자 패널 종결, 2026-07-07)

> 2026-07-07 P5 검증자 패널(3검증자). Verifier(grep0 별프로세스)의 진리술어 3건 — (Q1) SILENCE_TICKS·nominal 집합의 소유/배치, (Q2) cross-root ∧의 실현 평면, (Q3) gcs_proxy 생존 술어 — 를 종결. 패널의 노이즈("test") 답변은 배제하고 실질 합의만 반영. 2대 불변식·운영제약 우선. Verifier는 replay JSONL만 소비하는 순수 fold(core 미import·testbed 무·clock 무)라 세 결정 전부 verifier-side 오프라인 로직 — 라이브 상태변경 0, operator-go-safe. 검증: `test_p5_replay_viewer.py` 8/8, 전체 143 passed·1 skipped.

## P5-Q1 — SILENCE_TICKS=2·nominal 집합 {Continue, Continue+Monitoring} = verifier-OWNED FIXED 상수 유지(thresholds.yaml 이전 금지) [불변식②·PA-2 grep0]

**결정(락).** `SILENCE_TICKS=2`(연속 무heartbeat 틱 → TELEMETRY_SILENCE)와 nominal 결정집합 `{Continue, Continue+Monitoring}`(agent≠truth 발산 트리거)은 방어가능한 기본값이며 **doc-sourced 상수 아님**. 이 둘을 `verifier.py`의 verifier-소유 FIXED 상수로 **그대로 유지**하고 core 공유 `config/thresholds.yaml`로 **이전하지 않는다**. grep0 Verifier는 자신이 독립 검증하는 core와 상수 파일을 공유하면 안 됨(test isolation > DRY). 정본 doc에 canonical 값이 나타나면 그때만 재배치.

**코드 영향(적용됨).** `mdg/verifier/verifier.py` L37-42 — FIXED 상수 헤더 주석을 "verifier-OWNED·P5-Q1 lock·thresholds.yaml 미이전 근거" 명문화(값 변경 0). 로직 불변.

**불변식.** Verifier는 순수 fold(LLM 미참여·엣지 무관=①), core 미import 별프로세스(②·PA-2 grep0). 상수 위치가 grep0 경계를 강화. ①② PASS.

## P5-Q2 — cross-root '∧'는 PLANE 레벨에서 실현·현 증거 입도로 락(within-telemetry 14560∧14550 강화 금지) [불변식①·D-1·§P]

**결정(락).** anti-MITM 속성을 나르는 cross-root '∧'는 **평면 교차(cross-plane)**로 실현: [comm/drone root] air_telemetry_tap의 `Link_Heartbeat`(uav_ue lo:14550, verify_anchor `lo_14550_heartbeat_sys1`) **∧** [command root] gcs_proxy chokepoint 생존(14556). 이것이 현 증거 입도에서 최적 바인딩이며, **collector 분할 전까지 within-telemetry 14560∧14550 접속으로 강화 금지**.
1. **근거(현 증거서 미분리).** `AirTelemetryTap`은 단일 iface/port에 tcpdump 1회 → `source_id="air_telemetry_tap"`/`channel="plaintext_mavlink_tap"` 고정 dict **1개**만 방출. 14560과 lo:14550이 그 한 emit로 붕괴 → 동일 tamper-fate·동일 confidence. 지금 둘을 AND하면 phantom independence(anti-spoof 이득 0·false rigor). air_side가 `Link_Heartbeat` 방출 유일 collector라 현행 metric-only root 매치는 well-defined.
2. **진짜 독립은 cross-PLANE.** 네트워크 위조 downlink는 gcs_proxy를 role_verified로 유지하면서 드론 자신의 lo:14550 loopback heartbeat를 동시 위조 불가 → 이 두 root가 서로 다른 평면에 있어야만 성립하는 verifier의 anti-MITM 주장.
3. **텔레 root는 강한 vantage에 핀.** uav_ue lo:14550(드론 내부 loopback)은 네트워크 공격표면서 도달/위조 불가 — 네트워크측 14560(MITM replay 가능)보다 강함. collector 기본값(iface="lo", port=14550)이 이미 인코딩.
4. **FORWARD GUARD(락·미구현).** 향후 collector 분할이 14560 vs lo:14550에 **별도 source_id** 방출 시에만 `_telemetry()`를 두 heartbeat 명시 요구로 tighten하고 root 매치를 metric-only → **source_id-scoped**로 전환. 분리 증거 부재로 지금 선제 리팩터 금지(untested branch 추가).

**코드 영향(적용됨·문서화 only, 로직 0).** `verifier.py::_telemetry()` docstring에 단일-emit 붕괴·cross-plane ∧·forward guard 명문화. `verifier.py` 모듈 docstring 신호#1에 anti-spoof 비대칭(comm root가 anti-MITM 담지) 명기. `collector/air_side.py::AirTelemetryTap` docstring에 단일 tcpdump·1 emit·within-tap 미분리 명기(과대표현 시정).

**불변식.** Verifier grep0 순수 fold, ∧은 evidence 위 결정론 boolean(LLM 무·①), read-only 관측만(②). ①② PASS.

## P5-Q3 — gcs_proxy 생존 = role_verified(PRESENCE) 1차 술어 유지 + behaviorally_verified POSITIVE-only 상향(False 미강등) + 용어 'command-plane reachable/present' 시정 + cross-root anti-spoof 비대칭 문서화 [PS-9/PS-7·MEMORY 오판가드·불변식②]

**결정(락).** `verifier._gcs_proxy_alive`는 `role_verified['gcs_proxy']`(PRESENCE)를 **1차 chokepoint 생존 술어로 유지**하고 현 계층 그대로:
1. `role_verified['gcs_proxy']` True → alive True.
2. **POSITIVE-only 상향**(stale inspect 위에 raw-packet/behavioural override): untampered `air_command_tap` OR command-domain `plaintext_mavlink_tap` evidence → True; **신규** `behaviorally_verified['gcs_proxy']==True` → True(tap evidence와 **동일 tier**).
3. `role_verified` present-but-False AND positive evidence 없음 → False.
4. `role_verified`에 gcs_proxy 부재 → None(unknown).

**핵심 근거.** role_verified만이 NEGATIVE('chokepoint gone') verdict 공급 가능 — infra role은 `resolve.py`가 docker inspect `.State.Pid`서 `verified=(pid is not None)` 세팅 → `role_verified['gcs_proxy']==False`는 컨테이너 Pid 소멸=chokepoint down. behavioral 대안은 구조적 positive-only라 대체 불가: (i) `AirCommandTap`은 idle=0 packets를 정상 baseline으로 취급 → 건강-idle과 dead 양쪽서 침묵(dead 목격 불가); (ii) `command_entry_udp_14556` 앵커는 operator-go tap 하 boot all-False → False를 'dead'로 읽으면 SigningObs tri-state가 막은 UNKNOWN≠OFF 범주오류 재발. ∴ role_verified(present/known True/False)가 정직한 1차, tap/anchor evidence는 positive-only 상향, None은 진짜 키부재 예약.
- **behaviorally_verified 상향은 POSITIVE-only**: 그 False/부재는 **절대 downgrade로 미read**(operator-go run서 all-False → 오발 0). `.get` guard로 legacy JSONL(키 부재)은 role_verified/None 경로로 열화(WorldState 필드라 model_dump 포함되나 구버전 대비).
- **재정렬 금지·evidence-first 금지**: negative command evidence가 없어 True-단락 순서는 evidence-first와 관측 동치 → 재정렬 무이득, 단순 유지.

**용어 시정(적용됨).** Viewer/docstring 라벨을 'behaviorally verified survival'이 아니라 **'command-plane reachable/present'**로 표기. `_gcs_proxy_alive` = coarse 도달성/존재 confirm이지 behavioural command-plane health 아님.

**cross-root anti-spoof 비대칭(문서화·미패치).** command root는 negative/silence 검출기가 없어(AirCommandTap idle=0=정상), gcs_proxy 컨테이너를 present 유지하며 command plane을 위조하는 MITM/spoof는 `gcs_proxy_alive=True`로 읽혀 `CROSS_ROOT_INCONSISTENT`를 **트리거 안 함**. 실 anti-spoof 보증은 **TELEMETRY root의 드론측 lo:14550 cross-tap(D-1)**에 있음(공격자가 일관 유지 불가). command root는 coarse reachability confirm이지 독립 spoof 검출기 아님 → oversold 방지 위해 verifier.py 모듈 docstring·`_gcs_proxy_alive` docstring에 명기.

**코드 영향(적용됨).**
- `mdg/verifier/verifier.py::_gcs_proxy_alive` — behaviorally_verified positive-only 상향(`.get` guard) 추가, docstring에 4-tier 계층·POSITIVE-only·anti-spoof 비대칭 명문화. role_verified True 단락은 `rv.get("gcs_proxy")`로 정리(동치).
- `mdg/verifier/verifier.py` 모듈 docstring — 신호#3 'gcs_proxy presence(coarse·not a spoof detector)'로 시정, 신호#1에 anti-spoof 비대칭 명기.
- `mdg/tests/test_p5_replay_viewer.py::test_gcs_proxy_alive_p5q3_layering` — role_verified 1차·behaviorally_verified positive 상향(present-False/부재 role 공히)·False 미강등·legacy `.get` 열화·tap override 락(8/8).

**불변식.** verifier grep0 순수 fold(core 미import·LLM 무·엣지 무관=①), read-only 관측만(②). behaviorally_verified는 WorldState 필드(비밀 아님)라 PS-3 안전, State/JSONL 경유 OK. 라이브 상태변경 0. ①② PASS.

**잔여(operator-go 유보).** (a) cross-root anti-spoof 비대칭은 문서화만 — command root에 독립 spoof 검출기(negative/silence)를 붙이는 것은 새 collector vantage(14556 dead 목격) 요구·미배선. (b) behaviorally_verified['gcs_proxy'] 실값은 `targets/behavioral.apply_behavioral_verification`이 라이브 collector evidence서 세팅 → verify_anchor 실관측은 operator-go 유보(현 all-False라 상향 미발화, 안전측). (c) Q2 FORWARD GUARD: collector 분할(14560 vs lo:14550 별 source_id) 시 `_telemetry()` source_id-scoped tighten — 분리 증거 생길 때까지 미구현.

---

# 섹션 ④ E2E 캠페인 P6 (P6-1 ~ P6-3) — 5공격 로스터·위상 단일소스·보고서 crosswalk

> 3검증자 패널(P6) 합의를 코드로 확정. 노이즈 verdict(TEST/test)는 기각. 라이브 상태변경 0(DRY·operator-go), 2대 불변식 우선.

## P6-1 — 5공격 로스터·evidence band 계약 (LOCK, 코드 정합 실증)

**결정.** 정본에 5공격 로스터·band 목표값의 축자 명세가 없어 METRICS/CORRELATION_RULES/criticality_floor + §P/A/B 실측신호에서 도출한 값을 아래 계약으로 **락**한다(이미 코드에 박혀 있고 전 테스트 통과 → 재구현 아님, 계약 고정). 라이브 실측 재확인: A1 Red(71)·A2 Red(71,verified)·A3 Yellow(45)·A5 Green(4)·A6 Yellow(E8 저신뢰 1단 상향).

【로스터 5종 · verified/미검증 · band】
- A1 command_hijack_cr01 — CR01(PFCP삭제+무인증명령 시간창 상관). verified=False, **Red**. command distrust≥71 → criticality_floor 71 → Red.
- A2 pfcp_teardown — s5c_rx_deletesession 단조 카운터 diff. verified=**True(B-1)**, **Red**. session_network floor 71.
- A3 unauth_command(14556) — verified=False, **Yellow**. **실측 score=45 = floor 45**(weighted_mean<45로 floor가 드라이버). 단순 무인증/의심(signing=UNKNOWN)은 Red 자동확정 금지(P3-Q4). ⚠ 패널 소수의견 "driver=weighted mean 33"은 **실측 반증**(score 정확히 45=floor) → 기존 docstring 정정 불요.
- A5 mongo_dbaccess — verified=False, **Green**(탐지는 됨). identity_access w=10·conf 0.60 → weighted-mean 희석(MISSION_WEIGHTED_DILUTION 공시 한계, 미스 아님).
- A6 telemetry_silence — verified=**True(D-1)**, impact Green(communication floor 없음)이나 conf<0.5 E8 1단 상향으로 agent band=Yellow; 독립 Verifier는 SILENCE_TICKS로 TELEMETRY_SILENCE 판정 → **agent≠truth 발산**.

⇒ **verified detection = 정확히 2**(A2 PFCP/B-1, A6 telemetry/D-1), 미검증 3. `honest.banner` verified_detections=2·total_attacks=5와 정합.

**band 결정 원리(2계층).** (1) 신호 evidence band = METRICS 임계표 → E7 SEVERITY_FACTOR·BAND_MAP dev로 도메인 distrust 기여. (2) mission impact band(Green0-30/Yellow31-70/Red71-100) = `overall_impact = max(weighted_mean, criticality_floor)`, 이후 E8 저신뢰(conf<0.5) 1단 보수 상향. crit_floor가 두 계층 하중지지 브리지: command·session_network=[[71,71],[40,45]], identity_access=[[71,45]]. 71≡Red 하한컷, 45∈Yellow[31,70] — 밴드컷 파생 LOCK 상수(IMPACT_BANDS 이동 시 `test_floors_are_band_cut_derived` loud fail).

**P3-Q4 정합 핵심.** "PFCP삭제+무인증→Red vs 단순의심→Yellow"는 correlation으로 구현: 무인증명령이 PFCP 세션삭제와 시간창 상관(CR01)으로 확정 actuation일 때만 command distrust≥71→Red(A1). 단일신호(A3 명령만)는 floor 45→Yellow. Red는 "safety-critical 도메인 확정 침해"에만 예약, 의심은 Yellow 고정(주입 doubt로 아군 self-DoS 방지, PS-7).

**verified/미검증 분류 기준(발명의 핵심).** verified_detection = "라이브 read-only로 지상진실이 실측된 관측"만: (1) uav_ue lo:14550 평문 HEARTBEAT 실캡처(D-1), (2) SMF s5c_rx_deletesession 단조 카운터 diff(B-1). 나머지 3은 관측점 실재하나 탐지정확성을 unit-test로 못 닫거나(14556 idle baseline=0, B-3)·서명성공 per-packet 로그 부재(A-2)로 지상진실 미확보 → 미검증. 이 분류는 "탐지관측 ≠ 대응효력"과 직교(honest.py 분리): 대응효력은 5공격 중 3공격 미측정(C-1, nsenter DROP/pause 효력 GATE2 operator-go).

**구현 계약(이미 적용·본 P6서 재검증).**
- `mdg/campaign/e2e.py::ATTACKS`(5 시나리오·verified 플래그), `mdg/config/defaults.py`(METRICS·criticality_floor·mission_weight), `mdg/core/scoring.py::overall_impact/crit_floor`(순수함수 수치 결정론).
- `mdg/campaign/honest.py`(MISSION_WEIGHTED_DILUTION·UNVERIFIED_RESPONSE_EFFICACY 공시, banner verified=2).
- 검증: `tests/test_impact_floor.py`(밴드컷 파생·zero-weight·monotone 12/12) + `tests/test_p6_campaign.py`(A1=Red·A2=Red+verified·verified_count==2·A5 Green·A6 divergence 8/8). 실측: A3 score=45=floor(패널 소수의견 반증).

**불변식.** band/floor 전부 수치 결정론(scoring 순수함수), LLM(orient/decide) 상향만·엣지 미참여, 로스터 재생 Backend(allow_live=False) DRY → 라이브 상태변경 0. ①② PASS.

**잔여(operator-go 유보).** (a) verified 2건도 **대응효력은 별개 미검증**(C-1); "차단됨" 주장은 라이브 가역 실측 전까지 DRY 표기만. (b) A5·A6 Green은 mission_weight(config·operator 튜닝가능) 종속 — 회귀 시 floor 재도출(`test_floors_are_band_cut_derived`가 밴드컷 이동 loud fail). (c) V4(서명키 위조)는 구조적 탐지불가(A-2)로 독립 탐지항 없이 봉쇄(containment)만 — 로스터가 위조 명령을 개별 탐지한다고 오독 금지.

---

## P6-2 — LangGraph 위상 단일소스화 (PA-9 확장) + 3중 정적가드 + 동적 패리티

**문제 확정(현 코드 실측).** 선형 노드 스파인·DI 바인딩이 2곳(core/graph.py·campaign/e2e._TickExecutor)에 독립 하드코딩(라우팅은 edges.py 공유라 안전하나 선형순서·바인딩은 손유지). **발산 실증**: graph.py는 `partial(escalate, ledger, clock)`로 gate 미바인딩인데 `_TickExecutor`는 `escalate(…, gate=d.get("gate"))` 호출(둘 다 None이라 오늘은 무해했으나 무가드 발산면). langgraph 미설치(D-2)라 CI는 `_TickExecutor`만 돌고 `build_graph` 컴파일 경로는 로컬 미실행 → 검증되는 코드 ≠ 배포되는 코드.

**결정(계약, 구속).**
1. **선형 스파인 + DI 바인딩 단일소스화.** 신규 `mdg/core/topology.py`(순수 데이터: NODE_ROSTER·ENTRY·LINEAR_EDGES·COND_EDGES·BIND·END·derive_edges·kwargs_for)를 두고 `build_graph()`와 `_TickExecutor.run_tick`이 **동일 상수를 소비**. `_TickExecutor`는 스펙 인터프리터로 전환(ENTRY→LINEAR|COND branch→END walk). 이로써 core측 두 사본 구성상 발산 불가. escalate `gate=`를 `BIND["escalate"]`에 포함 → **DI 바인딩 발산 폐쇄**.
2. **topology.py는 langgraph/pydantic/노드함수 미import(순수 데이터).** 브랜치·노드 함수는 이름(문자열)으로 참조, 소비자(graph.py·e2e.py)가 자기 registry(`_BRANCH`)·`nodes.NODES`로 해소. → 의존성 경량 `verify/` 스크립트가 topology를 직접 import 가능.
3. **Verifier 격리 유지(PA-2 > DRY).** `verifier.py::_NODE_ORDER`는 자기 사본 유지·**core/topology 미import**. 발산은 '공유 import'가 아니라 `verify_graph.py`의 **정적 텍스트/AST 동치검사**로 잡음(장악된 core가 독립 검증자를 침묵 못 시킴).
4. **3중 정적가드(오늘 실행, langgraph 불요).** `verify/verify_graph.py` 확장: (a) node_files==topology.NODE_ROSTER(11), (b) derive_edges의 PA-1 shape(START→sense·act→effect_confirm→END·escalate→END·in-graph cycle 0), (c) graph.py·e2e.py가 topology 소비(하드코딩 add_node 리터럴 0), (d) `BIND["escalate"]`에 gate 포함, (e) `verifier._NODE_ORDER`(AST 추출) == roster + verifier가 core 미import(AST import 스캔), (f) topology.END==edges.END. `verify/verify_models.py`는 slot map을 `topology.BIND`서 도출(양 실행경로 동시검사).
5. **동적 패리티 가드(후속, langgraph 존재 시).** `tests/test_graph_parity.py`: `find_spec("langgraph")` 게이트 — 부재 시 skip(로컬 미차단), 존재 시 `build_graph({})` 컴파일 그래프 edges == `topology.derive_edges()` assert(START/END 센티널 정규화). 구조 절반(topology 자기정합·verifier._NODE_ORDER 일치)은 langgraph 없이 항상 검사.

**구현 계약(적용됨).**
- 신규 `mdg/core/topology.py` — 순수 데이터 스펙 + `derive_edges()`·`kwargs_for(node, deps)`.
- `mdg/core/graph.py::build_graph` — topology 루프 소비(add_node/add_edge/add_conditional_edges), `partial(NODES[name], **topology.kwargs_for(name,d))`, escalate gate 바인딩 포함.
- `mdg/campaign/e2e.py::_TickExecutor` — 스펙 인터프리터(topology walk), `_call`이 `topology.kwargs_for` 바인딩. 개별 노드 import→`nodes.NODES`.
- `mdg/verify/verify_graph.py` — 28체크(위 3중 가드), `mdg/verify/verify_models.py` — slot map topology.BIND 도출.
- 검증: verify_graph 28 PASS·verify_models 18 PASS·verify_grep0 371 PASS·verify_routing 19 PASS·test_p6_campaign 8/8(run.jsonl **바이트동일 유지**)·test_graph_parity(구조 always PASS·langgraph 절 skip).

**근거.** DRY의 유혹(Verifier가 core 스펙 import)은 거부 — grep0/trust-root 붕괴(장악 core 자기검증). 발산은 텍스트 동치검사로 잡음. topology를 순수 데이터로 분리해 경량 verify가 소비하면서도 core 두 사본을 구성상 일원화. escalate gate를 BIND에 넣어 실증된 바인딩 발산 폐쇄. langgraph 절은 skip으로 로컬 미차단·프로덕션 이미지선 필수 게이트.

**불변식.** 인터프리터는 다음 노드를 오직 COND_EDGES branch fn(edges.route_*·수치/불린) 또는 static LINEAR_EDGES로만 선택(orient_note/decide_note 미read=①). 노드가 유일 부작용 소유·actuation Backend.run(DRY)·인터프리터 subprocess 0(②). topology는 LLM필드·비밀·subprocess 무. ①② PASS.

**잔여(operator-go 유보).** (a) 컴파일 그래프 **런타임 채널 의미**(operator.add 리듀서·checkpointer readback·conditional dispatch)는 정적 가드론 미실증 — langgraph 존재 이미지의 `test_graph_parity` 동적 절이 유일 실증, D-2 로컬선 skip이라 **바이트 패리티는 topology 존재 이미지 전까지 정적(구조)만**. graph.py 위상변경은 그 이미지 테스트 통과 전까지 operator-go 유보. (b) 신규 노드가 새 dep 필요 시 topology.BIND에 추가 안 하면 양 경로가 조용히 default 수신 — verify_graph가 스펙 소비는 강제하나 dep 완전성 AST 체크는 후속.

---

## P6-3 — 보고서 6장 구조 = 자체 완결형 E2E 증거 보고서 + report_role crosswalk

**결정.** 6장 구조(개요·범위/공격재생/탐지/대응/독립검증/정직성·한계)를 **그대로 유지**하되, 공동 경쟁 보고서의 '6장'이 아니라 **자체 완결형 E2E 캠페인 증거 보고서(6장)**로 명명. `to_report`에 `report_role` crosswalk 필드 추가 → report-generator가 이 산출물을 공동 보고서의 '독립검증/E2E 증거' 절(§7)로 folds. 章 재구조화 금지(test_p6_campaign·RUNBOOK DRY·honest.py 章매핑 파손).

**구현 계약(적용됨).**
- `mdg/campaign/artifacts.py::_REPORT_ROLE` + `to_report` 반환에 `report_role`(artifact=e2e_campaign_evidence_report·standalone·chapters=6·folds_into·chapter_collision_note·chapter_titles). report 타이틀 '자체 완결형 6장'으로 시정.
- `mdg/tests/test_p6_campaign.py::test_report_six_chapters_and_honesty` — report_role.standalone/chapters/artifact/folds_into assert 추가(8/8 PASS).
- honest.py 章 매핑(report_chapter∈{4,5,6})·banner(verified=2·live_state_changes=0) 불변 유지.

**근거.** 탐지/대응/독립검증 분리는 라이브 실측(verified 2/5)에 정직한 유일 레이아웃. 6장 명칭 충돌은 crosswalk 필드로 해소(章 재구조화 아님). report-generator는 report_role.folds_into로 접어 넣고 정직성 배너 보존.

**불변식.** artifacts.py는 core·langgraph 미import(보고 측, run.jsonl 소비). report_role은 노드명/章명 데이터라 신규 비밀표면 0(PS-3 무영향). 라이브 상태변경 0. ①② PASS.

**잔여.** report-generator가 6장을 top-level로 승격하지 말고 report_role crosswalk 경유 소비를 요구 — 이는 report-generator 에이전트 계약(본 코드 밖).
