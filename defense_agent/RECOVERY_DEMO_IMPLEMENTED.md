# 자율 복구 시각화 — 구현 완료 보고 (As-Built)

> 계획서 `RECOVERY_DEMO_PLAN.md` 의 Phase 0/1/2/3/4/5/7 을 구현. Phase 6(테스트베드 서명강제)은
> uav_proxy 운영 단계라 코드에서 분리(하단 §운영 절차). 다단계 오케스트레이션 + 3전문가 검증으로 구현·수정.

## 검증 결과 (지상검증)
- **pytest: 236 passed / 2 skipped** (기준선 194 → 신규 테스트 +42)
- **무결성 게이트: 10/10 PASS** (routing·graph·leak0·no_fw_subproc·grep0·keys·tools·models·d11 + aggregate)
- **오프라인 캠페인 안전성**: `MDG_ALLOW_LIVE=1 MDG_OPERATOR_AUTO=1` 에서도 `live_executions=0`,
  6/6 탐지 유지 — operator_auto 가 결정론 증거 경로로 누출되지 않음(campaign 은 Backend(allow_live=False)+operator_auto 미주입).
- **뷰어 JS**: `node --check` 통과.
- **불변식**: ①(결정론 라우팅, operator_auto=env bool·LLM 불가시) ②(leak-0, observer read-only·단일 Backend._spawn) 보존.

## 페이즈별 변경 (파일 · 동작)

### Phase 0 — 기본값 자율화
- `.env.example`: `MDG_ALLOW_LIVE=1`, `MDG_OPERATOR_AUTO=1`(신규) — 샌드박스/SITL 데모 전용 주석.
- `mdg/live_autorun.py`: `parse_operator_auto(env)`(truthy 파서, 기본 False) 추가, `run(operator_auto=...)` → `deps['operator_auto']`.
- `mdg/core/graph.py`·`topology.py`: operator_auto 를 단일 토폴로지 소스로 정규화·전달(PA-9 drift 방지).
- `dah.sh`: `_load_env` 가 MDG_OPERATOR_AUTO export, monitor 배너에 상태 노출.

### Phase 1 — 운영자 자동승인 (OPER 집행)
- `mdg/core/gate.py`: `gate_for(..., operator_auto=False)`. operator_auto=True면 **등록된** OPER → `auto=True`(tier2=`AUTO_BY_OPERATOR`), `flight`/`registry_tier` 필드 보존(투명성). **ghost/미등록 id는 절대 확대 안 함**(closed-registry fail-closed 절대).
- `mdg/core/edges.py`: `(auto or operator_auto)`면 act 라우팅, `state['operator_auto_confirmed']=True`.
- `mdg/core/nodes/act.py`·`state.py`: ledger 에 `operator_auto_confirmed`, `authority='sandbox-auto'` 기록.

### Phase 2 — provenance/debounce 데모 완화
- `mdg/core/nodes/rank_recovery.py`: operator_auto(데모) 하에서만 provenance 게이트를 'record-then-pass'로 완화(`provenance_relaxed` 명시), debounce 는 config 키로 축소.
- `mdg/config/thresholds.yaml`·`loader.py`·`defaults.py`: `demo_mode`(provenance_relaxed, debounce_ticks) 키.
- 프로덕션 기본(operator_auto off)은 엄격 유지.

### Phase 3 — rank_recovery 선택 (보이는 복구)
- `mdg/config/recovery_priors.yaml`(값)·`mdg/core/nodes/select_policy.py`: S1 `backdoor_pause`(docker_pause) 집행 가능 유지, S2 `signed_guided` 는 signing 확정 시 후보 진입. 코어 하드코딩-0·결정론 유지.

### Phase 4 — effect_confirm 관측 배선 (복구 완료 신호)
- 신규 `mdg/safe_exec/observer.py`: `make_effect_observer` — `backdoor_pause`→docker Paused, `backdoor_drop`→netns ss 5762 연결 소멸, `signed_*`→telemetry rel_alt 30m±tol & mode!=LAND. **전부 read-only**.
- `mdg/live_autorun.py`: `deps['observe']=make_effect_observer(...)`.
- `mdg/core/nodes/effect_confirm.py`·`safe_exec/response.py`: confirmed 시 `applied[rule].confirmed` + before/after delta.

### Phase 5 — 비행상태 관측 (mode/altitude)
- `mdg/collector/air_side.py`·`worldstate.py`: 14560 텔레메트리에서 `rel_alt`, `flight_mode` 메트릭 방출(effect_confirm·뷰어 그래프 y축).

### Phase 7 — 뷰어 복구 타임라인 + 비행상태
- `mdg/viewer/app.py`: `load_panels` 에 복구 lifecycle(탐지→대응→집행→확인→회복) + 비행상태 시계열 산출.
  `_recovery_band`(엔진 impact_band 우선, view_band 로그전용과 분리), 좌측 복구 카드 + 고도 스파크라인(30m 기준).
  기존 상시패널/view_band/3초 자동갱신·펼침 상태 보존.

## 데모 실행 (감독관)
```bash
# 서버 defense_agent 에서 (기본값이 이미 1)
MDG_ALLOW_LIVE=1 MDG_OPERATOR_AUTO=1 sudo -E bash dah.sh monitor      # 24/7 자율 집행 감시
bash dah.sh viewer live_out/monitor/run.jsonl                        # 복구 타임라인 뷰어
# 공격(별도 터미널): attack_agent 에서 5762 LAND 주입 → 탐지→docker_pause 자동집행→효과확인→회복
```
- **S1(컨테이너 격리 복구)**: 위 그대로 → 뷰어 복구 카드가 [탐지→대응→집행(auto)→확인→회복] 표시.
- **S2(비행 30m 복귀)**: 아래 §Phase 6 서명강제 선행 필요.

## §Phase 6 (미포함, 운영 절차) — 업링크 서명 강제
S2(비행 복귀) 시각화에는 테스트베드 `uav_proxy` 가 미서명 MAVLink 를 실제 드롭하고 드롭로그를 남겨
`tail_signing_drops`→`world.signing=CONFIRMED_ON` 이 되어야 `send_signed_mode` 가 legal 이 된다.
이는 테스트베드 재구성(업링크 잠깐 끊김)이 필요해 코드 워크플로에서 분리. 미적용 시 S1(격리 복구)만 시연됨.

## 안전 포스처 / 잔여
- `MDG_OPERATOR_AUTO=1` 기본 = 비행·비가역 OPER 도 자동집행 → **SITL 전용·가역·원장기록** 전제(실기체 0).
- 오프라인 캠페인 증거는 operator_auto 무관하게 DRY(`live_executions=0`) — 결정론 증거 무손상.
- provenance 완화·라이브 actuator 완전 멱등성 등은 데모 스코프로 문서화된 의도적 스킵(결함 아님).
- 프로덕션 배포 시 `.env` 를 0/0 으로 두면 기존 안전 포스처(DRY·OPER=사람)로 복귀.
