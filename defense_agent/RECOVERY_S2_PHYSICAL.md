# S2 물리 복구 — 방어 agent 변경사항 (As-Built)

> S2(비행 30m 복귀)의 legality·관측·운영자선택·gcs_c2 서명발행 위임 구현 + 라이브 검증.
> 다단계 워크플로 + AI개발자·UAV·4G 3전문가 검증. commit 50ae8be(빌드) → 2b16114(실작동 트리거 갱신).

## 배경 (앞선 단계)
- S2 legality/관측은 이전에 완성(commit 35e247b): SignLogCollector가 uav_proxy 서명 드롭로그를 관측 → sense.py MONOTONIC 래치로 `world.signing = CONFIRMED_ON` → `send_signed_mode`가 legal_actions 진입. 라이브로 signing unknown→confirmed_on 확인.
- 남은 두 장벽: (1) 자율 랭킹이 항상 가역 봉쇄(backdoor_pause)를 선호해 send_signed_mode 미선택, (2) emit_signed가 실제 발행 미구현(gcs_c2 위임 RESERVED).

## 변경 파일 (defense agent)

### 운영자 선택 경로 (①)
- `mdg/live_autorun.py`: `parse_operator_pick(env MDG_OPERATOR_PICK)` 추가 → deps/state0 로 전달. 미설정 시 자율 랭킹 유지(fail-safe).
- `mdg/core/nodes/rank_recovery.py`: `state['operator_pick']`이 legal_actions의 recovery_type/tool_id와 일치하면 그 Action을 top으로 승격(authority='operator-select', command_digest 바인딩). 결정론(env→state, LLM 불가시).
- `mdg/core/nodes/act.py`: operator-select 프로비넌스 보존(operator_auto_confirmed AND authority='operator-select' 둘 다 원장 기록 — UAV 검증자 MAJOR 반영, 감사에서 "사람이 선택 + 샌드박스 자동집행" 모두 표시).
- `mdg/core/nodes/escalate.py`·`state.py`: authority 보존 + OperatorGate ISSUED 영수증.

### gcs_c2 서명발행 위임 (실작동 트리거 방식)
- `mdg/safe_exec/signer_shim.py`: `emit_signed` live 경로 → 단일 Backend spawn `docker exec gcs_c2 sh -c 'printf "%s %s" "$1" "$2" > /tmp/mdg_correct' sh <mode> <alt>`. **MDG는 서명키를 절대 안 만짐**(KEY-FREE, verify_signer_no_keyopen). dry(allow_live=False)는 digest-only 무변경.
- `testbed/gcs/gcs.py`: `_poll_recovery_trigger` 추가 — gcs.py(SITL 서명링크 유일 소유자)가 매 루프 `/tmp/mdg_correct`를 폴링 → 자기 키로 **signed set_mode(GUIDED)+arm+takeoff(alt)** 발행 후 consume. (독립 sender는 gcs.py가 14550 점유해 미작동이라 폐기 → 트리거 방식으로 전환.)
- `mdg/safe_exec/assets/gcs_signed_correct.py`: SUPERSEDED 표기(참고용). `assets/gcs_recovery_trigger.README`: 표준 트리거 폴링 블록 버전관리.

### 관측/뷰어
- `mdg/safe_exec/observer.py`: effect_confirm signed_* 경로 — rel_alt 30m±tol 회복 & mode!=LAND 이면 confirmed.
- `mdg/viewer/app.py`: 복구 타임라인이 send_signed_mode 이벤트(탐지→대응(operator-select)→집행→확인) + 고도 렌더.

## 라이브 검증 결과 (정직)

### ✅ 서명 물리복구 메커니즘 — 라이브 증명
- 미서명 MAVLink 주입 → uav_proxy 드롭로그 → SignLogCollector 관측 → `signing:confirmed_on` 래치 확인.
- MDG 트리거(`/tmp/mdg_correct` 기록) → gcs.py가 **자기 서명 C2 링크로 GUIDED+ARM+TAKEOFF 발행** → uav_proxy 서명검증 통과 → **드론 실제 `armed=True, mode=GUIDED` 전환** 확인. 즉 "방어가 서명된 비행명령으로 제어권 회수"가 작동.

### ⚠️ 클린 30m 호버 — 미달 (SITL 비행역학 한계, 보안 범위 밖)
- 공격의 강제착륙 + 반복 이륙 테스트로 SITL **EKF 고도추정 발산**(alt~5500m, climb -291m/s = 물리 불가). 깔끔한 30m 정지비행 미달.
- pristine 30m엔 uav_sitl EKF 리셋(컨테이너 재시작) + 단일 클린 복구가 필요 — 사용자 결정으로 "메커니즘 증명 수용, 코드만 갱신"으로 마무리.

### 안전/불변식
- pytest 268/2skip, verify 게이트 전부 PASS, 캠페인 `live_executions=0`(operator_pick 미설정·operator_auto OFF 경로 무변경), KEY-FREE grep 0, 단일 Backend spawn(leak-0), 결정론 라우팅(①) 유지.
- send_signed_mode는 HIGH·비가역 → operator_auto 하에서만 자동집행. 자율 랭킹은 여전히 가역 봉쇄 우선(안전보수적); 운영자 명시선택(MDG_OPERATOR_PICK) 시에만 서명복구 발동.

## 감독관 실행 (S2 물리복구)
```bash
# .env: MDG_ALLOW_LIVE=1 MDG_OPERATOR_AUTO=1 MDG_OPERATOR_PICK=signed_guided
# 서버 defense_agent: sudo -E bash dah.sh monitor  (24/7 자율집행 감시)
# 공격 주입 → operator-pick으로 send_signed_mode 집행 → gcs.py 트리거 소비 → 서명 GUIDED+arm+takeoff
```
> 주의: gcs.py 트리거 폴링 블록이 배포 gcs.py에 포함돼야 함(커밋 소스 testbed/gcs/gcs.py 반영됨). SITL/샌드박스 전용 — 실기체 아님.
