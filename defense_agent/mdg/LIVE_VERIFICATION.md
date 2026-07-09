# MDG 방어 에이전트 — 라이브 배포·검증 기록 (LIVE_VERIFICATION)

- 프로젝트: DAH 2026 방어 AI 에이전트(MDG) · 인가된 격리 샌드박스 보안평가
- 일시: 2026-07-07
- 대상 testbed: `<TESTBED-IP>` (AWS 호스트 `<aws-host>`, dahv2 스택)
- 배포 위치: 서버 `~/mdg` (venv `~/mdg_venv`, Python 3.12.3)
- 범위: **배포 + read-only 라이브 검증(V0~V3) + GATE2 가역 집행 실증(V4) + 자율구동 실증·경합버그 수정(V5) 완료.** V4는 operator 명시 승인 하(auto mode 해제) 단일 가역 nsenter DROP→검증→revert로 집행, testbed 최종 무변경. V5는 자율구동(idle+A5 자율탐지) 실증 중 발견한 air-tap 세마포어 경합 버그를 수정(read-only 관측/집행 세마포어 분리 + air-tap 타임아웃)하고 S2~S5 실집행 계획을 기록.

> 운영 제약(준수): 상태변경(nsenter DROP·docker pause·서명·컨테이너 stop·설정수정) **자동실행 0**.
> V0~V3은 read-only. **V4만 operator 명시 승인 하 가역 예외**로 집행(단일 DROP, 즉시 revert, 흔적 0). docker pause·서명명령·컨테이너 stop은 미실행.

---

## 0. 배포 (Stage 1~2) — testbed 무변경

| 항목 | 결과 |
|---|---|
| 코드 전송 | tar+scp → `~/mdg` 107개 .py + Dockerfile/requirements/DESIGN_DECISIONS/BUILD_REPORT |
| 의존성 | venv + `pip install -r requirements.txt` |
| **의존성 충돌 해소** | `litellm 1.55.0` ↔ `httpx 0.28.1` 충돌 → **httpx 0.27.2**로 완화(로컬 requirements.txt 동기화 반영) |
| **read_only 배선 패치** | `Backend.run`이 `ExecRequest.read_only`를 참조하도록 수정 — 관측(read_only=True)은 `allow_live` 없이 실행, 집행(read_only=False)은 DRY 유지(RUNBOOK §2 정합). 회귀 무영향(154 passed). |

---

## 1. GATE0 (실서버, langgraph 포함) — ✅ PASS

로컬 D-2(langgraph 미설치) 갭이 실서버에서 폐쇄됨:

| verify | 결과 |
|---|---|
| verify_graph | **PASS — 28 checks** (로컬 13 → langgraph 컴파일 검증 확장) |
| verify_tools | PASS — 178 |
| verify_routing | PASS — 19 (불변식① 결정론 라우팅) |
| verify_grep0 | PASS — 371 |
| verify_keys | PASS — 401 |
| verify_no_fw_subproc | PASS — 119 (불변식② 노드 subprocess 0) |
| **pytest** | **154 passed · 1 skipped** |

## 2. DRY 캠페인 (실서버) — ✅ 상태변경 0

`python -m mdg.campaign.e2e` → `report.json`:
- `live_state_changes: 0` · `live_executions: 0`
- 5공격 탐지 5/5 (독립검증 2: A2 PFCP·A6 telemetry), agent≠truth 발산 2(A6, D-1)
- 결과: A1 Red · A2 Red(verified) · A3 Yellow · A5 Green(mission-weighted 희석 실증) · A6 Yellow(verified)

---

## 3. V1 — 관측원 정합 (read-only) — ✅ 5/5 라이브

배포된 collector 5종의 실 데이터소스를 라이브 확인(파서 기준):

| 관측원 | 라이브 근거 |
|---|---|
| AirCommandTap `gcs_proxy:14556` | `UNCONN 0.0.0.0:14556`(python3 pid=8) — 명령진입점 live |
| AirTelemetryTap `uav_ue lo:14550` | 평문 HB 3패킷(len 75/21/75) — D-1 교차탭 |
| NetworkMetric `SMF:9090` | `s5c_rx_deletesession 9`·`createsession 10` — 단조 트립신호 |
| SmfSession `SMF log` | `UE IMSI[001010000000001] IPv4[10.45.0.4]` — IMSI↔동적IP(P4-1) |
| MongoLog `docker logs epc_mongo` | `id:22943 remote:10.44.0.31` — RAN측 DB접속 신호 |

## 4. V2 — collector 라이브 관측 (read-only, 실 Evidence 방출) — ✅

`Backend(allow_live=False, mode='local')`로 실 collector `collect()` 실행:

| collector | 방출 Evidence (라이브) |
|---|---|
| **Network** | :9090 httpx 실폴링, baseline 카운터 포착(`smf:s5c_rx_deletesession=9.0`, `upf:n3_indatapkt` 등). diff 기반이라 idle→0 payload(오탐 0, 정상) |
| **Mongo** | **201 payloads** — `{"metric":"DB_Access","band":"warning","domain":"identity_access","remote":"10.44.0.3..."}` (RAN CIDR 실탐지) |
| **SMF** | `PFCP_Delete_Attempt`(session_network) + ★**IMSI↔IP 세션테이블 라이브 구축**: `imsi_to_ip={'001010000000001':'10.45.0.4'}`, `ip_to_imsi={'10.45.0.4':'001010000000001'}` — P4-1 실작동(귀속·pause 대상해석·correlation 조인 동시 해소) |
| **air-tap 경로** | 호스트 `sudo nsenter --target <uav_ue pid> --net -- tcpdump -i lo` → 14550 HB 실캡처. 호스트 nsenter/tcpdump/ss 존재·passwordless sudo 확인 |

## 5. V3 — GATE1 누수-0 실측 (read-only) — ✅ PASS

관측 버스트(3 collector ×3회 + sudo nsenter tcpdump ×3) 전후 비교:

| 지표 | BEFORE | AFTER |
|---|---|---|
| docker 컨테이너 수 | 20 | **20 (diff 0)** |
| 잔존 tcpdump/nsenter proc | 0 (실측; count 2는 스냅샷 명령 자체 매칭) | **0** |

→ 관측 subprocess는 timeout/count로 자기종료 + R1~R6 reap. **누수 0·사이드카 미생성**(nsenter 방식).

---

## 게이트 상태 (라이브 반영)

| 게이트 | 상태 | 근거 |
|---|---|---|
| **GATE0** | ✅ PASS (실서버) | verify 6종 + pytest 154 + langgraph 컴파일 |
| **GATE1** | ✅ **누수-0 실측 PASS (관측 경로)** | V3 버스트 diff 0. ※ 집행 경로 누수-0은 V4(allow_live) 시 재확인 |
| **GATE2** | ✅ 오프라인 GREEN + 관측층 라이브 실증 + **집행 메커니즘·가역성 라이브 실증(V4)** / 실 공격 트래픽 차단 effect만 미실증 | V1~V3 관측·탐지 + V4 nsenter DROP 설치→UAV무영향→revert→복원(E3/E4 폐쇄). live-attack effect는 활성 공격 재구성 필요 |

## 6. V4 — GATE2 가역 집행 실증 (operator 승인, MDG `Backend(allow_live=True)`) — ✅ PASS

**Preflight(read-only):** UAV(IMSI001) tun=10.45.0.2(pid 14778, 보호) · attacker(IMSI002) tun=10.45.0.11(pid 2160, 차단대상) — distinct. ⚠ attacker→UAV 베이스라인 도달성 **100% loss**(현재 활성 측면이동 없음, 라우트 미설정) → DROP은 collateral 0 조건.

**집행 시퀀스 (MDG 실제 actuation 경로, RUNBOOK §3):**

| 단계 | 결과 |
|---|---|
| 0. record_intent (guard 밖) | `{rule:nsenter_input_drop, source:10.45.0.11, revert_cmd:..., reversible:true}` 선기록(G3) |
| 0b. 안전 assert | 대상 10.45.0.11 ≠ UAV 10.45.0.2 ✓ |
| 1. BEFORE (read_only) | uav_ue netns INPUT = `-P INPUT ACCEPT` |
| 2. DROP 집행 (allow_live=True) | `ok=True dry_run=False` — 실 subprocess(불변식② 단일경로) |
| 3. effect_confirm | **`-A INPUT -s 10.45.0.11/32 -j DROP` 설치됨** ★E3 실증(uav_ue엔 iptables 없음→호스트 nsenter 주입) |
| 4. UAV C2 무영향 | lo:14550 HB 3라인 캡처 — self-DoS 0 |
| 5. REVERT (allow_live=True) | `iptables -D` ok=True |
| 6. 복원 확인 | 규칙 removed → `-P INPUT ACCEPT` |
| 안전망(read-only) | uav_ue netns INPUT 잔존 10.45.0.11 규칙 **0** · UAV HB 정상 |

**결과:** `GATE2_mechanism_PASS = true` (drop_installed ✓ · uav_c2_intact ✓ · reverted_clean ✓)

**입증:** ①**E3/E4 GATE2 블로커 폐쇄** — 호스트 nsenter가 iptables-없는 컨테이너 netns에 DROP 실적용 ②**가역성** 설치→clean 제거 ③**self-DoS 0** UAV C2 무영향 ④MDG 실제 코드경로(record_intent·단일 subprocess·revert, PA-6/G3/불변식②).

**미입증(정직):** attacker가 현재 UAV 미도달이라 **"라이브 공격 트래픽 실차단(E4 effect on live traffic)"은 미실증** — 집행 메커니즘·가역성·무해성은 확정, 실 공격 도달차단은 활성 공격 재구성 시에만 가능(추가 상태변경).

## 정직 한계
- **라이브 집행 범위**: V4에서 **nsenter DROP만** operator 승인 하 가역 집행(설치→revert, 흔적 0). **docker pause·서명명령(비가역)은 미실행.** 집행 메커니즘·가역성은 실증됐으나, attacker 미도달로 **실 공격 트래픽 차단(E4 effect)은 미실증**.
- **LLM 라이브 미실증**: litellm 엔드포인트 실호출 미수행(오프라인 G6 결정론 폴백으로 정합 유지). 모델 응답 결정론은 sign-off 대기.
- **캘리브레이션 미확정**: thresholds/recovery priors 도메인 sign-off 대기(결정론·배선은 정상).
- **탐지 사각(공개)**: V4 키위조 탐지불가·mission-weighted 희석(A5→Green)·anti-spoof presence-only(P5-Q3).

## 7. V5 — 자율구동 실증 + 다틱 정체 근본원인(driver) 규명·수정 + 세마포어/관측 하드닝, S2~S5 실집행

### 7.1 자율구동 실증 (idle + A5 mongo 자율탐지)

`live_autorun.py`(recon + 5 collector + `build_graph` + `run_driver` + `Backend(allow_live=True)`)로
**operator 없이 그래프가 자율 순환**하며 관측→탐지 실증:
- **idle** 상태: 명령평면 baseline=Green(0 신호), 텔레 HB normal — 오탐 0.
- **A5 mongo** 자율탐지: `MongoLog`가 RAN CIDR(`remote:10.44.0.3x`) DB 접속을 실시간 포착 →
  `DB_Access`(band=warning, domain=identity_access) **8건** 방출 → 그래프가 **Continue + Monitoring**
  으로 자율 라우팅(A5는 mission-weighted 희석으로 Green band, 감시 지속 결정).

### 7.2 ★ 다틱 정체 진짜 근본원인 = driver `stream(None)` 연속화 버그 (세마포어 오귀속 정정)

자율구동을 **다틱**으로 돌리면 tick 0 이후 정체(crash·leak 아님, run.jsonl 8줄 고정, 프로세스
state=S·no-syscall). 최초엔 air-tap 세마포어 경합으로 추정했으나, **로컬/서버 langgraph 최소 재현으로
진짜 원인을 확정**:

- 모든 틱의 그래프는 **END로 종료**(토폴로지: Green→END·act→effect_confirm→END·escalate→END).
  LangGraph에서 **END 도달 thread는 pending work가 없어 `graph.stream(None, cfg)`가 0 업데이트 반환**
  (재실행 안 함). → `tick_i`가 1에 영구 고정 → 드라이버 브레이크 조건(`tick_i>=max_iters`) **영원히 거짓**
  → **무한 무진행 루프**(InMemorySaver라 syscall 없음 → strace 공백·wchan=0과 정확히 일치).
- **최소 재현 결과**: 동일 thread_id + `stream(None)` ⇒ tick1~3 updates=**0**, tick_i **1 고정**.
  **틱마다 fresh thread_id + carry state** ⇒ updates=2씩, tick_i **1→2→3→4**, operator.add 채널
  log 2→4→6→8 (**중복누적 0**, 정확).

**수정 (`core/driver.py` — 실제 정체 해소):**
| 파일 | 변경 |
|---|---|
| `core/driver.py` | 틱마다 **fresh thread_id(`{run_id}-t{tick}`) + 직전 read-back state를 입력으로 re-seed**. `stream(None)`(END-thread no-op) 폐기. operator.add 채널은 fresh thread에서 carried value에 **정확히 1회** reduce(재현 실증). thread_id는 결정론이라 replay 바이트동일(GATE2) 유지. |

> **정정:** 이전 판(§S-1)에서 다틱 정체를 "air-tap 세마포어 경합"으로 귀속한 것은 **오귀속**이었다.
> 실제 정체 원인은 driver의 `stream(None)` 연속화 로직이며, 위 driver 수정으로 해소된다(idle 6틱
> **6초 완주**·아래 7.4). 세마포어/타임아웃/argv-allowlist 변경(아래 7.3)은 **유효한 방어 하드닝**이나
> 정체의 원인·해법은 아니었다.

### 7.3 부수 하드닝 — 세마포어 분리 + air-tap 타임아웃 + argv allowlist (정체와 별개, 유효)

정체의 원인은 아니었으나 독립적으로 옳은 개선(3전문가 적대검증 전원 approve, finding 반영):
| 파일 | 변경 |
|---|---|
| `safe_exec/backend.py` | read-only 관측은 세마포어 미획득·곧장 `_spawn`; 집행만 `with self._sem`(pool=1). `read_only` argv를 `is_read_only_argv` allowlist로 검증(신뢰경계 하드닝 — tcpdump `-w/-z/-G` 등 차단). |
| `collector/air_side.py` | air 탭 `_observe`에 짧은 deadline(command 2.0s / telemetry 3.0s) — idle 즉시 빈 반환. |
| `collector/__init__.py` | 두 air 탭 `interval_s≈0.1` back-to-back 재무장(~100% duty-cycle, 단발 명령 blind-gap 복원). |

**불변식 무손상:** ②누수-0 — R1(`kill_group`)·R6(`reap_proc`) teardown은 `_spawn` 내부라 세마포어와
독립적으로 read-only 경로에서도 실행. ①결정론 제어흐름 — driver의 fresh thread_id는 결정론이고
분기는 스케줄링만 변경(라우팅 무영향). read-only 관측 pool=1 의도 무손상(collector ss는 read-only·미connect).

### 7.4 S2 재검증 결과 — 다틱 자율런 완주 PASS (수정 적용 후)

수정 배포 후 idle 자율런(`live_autorun 6`) 실측:
- **완주 6초 · exit 0** (기존: 60초 timeout·미완, 무한정체) — 정체 완전 해소.
- **4틱 실행**(sense/correlate/trust/impact ×4 + 1틱 Yellow orient→select_policy→rank_recovery→decide),
  dry_streak 조기중단(PA-1 예산로직 정상), tick_i 정상 전진.
- **집행 0**(act/effect_confirm 노드 미발생 = idle 정상, 오탐 0).
- **누수-0**: 잔존 tcpdump/nsenter **0** · 컨테이너 **20 안정**(diff 0).
- **회귀 무영향**: pytest **154 passed · 1 skipped**.

### 7.5 S1~S5 라이브 실집행 (operator 승인 하 순차 집행)

`live/STEP_SPEC.md` + 동거 스크립트에 **DRY/read-only 기본, operator 명시 승인 하에서만** 실행되는
S1~S5 절차를 명세. 2대 불변식·운영제약이 항상 우선.

| 스텝 | 스크립트 | 성격 | 상태 |
|---|---|---|---|
| S1 근본원인 수정·베이스라인 | §7.2 driver 수정 | driver `stream(None)` 정체 규명·수정, pytest 154 무회귀 | ✅ 완료 |
| S2 MDG 자율런(다틱) | `live/run_autonomous.sh` | 관측, **6틱 6초 완주·집행0·누수0**(정체 해소 실증, §7.4) | ✅ 완료 |
| S3-a A2 PFCP teardown | `live/s3a_pfcp.sh` | 공격주입→탐지→즉시 복원(UAV 세션 삭제 금지 assert) | 집행 중 |
| S3-c A1 무서명 명령 | `live/s3c_command.sh` | AirCommandTap + uav_proxy 서명차단 카운터 실증 | 집행 중 |
| S4 E4 자율 차단 | `live/s4_e4_autodrop.sh` | **유일 상태변경** — 단일 가역 nsenter DROP(operator 승인·즉시 revert·흔적 0) | 승인 대기 |
| S5 종료·누수-0 | (STEP_SPEC §S5) | allow_live=False 원복, BEFORE/AFTER diff 0 | 대기 |

> 운영제약(불변): 상태변경 자동실행 0. 유일 예외 = S4 단일 가역 DROP(operator 서면승인). docker
> pause·서명명령(비가역)은 이 계획 범위 밖. IP/PID 런타임 해석, `attacker_ip != uav_ip` fail-closed.

---

## 서버 잔존물 (참고)
`~/mdg`(배포본)·`~/mdg_venv`·`~/campaign_out`(DRY 산출)·`~/v2_observe.py`(검증 스크립트)·`~/mdg.tgz`. 전부 방어측 파일이며 testbed dahv2 컨테이너는 무변경.

---
*요약: 배포 + 실서버 GATE0 + DRY + 라이브 관측(V1~V3, read-only) + GATE2 가역 집행(V4, operator 승인) + 자율구동 실증·다틱 정체 근본원인 규명·수정(V5)까지 완결. 방어 에이전트가 실 testbed를 정확·누수0으로 관측·탐지하고, 집행(nsenter DROP)이 iptables-없는 컨테이너 netns에 실적용·가역·self-DoS 0임이 실증됨(E3/E4 폐쇄). V5에서 자율구동(idle+A5 mongo 자율탐지, DB_Access 8건→Continue+Monitoring)을 실증하고, **다틱 정체의 진짜 근본원인이 driver의 `stream(None)` 연속화 버그(END-thread no-op → tick_i 고정 → 무한 무진행)임을 로컬/서버 langgraph 재현으로 확정**, 틱마다 fresh thread_id + carry-state re-seed로 수정하여 **idle 6틱 6초 완주·집행0·누수0·pytest154 무회귀**를 실증했다(세마포어 오귀속 정정). testbed 최종 무변경. 남은 미실증은 "실 공격 트래픽 차단(활성 공격 재구성 필요)"과 LLM 라이브·캘리브레이션 sign-off뿐.*
