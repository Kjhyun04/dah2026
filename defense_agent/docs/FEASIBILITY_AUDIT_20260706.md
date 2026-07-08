# 방어 에이전트 구현 타당성 감사 — MDG 설계 ↔ 라이브 테스트베드

> 작성 2026-07-06 · 근거: 12-에이전트 워크플로우(라이브 서버 <TESTBED-IP> read-only 실측 + 설계문서 대조) · 대상: `mission_defense_*` (Mission-Centric Defense / MDG) 설계
> 목적: 설계요소를 **에이전트 개발 관점**에서 ①그대로 구현 ②수정 구현 ③고정값 대체(불가능하지만 필수) ④제거(불가능+불필요) 로 분류하고, 누락·오분류·모순을 검증.

---

## 0. 요약

104개 설계요소를 실측 대조로 분류(검증 정정 반영):

| 판정 | 의미 | 개수 | 대표 예 |
|---|---|---|---|
| **IMPLEMENTABLE** | 이 테스트베드에서 그대로 수집/집행 가능 | ~35 | MAVLink Command_Type/Seq/Source 파싱, PFCP delete 카운터, RTT/loss, 서명 DO_SET_MODE, docker pause, Evidence/Trust/Impact/Decision 데이터모델·수식 |
| **MODIFY** | 설계와 **다른 메커니즘**으로만 가능 | ~34 | Network Collector(pcap→Prometheus+로그), Web Collector(로그훅→netns pcap), UE 격리(SDN→docker pause), Trust 수식(0-분모 패치) |
| **FIXED_VALUE** | 라이브 소스 없음 but 파이프라인 필수 → **하드코딩/config** | ~14 | Mission Context 전체, Mission Weight 표, Session_TTL(3240s), Threshold 정상값, Recovery 성공확률 prior |
| **REMOVE** | 불가능 + 불필요(공격자산·기반·수요 부재) | ~21 | SDN Controller, 메시지브로커, 분산/샤딩 스토어, WORM, ML/RL, PX4 API, Key Rotation, Route/Mission Replan, GPS·환경센서·GTP브릿지·Mission재할당 탐지 |

**핵심 결론 5:**
1. **파이프라인 골격(Evidence→Trust→Impact→Policy→Recovery→Decision)은 전부 구현 가능** — 순수 소프트웨어. 제거 대상은 전부 "인프라/미래지향 잎사귀"(브로커·SDN·WORM·샤딩·ML·미션플래너)이며 각각 작동하는 대체재가 있어 파이프라인이 끊기지 않는다.
2. **탐지 데이터의 절반은 설계가 말한 방식으로는 못 얻는다** — mongo audit(Enterprise 전용), web_backend 요청로그(없음), 미션서버(없음), UE 격리 메트릭(없음). 메커니즘 교체(MODIFY) 또는 고정값(FIXED)로 흡수.
3. **⚠ 설계의 최우선 방어(iptables로 tcp/5762 차단)가 실제로는 무력** — 5762은 10.45 UE풀(GTP-U 유저스페이스 스위칭)로 도달해 호스트 netfilter를 통과하지 않는다. UE 격리를 무력화한 바로 그 우회. **호스트 iptables가 아니라 `docker pause` 또는 uav_ue netns 내부 INPUT 규칙**만 유효.
4. **미션 계층 전체가 고정 config로 붕괴** — 미션서버·플래너·Mission API가 존재하지 않음. Mission Context/Weight/Impact는 상수 프로필로 공급해야 파이프라인 수학이 성립. 단, **정찰 가중치 벡터·mission_type 키·제약값이 문서마다 달라** 하나의 정본으로 통일 필요.
5. **V4 키위조 공격은 탐지기가 없다** — 올바르게 서명·위장된 명령은 서명검증·소스 화이트리스트를 모두 통과. 봉쇄(차단/pause)만 매핑됨, 탐지 불가로 명시 필요.

---

## 1. IMPLEMENTABLE — 그대로 구현 (에이전트 즉시 착수)

| 요소 | 실측 근거 | 개발 노트 |
|---|---|---|
| **Command_Type / Sequence_Number / Command_Source** | `172.30.0.20:14560` 평문 fan-out에 표준 MAVLink2(헤더 seq, COMMAND_LONG.command, sysid/compid) — **컨테이너 attach 불필요**. 정상 GCS=`(255,190)`, 5762 백도어=`(1,1)` | pymavlink 단일 파서가 세 필드 동시 산출. 그룹 Command 전체의 최적 관측점 |
| **PFCP_Delete / PFCP_Create / Session_Reset(파생)** | Open5GS `:9090/metrics` (`s5c_rx_deletesession`, `pfcp_peers_active`, `n4sessionestabreq`) + INFO 로그(`PFCP de-associated`) | 1s 틱 카운터 diff. idle 정상=0 → `>0` 트립. `B_TM2_V3/pfcp_delete.py`로 검증 |
| **Packet_Loss / RTT** | UE netns ping 실측: `uav_ue→gcs_proxy` 0% loss, RTT 21.7/24.5/27.8ms; tun ~120ms | **유일하게 통계적 정상이 존재**하는 두 지표. 60s 창 자동 캘리브레이션 |
| **Port_State (5762/14540)** | `ss` 실측: `tcp 0.0.0.0:5762 LISTEN`(arducopter, 유일 실증 백도어), `udp 0.0.0.0:14540`(GPS_INPUT) | 5762 신규 연결 감시가 최고신호. `ss -tnp` established 감시 병행 권장 |
| **Invalid_Command_Format** ⭐(검증에서 REMOVE→IMPL 정정) | 변형/범위이탈 COMMAND_LONG은 14560 평문탭에서 pymavlink 파싱오류/필드검사로 관측 — **전용 공격자산 불필요** | Command_Type 파서에 무료로 얹히는 신호. 제거하면 안 됨 |
| **Autopilot 서명 DO_SET_MODE / LAND / RTL (ARIA 정규경로)** | `gcs_c2`·`web_backend`가 `/sign.key`(ro) 보유, 서명 uplink `COMMAND_ACK` 실측. 기존자산 `def_exec/G_TM1/tm1_signing_defense.py`(mode 4/6/9) | **공격자와 구별되는 인증된 복구경로**. ArduPilot 모드번호(GUIDED4/RTL6/LAND9) — PX4 아님 |
| **docker pause / network disconnect** | `/var/run/docker.sock` 존재, ubuntu ∈ docker 그룹 | **UE풀 우회를 유일하게 막는 격리 수단**(공격 컨테이너를 소스에서 정지) |
| **Mongo 27017 네트워크 ACL** | mongo 무인증·이중홈(10.44.0.2 + 10.50.0.5), 27017 클라이언트는 **진짜 docker bridge**(net_core/net_cellular) → INPUT/DOCKER-USER 필터 유효 | UE풀 우회 대상 아님. 가역 iptables로 RAN측 접근 차단 |
| **데이터모델·수식 전부**: Evidence/Incident/Trust/Policy/Recovery/Decision Trace 스키마, Confidence 수식, Impact Matrix+Green/Yellow/Red, Correlation 엔진, Core Data Flow 8단계, Operator Confirmation, Decision Trace 해시체인 | 순수 in-process 소프트웨어; web_backend가 이미 asyncio 3.9msg/s 처리 | 단일 MDG 컨테이너 내 asyncio 파이프라인. 브로커 불필요 |
| **Evidence TTL 자동만료** | mongo:6.0 Community가 **TTL 인덱스는 지원**(audit와 달리) | `expireAfterSeconds` 또는 in-mem reaper |
| **Collector 무판단 원칙 / heartbeat / 버퍼링+confidence감쇠** | 모든 수집경로가 read-only·비추론 | Collector는 raw Evidence만, 판단은 MDG 독점 |

---

## 2. MODIFY — 수정하여 구현 (메커니즘 교체 필수)

| 요소 | 설계가 말한 것 | 실제 가능한 것(교체안) |
|---|---|---|
| **Network Collector** | host-net 특권 pcap 에이전트 | net_core+net_cellular 멀티홈 컨테이너가 `:9090` 폴링 + `docker logs` 테일. pcap 아님 |
| **Web Backend Collector** | 공유 로그볼륨 + instrumentation hook | app.py가 요청로그·훅 전무 → **web_backend netns join**(`--network container:web_backend`)해 8080 캡처. ⚠검증정정: net_sgi 브리지 스니핑은 실패(localhost→docker-proxy DNAT, 브리지는 유니캐스트 미플러딩) |
| **MongoDB Collector / DB_Access** | audit log 플러그인, per-query | mongo:6.0 **Community=audit 불가**. `mongod.log` NETWORK 연결-수락 이벤트 테일(연결 단위). net_cellular(10.44) 출처 연결을 이상으로. per-query 불가 |
| **Auth_Failure / Credential_Verification** | HTTP 401·DB 인증실패 | 그런 인증경계 없음 → **MAVLink v2 서명검증 실패**(uav_proxy `서명검증 실패 -> SITL 차단 (누적 N)`, 실측 카운터=8)로 재정의. Signature_Verified·Unauthorized_Command과 **단일 로그테일 공유** |
| **Signature_Verified** | 구조화된 wire 필드 | wire 필드 없음. **실패만** 관측(uav_proxy stderr). per-packet PASS 필요 시 `/sign.key` 재계산 사이드카 |
| **Unauthorized_Command** | 단일 네이티브 메트릭 | 복합신호 = 서명드롭 + 소스불일치(14560) + 5762 활동. 3자 융합 규칙 |
| **UE_Isolation_State** | 격리 상태 게이지 | 메트릭 없음 + 능동프로브도 불가(attacker_ue에서 프로브 못 함, 신규 UE 프로비저닝=상태변경). **"미격리" 상수**로 보고 + UPF anti-spoof DROP 로그 보조 |
| **Trust Score 수식** | `100×(1−Σ(w·sev·deviation))×conf` | ⚠ deviation=`(obs−exp)/max(exp,thr)`가 **고정0 기준 지표(PFCP/DB/Unauth)에서 0-분모→NaN**. `obs>0 ⇒ deviation=1.0` 또는 per-metric normalizer로 패치. + **도메인 내 weight 합=1 정규화**(안 하면 trust 음수) |
| **Correlation Rules** | CR01: PFCP_Delete+Unauth_Command **same source_ip** | 두 이벤트가 다른 평면(PFCP=10.50 코어NF / 명령=10.45·net_sgi) → source_ip 조인 영원히 미발화. ⚠IMSI 조인도 불가(MAVLink Evidence엔 IMSI 없음) → **순수 시간창 동시발생**만 |
| **iptables 5762 차단** ⚠(검증에서 IMPL→MODIFY 정정, 치명적) | host DOCKER-USER/FORWARD DROP | 5762은 10.45 UE풀(GTP-U 유저스페이스 스위칭)로 도달, **호스트 netfilter 미통과**. → **uav_ue netns 내부 INPUT 규칙** 또는 **docker pause**만 유효. (net_core PFCP 8805·net_sgi 8080·mongo 27017 필터는 진짜 브리지라 유효) |
| **Network/APN 격리, Command Override, Access Control 등 대응** | SDN flow / 프로토콜 sequence-reset / 앱 인증 | 각각 docker pause+victim-INPUT / 상위권한 서명명령 재발행 / **네트워크층 방화벽 스코핑만**(app.py 무인증은 런타임 수정 불가) |
| **MDG 배치 / 전송** | net_sgi 단일 배치, gRPC over net_sgi | MDG를 **net_sgi+net_cellular+net_core 멀티홈**; 각 Collector는 자기 로컬망으로 접속 |
| **6단계 Decision 래더** | 6개 자동 대응 | Reconfiguration·Graceful Degradation은 **actuator 없음**(리라우팅·백업링크 부재) → 운영자-권고로 강등. 자동집행은 Continue/+Monitoring/Abort(서명 RTL/LAND)만 |

---

## 3. FIXED_VALUE — 불가능하지만 필수 → 고정값/config로 대체

> 라이브 소스가 없으나 downstream 수학이 이것 없이는 성립 못 하므로 **상수로 공급**. 아래 값은 실측 idle 텔레메트리와 정합.

| 요소 | 왜 측정 불가 | 공급할 고정값 |
|---|---|---|
| **Mission Context (7필드)** | 미션서버·플래너 부재 | `{mission_type:"Recon", mission_phase:"En-route", mission_priority:"High", mission_goal:"Area surveillance sector B3", critical_asset:"UAV+camera", constraints:{max_alt_m:120, rtl_on_link_loss:true, rtb_min:30}, environment:"clear/urban"}` — **⚠단일 정본으로 통일**(아래 §4 모순) |
| **Mission Weight 표** | 순수 설계상수, mission_type도 고정 | 5행 lookup 상수. 활성행 Recon=`{comm:30, identity:10, session_network:20, command:20, mission:20, recovery:0}`(합100). **⚠Collector가 다른 벡터를 실었음 — 이 행으로 통일** |
| **Session_TTL** | mme.yaml 타이머 주석처리 → 런타임 노출 없음 | Open5GS 기본 T3412=**3240s(54분)** 상수 |
| **NAS_Cipher_Order** (검증: MODIFY→FIXED 통일) | 정적 startup config, 핫리로드 없음, MME 재시작 필요 | mme.yaml 1회 읽어 `[EEA2,EEA1,EEA0]` 기대와 비교. **라이브가 EEA0-first라 설계 가정과 모순** → 상시 posture 결함으로 보고(연속 오탐 방지). 다운그레이드 공격자산 없음 |
| **Threshold 정상값**(PFCP_Delete/DB_Access/Unauth/Session_Reset) | idle=정의상 0, 통계적 정상 없음 | def4 고정 밴드: PFCP_Delete `normal[0]/warn[1]/crit[2,3]/danger[4,∞]`; Unauth/Session_Reset `>0=경보`. (RTT·Packet_Loss만 실측 캘리브레이션) |
| **Evidence expected/threshold/weight** | "정상" 라이브 소스 없음 | `thresholds.yaml` 상수표(가중치·심각도 포함) |
| **Confidence 채널품질 prior** | per-Evidence 기본신뢰 소스 없음 | 채널별 상수: 평문MAVLink탭 0.95, 5762읽기 0.9, :9090 0.9, NAS로그 0.85, mongo연결로그 0.6, 능동프로브추정 0.7 |
| **Recovery Feasibility 값**(success_probability·expected_recovery) | "Historical Success Data" 없음(신규 데모) | 실행가능 타입별 prior: 서명LAND/RTL 0.9(+cmd40), 5762차단 0.95(+cmd30), PFCP방화벽 0.8(+sess20), mongo ACL 0.85(+id20) |
| **Time Window 파라미터** | 튜닝 상수, 측정소스 없음 | decay 60s(정책 300s), rolling 10s, observation 5s, aggregation 60s, TTL 60s |

---

## 4. REMOVE — 불가능 + 불필요 (에이전트 범위에서 제외, 미래과제 표기)

> 제거해도 파이프라인 안 끊김을 §검증에서 확인. 각 항목 **작동 대체재** 명시.

**인프라/비기능(과잉설계):**
- **SDN Controller API** — onos/odl/ryu/ovs 전무 → iptables+Docker API로 대체
- **메시지 브로커/스트림**(kafka/redis/nats) — 없음, 데모 3.9msg/s → in-process asyncio
- **분산/샤딩 시계열·NoSQL 스토어** — 단일 mongo:6.0 노드 → TTL 인덱스 단일 컬렉션
- **WORM 암호 감사 스토리지** — 매체 없음 → 앱층 해시체인+HMAC(전용 audit키, MAVLink /sign.key 재사용 금지)
- **ML/RL 이상탐지·강화학습·정책최적화** — 스택·데이터 전무 → 결정론적 수식. 인터페이스만 남겨 미래 슬롯
- **선형확장/클러스터링** — 단일서버 고정 20컨테이너 → 고정 토폴로지

**존재하지 않는 대상/자산:**
- **PX4 API** — 실제는 ArduPilot SITL → 제네릭 MAVLink로 재타깃(모드번호 재매핑)
- **Key Rotation**(서명키/ARIA) — 키를 import 시 1회 로드, ro 마운트, 리로드 엔드포인트 없음, 재시작 필요(금지) → 키노출 시 **경로 봉쇄(차단/pause)**로 대응
- **Mission API / Route Replan / Mission Replan** — 미션서버·플래너·waypoint 프로세스 전무 → 손상 시 **Safe Landing(RTL/LAND)**으로 대체
- **Session_Token_Usage** — 토큰인증 전무 → 데이터소스·자산 0
- **GPS Spoofing / GPS_Signal_Deviation** — 공격자산 없음 + 기준-진위 위치소스 없음(리라우팅 대응도 없음)
- **Environment Sensor Spoofing / Env_Sensor_Deviation** — 센서·자산·데이터소스 **전무**(영구 null 도메인이라 confidence 수학 오염)
- **GTP Bridge / GTP_Bridge_Attempt** — 공격자산 없음 + 격리 mechanism 없음. (인접 실존신호: UPF anti-spoof `[DROP]` 로그는 다른 용도)
- **Mission Reassignment/Tampering (NF-5)** — 조작할 plan 객체·자산 없음

---

## 5. ⚠ 검증에서 발견된 치명적 정정 (원 분류 오버라이드)

에이전트 코딩 전에 **반드시** 반영:

1. **iptables 5762 차단 = 무력** (IMPL→MODIFY). 공격 리포트의 "1순위 완화(5762 loopback)"를 에이전트가 호스트 iptables로 흉내내면 백도어가 그대로 열려있는데 막았다고 오판. → `docker pause` / uav_ue-netns INPUT만.
2. **V4 키위조 = 탐지기 부재**. 올바른 서명·위장 명령은 모든 판별자 통과 → 봉쇄만 가능, **잔여 탐지불가로 명시**. 완화책: 14560 탭에서 예상밖 wire출처의 중복 link_id 또는 seq이상 행동 판별자 추가 검토.
3. **Invalid_Command_Format = 제거하면 안 됨** (REMOVE→IMPL). 실존 producer(14560 파싱오류) 있음.
4. **Web Collector 데이터경로 오류**. net_sgi 브리지 스니핑 실패 → **web_backend netns join** 필수.
5. **UE_Isolation 능동프로브 불가**. attacker_ue에서 프로브 못 함 → "미격리" 상수 보고.
6. **5762 탐지 자체가 단일점·poll취약**. 14560 fan-out·서명로그에 안 잡힘 → Port_State ss 폴링만 → established-conn watch/conntrack 보강.

---

## 6. 설계문서 내부 모순 (코딩 전 1개 정본으로 확정)

| # | 모순 | 정본 권고 |
|---|---|---|
| M1 | **정찰 가중치 벡터 2종**: Collector `{comm.15,id.15,sess.20,cmd.30,mission.20}` vs Weight표 Recon `{comm.30,id.10,sess.20,cmd.20,mission.20}` | **Weight표 Recon행**으로 통일 |
| M2 | **mission_type 키 3종**: `reconnaissance`/`Reconnaissance`/`Recon` → lookup KeyError | 단일 토큰 `"Recon"` |
| M3 | **operational_constraint 3종**: 고도 100 vs 120 vs "<120m" | 단일 정본 JSON(§3 값) |
| M4 | **Policy priority 방향**: core §10(낮은수=높은우선) vs def5(높은수=높은우선) | 하나 선택(권고: 낮은수=높은우선) |
| M5 | **overall_impact 스케일 3종**: 0-100 높을수록나쁨 vs 0-1 ≥0.8=continue vs 0-1 ≥0.8=abort | **0-100, 높을수록 나쁨, Green0-30/Yellow31-70/Red71-100** 표준화 |
| M6 | **recovery_score 수식 3종** / **recovery_type enum 3종** | 실행가능분(§2)에 맞춰 각 1종 확정 |
| M7 | **Mission Impact 인코딩**: 0-100 정수(객체) vs 0-1 실수(Decision Trace 예시) | 0-100 정수 통일 |
| M8 | **weight에 recovery(6번째) 키** but Impact Matrix는 5도메인 | recovery 키 제거 또는 Impact 매핑 추가(Monitoring행 recovery:5가 5% 소실) |

---

## 7. 누락 요소 (완결성 갭 — 분류에 추가 필요)

완결성 검증이 찾은 미분류 설계요소(대부분 구현가능한 소프트웨어이거나 REMOVE):

- **Attack Mapping Model**(Core §13) — 공격별 매핑/검증 레코드. 7 검증가능 vs 5 불가 구분해 구축
- **Evidence Repository 인터페이스** StoreEvidence/QueryEvidence/StoreIncident/SubscribeIncident — 구현가능(파이프라인 의존)
- **외부 인터페이스** Sensor/Operator/Logging — Operator/Logging은 구현가능, 나머지 REMOVE
- **Key_Distribution_Status / Key_Exposure_Detected** 메트릭 — 대부분 소스 없음(키노출은 봉쇄만)
- **Mission Impact Confidence Modifier**(저신뢰 도메인 impact 과대) — 구현가능, 보수적 동작 유지 위해 필요
- **Mission Decision Object 스키마**(로직과 별개) — 구현가능
- **Trust Score Range 밴딩표**(100-90…29-0) — 결정 래더가 참조하는 상수, 명시 필요
- **Collector Manager 모듈**(버퍼/순서/heartbeat 수신) — 구현가능
- **Trust Failure Handling**(증거부족→이전점수유지·confidence↓, 충돌→correlation우세, 무효weight→균등분배) — 구현가능, 명시 필요
- **Policy Conflict Resolution**(동순위 tie-break→exception→운영자에스컬레이션) — 구현가능
- **Threat Capability Matrix + Packet_Count/GPS_Input** — 매트릭스는 문서화, GPS_Input는 REMOVE
- **Capability 외부연동**(Dashboard/AAA/OAuth/IAM) — 전부 부재 → **REMOVE 명시**

---

## 8. 실증 공격별 방어 커버리지 (에이전트가 실제 데모 가능한 것)

| 실증 공격 | 탐지(IMPL 메트릭) | 대응(집행 가능) | 상태 |
|---|---|---|---|
| PFCP delete (TM2) | :9090 카운터 + SMF 로그 | iptables 8805 peer제한(진짜 브리지) | ✅ 완결 |
| MAVLink replay (V1) | Sequence_Number 단조성(14560) | 서명 Command Override | ✅ 완결 |
| TM1 web-oracle | 8080 캡처(netns join) | iptables 8080 스코핑 | ⚠ 단일점(heartbeat 보강) |
| 5762 백도어 | Port_State/established watch | **docker pause / netns-INPUT** (호스트 iptables 아님) | ⚠ 메커니즘 정정 필수 |
| rogue-UE recon | DB_Access net_cellular 플래그 | docker pause | ✅(격리는 pause만) |
| **V4 키위조** | **없음**(서명·소스 통과) | 봉쇄만 | ❌ 탐지불가 명시 |
| TM3 S1-U | (ARIA 암호문 — 무력화됨, 방어 불필요) | — | ✅ 설계상 안전 |

---

## 9. 에이전트 개발 권고 (아키텍처 결론)

- **단일 MDG 컨테이너**(net_sgi+net_cellular+net_core 멀티홈) 내 asyncio 파이프라인 + **6개 경량 Collector**(2개 air-side netns 사이드카는 그대로, Network=metrics/log 어댑터, Web=netns-join pcap, Mongo=연결로그, Mission=config 로더).
- **Collector→MDG 전송은 gRPC 단일**(브로커 제거). Collector는 무판단 raw Evidence만.
- **결정론적 수식 파이프라인** 전량 구현 가능 — Trust 0-분모/weight정규화 패치, Correlation 시간창 조인, Impact 0-100 표준화 선행.
- **actuator 라이브러리 = {서명 MAVLink(LAND9/RTL6/GUIDED4), 진짜-브리지 iptables(8805/8080/27017), docker pause/disconnect}**. 5762 봉쇄·UE격리는 pause/netns-INPUT. 2-tier 게이트(자동 vs 운영자승인)로 비행상태 변경은 승인 필수.
- **Mission 계층·Threshold·Recovery prior는 config 상수**로 출하; §6 모순을 하나의 `mission_profile.yaml`/`thresholds.yaml`로 확정.
- **정직성**: V4 탐지불가, NAS EEA0-first 상시결함, 5762 호스트차단 무력, 미검증 4공격(GPS/env/GTP/mission)은 "미래과제"로 보고서에 명시 → 배점 ②(방어-공격 연결성)·문서완성도에서 과장 없는 신뢰 확보.

> **★2026-07-07 프레임워크 개정:** §9의 "단일 MDG 컨테이너 내 asyncio 파이프라인"은 **LangGraph StateGraph 오케스트레이션**으로 구현(asyncio는 그 하부). 파이프라인 8단계 = LangGraph 노드, 대응 래더 분기 = 결정론 조건부 엣지. Collector는 그래프 밖 장수 데몬. 도메인 분류(IMPL/MODIFY/FIXED/REMOVE 104요소)는 **불변** — 프레임워크 전환은 "무엇을"이 아니라 "어떻게 조립하나"만 바꿈. 상세 `FRAMEWORK_STACK.md`.
