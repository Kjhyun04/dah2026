# 방어 에이전트 구현 갭 — 설계 → 코드 이관 시 추론/구체화 필요 지점 (라이브 대조)

> 작성 2026-07-07 · 근거: 라이브 서버 `<TESTBED-IP>` read-only 실측 + `DEFENSE_AGENT_V3_DESIGN.html`(정본) 대조
> 목적: 설계가 "무엇을·왜"까지 닫았으나 **코드로 옮기는 순간 구현자가 추론/발명하거나, 문서 전제가 라이브에서 이미 어긋난 지점**만 추출.
> 심각도: 🔴 그대로 코딩하면 즉시 깨짐 · 🟠 메커니즘 미구체화 · 🟡 값·정본 미확정. **BLOCKED(불가) 0건.**

---

## 0. 요약

| 범주 | 갭 | 심각도 | 성격 |
|---|---|---|---|
| A | 문서 값이 라이브와 불일치(이미 realized) | 🔴 | 실측값 이관 |
| B | 관측점 metric/로그/도구 미구체화 | 🟠 | 실측값 이관 |
| C | 집행 효력 미측정 / signer-shim 순환 | 🟠 | 실측 1건 + **설계 판단 1건** |
| D | LLM·mdg 컨테이너 인프라 미확정 | 🟠 | 환경 결정 |
| E | 수식·config·형식 정본 미생성 | 🟡 | 파일화 |

**유일하게 새 설계 판단이 남은 것 = C-2(signer-shim 키 비확산 배치).** 나머지는 실측값 이관 + 결정 파일화.

---

## A. 🔴 문서 값이 라이브와 불일치 — 하드코딩하면 지금 당장 틀림

### A-1. UE풀 IP 문서(.3/.4) ≠ 라이브(.2/.10), 그리고 `docker inspect`에 부재
```
공격리포트/워크플로우 문서:  UAV=10.45.0.3,  attacker=10.45.0.4
라이브 실측(2026-07-07):     uav_ue tun_srsue=10.45.0.2,  attacker_ue tun_srsue=10.45.0.10
docker inspect:              uav_ue=10.44.0.30, attacker_ue=10.44.0.31  ← cellular만; tun(10.45.x)은 안 보임
```
- UE풀 IP는 재접속마다 **동적 재할당**되고 `tun_srsue` 인터페이스에만 존재 → `docker inspect`로 취득 불가.
- **영향:** `10.45.0.3` 상수화 시 docker pause 대상 해석·드론측 교차탭·correlation이 전부 오대상.
- **결론:** H-I(런타임 role→IP 해석)는 필수. 해석 메커니즘은 반드시 **`docker exec <c> ip -4 addr show tun_srsue` 스캔**(inspect 불가). role_verified는 tun IP 취득 + 아래 검증으로.
- **검증 앵커:** uav = `lo:14550` 평문 HEARTBEAT sys=1 관측 / attacker = UE풀 IP 보유하나 5762 백도어 접속 시도.

### A-2. 파서가 의존할 실제 로그/wire 포맷 (영어·표준 가정 시 전멸) — 실측 문자열 고정
```
uav_proxy 서명드롭:  [proxy] ⛔ 서명검증 실패 → SITL 차단 (누적 <N>)   # 한글+이모지, 누적 카운터. regex: 누적 (\d+)
gcs_c2 서명 ON:      [GCS] 🔒 MAVLink2 서명 송신 ON (link_id=0)
gcs_c2 하행 HB:      [GCS] ✓ DOWNLINK HEARTBEAT from UAV sys=1 (셀룰러 경유)
gcs_c2 상행 ACK:     [GCS] ✓ UPLINK ACK ok (COMMAND_ACK)
Mongo 접속(stdout):  {"c":"NETWORK","id":22943,"msg":"Connection accepted","attr":{"remote":"10.44.0.31:59948","connectionCount":3}}
```
- **서명 성공은 per-packet 로그 없음** → `Signature_Verified=PASS`는 로그로 관측 불가(**실패 카운터만**). 성공 스트림 파싱 시도 = 영구 0.
- **Mongo 로그파일 없음**(`/var/log/mongodb/mongod.log` 부재) → 소스 = `docker logs epc_mongo` **stdout JSON**. 판정 = `id==22943(accepted)` + `attr.remote` CIDR(10.44=RAN측=이상). id 22944=ended.
- 파서는 **UTF-8 이모지/한글 안전**해야 함.

---

## B. 🟠 관측점 — metric 명칭·메커니즘·도구가 안 박힘

### B-1. PFCP 트립 신호 metric + 음수 게이지 지뢰
```
SMF 10.50.0.4:9090 → s5c_rx_deletesession 8            ✅ 신뢰 트립신호(단조 카운터, 틱당 diff)
                     gtp_node_s5c_rx_deletesession{addr="10.50.0.3"} 8   (per-peer)
                     s5c_rx_createsession 9
                     pfcp_sessions_active -8            ⚠️ 음수 게이지 (버그성)
                     fivegs_smffunction_sm_sessionnbr{...} -8   ⚠️ 음수
UPF 10.50.0.7:9090 → pfcp_peers_active 1, fivegs_upffunction_*   (delete 카운터 없음)
```
- **metric이 NF별 분산:** delete 카운터=SMF, peers=UPF → Collector가 **두 net_core IP 폴링** + metric→NF 매핑 필요.
- **`localhost:9090` 아님** — NF의 net_core IP(:9090). MDG는 net_core 멀티홈 필수.
- **`*_active` 게이지는 음수(-8)** → 세션 수 기반 임계는 붕괴. 반드시 **`s5c_rx_deletesession` 카운터 diff**만 트립으로.

### B-2. `dahv2/air` 이미지에 `curl`/`nc` 없음 → 메트릭 폴링 도구 제약
```
air 이미지: python3 ✅  tcpdump ✅  ss ✅  pymavlink 2.4.49 ✅  |  curl ✗  nc ✗
epc 이미지: curl ✅  python3 ✅  ss ✅
```
- :9090 폴링을 `curl`로 짜면 air 사이드카에서 실행 불가 → **python `urllib`** 폴링 또는 epc-이미지 컨테이너 사용.

### B-3. 14556 명령 tap 방식 + baseline 부재
- gcs_proxy netns 인터페이스 = `lo, eth0(172.30.0.10)`. 명령은 **eth0 UDP:14556** 진입.
- proxy.py가 **유일 소비자** → 2차 `recvfrom` 불가 → tap = **`tcpdump -i eth0 udp port 14556` 스니핑만**.
- idle 14556 트래픽=0(공격 시에만) → **정상 baseline 부재 도메인**. 관측 정확성은 공격 재생으로만 검증(unit-test로 못 닫음).

### B-4. (갭 아님, ✅ 확정) 드론측 lo:14550 교차탭
- `uav_ue` netns `lo`에서 평문 UDP:14550 **3패킷 캡처 성공**(len 40/30/14). D-1 교차검증 = `docker exec uav_ue tcpdump -i lo udp port 14550` + pymavlink. 확정.

---

## C. 🟠 집행 메커니즘 — 효력 미측정 / 순환 논리

### C-1. inter-container nsenter DROP 실효력 = 코드 전 미측정 (GATE2 블로커)
- `DOCKER-USER` 빈 체인 · `/proc/sys/net/bridge` 부재(br_netfilter 미로드) 재확인.
- netns-INPUT 집행으로 정정했으나 **실제 DROP 1건이 inter-container 도달을 끊는지 read-only로 확정 불가**.
- **구현 시:** `pfcp_firewall`/`mongo_acl` 성공확률은 prior(추론)로 넣고 "미확인" 라벨. GATE2 가역 실측이 이 추론을 없애기 전엔 "차단됨" 주장 미검증.

### C-2. ★ signer-shim 배치의 순환 (유일한 미해소 설계 판단)
설계: "operator-gate shim을 gcs_c2 netns에 두되 **키 비확산**." 라이브 실태:
```
/sign.key 마운트: uav_proxy=HAS, gcs_c2=HAS, web_backend=HAS  ← 이미 3곳 확산(H5/E11 지적 대상)
gcs_c2 command: python3 /gcs.py udpin:0.0.0.0:14550  (고정; gcs.py는 호스트 ../gcs/gcs.py ro 마운트)
```
operator 토큰을 요구하는 서명 shim 삽입 경로:
- (a) 새 사이드카에 `/sign.key` 재마운트 → **E11(키 확산) 재현**.
- (b) `gcs.py` 수정 → **공격자산(ro) 변경** = testbed 오염.
→ **"키를 더 안 퍼뜨리면서 operator-gate를 강제"하는 배치가 설계에 없음.** 코드 전 결정 필요(별도 설계).

### C-3. docker pause 대상 역매핑
- A-1의 결과: UE풀 소스IP(10.45.0.x)→컨테이너는 후보 컨테이너 `ip addr show tun_srsue` **exec-scan 역매핑**이 유일.
- 사전 화이트리스트도 IP 동적이라 **매 부팅 재검증**. 메커니즘 명시 필요.

---

## D. 🟠 LLM·런타임 인프라 — 환경 미확정 (직전 P0 빌드 실패의 뿌리)

### D-1. LLM 도달성 ✅ / 크레덴셜·모델 ✗
- net_core 컨테이너 → `api.anthropic.com` 도달 확인(egress NAT 열림). 호스트도 도달.
- **미정:** `ANTHROPIC_API_KEY` 프로비저닝 · `models.yaml` 모델ID(Orient/Decide 역할별) · 레이트/비용. (직전 P0 빌드=레이트리밋 사망과 직결.)
- `litellm`/`grpcio` 호스트 미설치(그린필드 확인).

### D-2. mdg 컨테이너 — 스펙 확정됨 (FRAMEWORK_STACK.md §4)
- **base:** `python:3.12-slim`(서버 3.12.3 정합). 로컬 3.14 pip-free 목표 폐기 → **replay JSONL이 이식성 본선**.
- **멀티홈:** net_sgi+net_cellular+net_core. 도구 바이너리: nsenter·iproute2(ss/ip)·tcpdump·docker CLI/sock.
- **deps(핀 고정·lockfile):** langgraph·litellm·pydantic v2·pyyaml·grpcio·grpcio-tools·protobuf·httpx·pymavlink==2.4.49·scapy·fastapi·uvicorn·pytest.
- **잔여(구현 P0):** `~/mdg` 디렉토리·Dockerfile·lockfile 실제 생성 + ANTHROPIC_API_KEY 프로비저닝(D-1).

---

## E. 🟡 수식·config·형식 — 결정만 하고 실체 미생성

| # | 갭 | 필요 조치 |
|---|---|---|
| E-1 | `mission_profile.yaml`/`thresholds.yaml` **실파일 미생성** — M1~M8 모순(가중치벡터·mission_type키·고도120·priority방향·impact 0-100·recovery수식) 결정만, 파일화 안 됨 | 정본 파일 생성 |
| E-2 | Trust 수식 **최종 함수 1개 미확정** — E5(conf 적대항만)·E6(포화 vs noisy-OR **택1 안 함**)·E7(band→severity→dev 매핑표 미작성)·E19(correlation_score 산출식 미정) | 함수 확정 |
| E-3 | Confidence prior·Recovery success_probability·Time window 파라미터 = FIXED 상수(FEASIBILITY §3 값 있으나 config 미이관) | 상수표 이관 |
| E-4 | **H-E WorldState 닫힌 술어/아티팩트 완전표 부재**(NEEDS-FIX) — 27 tool의 requires/consumes/produces와 정합, 누락 술어=legal 데드락 | 완전표 작성(verify_tools 전제) |
| E-5 | verify-suite **미작성**(서버 부재) — `verify_tools`/`verify_keys`/`verify_leak0` + **LangGraph 신규 3종** `verify_graph`/`verify_routing`(불변식①)/`verify_no_fw_subproc`(불변식②) | GATE0/1 러너용 신규 작성 |

---

## P. 도메인 전문가 패널 검증 (2026-07-07) — 새 갭 (AI개발자·보안·4G인프라)

> H-O 규율(3인 병렬). 위 A~E와 **중복 아닌 새 갭**만. 🔴=코딩 즉시 막힘 · 🟠=발명 필요 · 🟡=값·매핑 미확정.

### P.AI — LangGraph 구현 (AI 에이전트 개발자)
| # | 갭 | 심각도 |
|---|---|---|
| **PA-1** | **루프 위상 모순** — §1.3 엣지(`…→sense` 되돌이)는 그래프 내부 사이클(recursion_limit 무한루프)인데 종료는 "루프 밖 드라이버"+"그래프=1틱". 양립 불가. MDGState에 `tick_i/pivots/dry_streak` 카운터 부재. → **"1 invoke=1틱, 되돌이 엣지 전부 →END, recon은 부트 1회"로 확정** | 🔴 |
| **PA-2** | **`verify` 노드 ↔ grep0 Verifier 충돌** — `verifier_truth`가 decider의 MDGState 필드라 `verify_grep0`(Verifier↛decider) 즉시 실패. in-graph effect-confirm ≠ out-graph Verifier 이름 뭉갬. → **`effect_confirm`(노드,피벗신호) vs `Verifier`(별프로세스,replay만) 분리·State에서 verifier_truth 제거** | 🔴 |
| **PA-3** | **MDGState 채널 어노테이션 전무** — 누적 list(`ledger/decisions/incidents`)에 리듀서(`Annotated[list,add]`) 미지정 → LangGraph 기본 LastValue로 조용히 덮어씀. WorldState/TrustObj/Intent/OrientNote pydantic 실체 없음 | 🔴 |
| **PA-4** | decide→act 엣지의 risk/reversible이 LLM 선택에 오염 가능(불변식① 위협). 행동선택은 `rank_recovery`(결정론) 확정, `chosen_action_risk/reversible`(번들=max/all) State 필드로 승격 후 엣지가 이것만 읽게 | 🟠 |
| **PA-5** | LLM 노드 `OrientNote/DecideNote` pydantic 스키마 부재 + "상향만"(E12) 집행함수 부재(`apply_advice=tighten_only`). structured output만으론 병합규칙 없음 | 🟠 |
| **PA-6** | act 노드 순서 모순 — legality(pre_hook=guard 안) vs record_intent(guard 밖)이 역전. legality를 tool_wrap 밖 선체크로 올리고 tool_wrap은 safe-exec+world_update만 감싸기 | 🟠 |
| **PA-7** | Collector→sense 드레인 스레드/이벤트루프 경계 미정(sense=동기노드+`queue.Queue` non-blocking 드레인으로 확정, async 금지) · replay 가상시계 주입점(`Clock` config 주입·`time.*` 직접호출 AST금지)·녹화훅(`stream_mode="updates"`) 미확정 | 🟠 |
| **PA-8** | 11노드에 홈 없는 v2 로직(compute_confidence·build_evidence·gate_evaluate·emit_trace) 노드매핑 부재 · `escalate(operator)`가 엣지타깃인데 노드로스터 없음·HITL을 LangGraph `interrupt()`로 할지 미정 | 🟠 |
| **판정** | **PA-1/2/3 닫기 전 StateGraph 스캐폴드·verify_graph/routing 배선 불가.** 반나절 설계결정 선행 후 P0 착수 | 🔴 |

### P.SEC — 방어 에이전트 자기 보안 (보안 전문가)
| # | 갭 | 심각도 |
|---|---|---|
| **PS-1** | **docker.sock = 분할불가 root** → D-2 권한분리("iptables-agent ⟂ signer")가 무효(둘 다 sock 참조 시 이득 0). → **docker-socket-proxy(pause/inspect만 화이트리스트)** + nsenter 최소권한 헬퍼로 격리, core/signer는 sock 미접근(grep0 확장) | 🔴 |
| **PS-2** | **in-proc Collector 큐가 ingest HMAC/mTLS 우회** — §6#3이 로컬 collector에 무인증 in-proc 허용. 사이드카(대상 netns 공존) 장악 시 위조 Evidence 직접주입→오탐 auto-격리. → **sense가 드레인 시점에 HMAC/seq 검증 필수**(전송계층 아닌 소비계층) | 🔴 |
| **PS-3** | **replay JSONL/MDGState가 비밀 원문 영속** — "Viewer redact"는 표시시점, 디스크 JSONL은 secret 보유. verify_keys는 소스 리터럴만 검사. → **녹화시점 redact + State/JSONL secret-free 계약**(LLM키·operator토큰·HMAC키 State 미경유) + `verify_replay_leak0`(카나리) | 🔴 |
| **PS-4** | LangGraph/litellm 전이 의존트리 = host-root 에이전트 대형 공급망 표면. 해시핀(`--require-hashes`)·SBOM·**egress allowlist**(api.anthropic.com만, litellm exfil 채널 차단) 미명세 | 🟠 |
| **PS-5** | 키 부트스트랩·회전 경로 부재("out-of-band"는 명칭만). CA·mTLS 발급/폐기·HMAC kid 버전화 미정 → 실코딩 시 "이미지에 키 굽기"(E11 재현) 위험 | 🟠 |
| **PS-6** | 안티리플레이 seq/윈도우 파라미터 미확정 + **크래시 복구 시 seq high-watermark 미영속→리플레이 윈도우 재개방** + 캐시 무한증가 DoS. seq를 ledger에 영속 | 🟠 |
| **PS-7** | structured output은 인젝션 미차단(출력스키마만 제약)·"상향만"은 **과잉대응 유발 인젝션 통과**(→엉뚱 대상 auto-격리=자해 DoS). 신뢰불가 필드는 파생신호(수치)로만 LLM 전달, 대응은 결정론 임계 재확인+디바운스+provenance 게이트 | 🟠 |
| **PS-8** | FastAPI viewer/:50051 바인드 인터페이스 미명세(0.0.0.0면 공격자 UE 10.45.x 도달)·viewer 인증 부재(posture 유출)·gRPC pre-auth DoS(max_message/동시연결 상한 없음). 관리 인터페이스/loopback 바인드+토큰인증+한도 | 🟠 |
| **PS-9** | checkpointer 저장소(백엔드·경로·0600·비공유볼륨) 미명세=data-at-rest 유출면 · operator 토큰이 **명령 다이제스트 미바인딩**→캡처 토큰으로 다른 서명명령 승인 가능(token=존재증명≠명령승인) | 🟡 |
| **판정** | **자기보안 GATE1(라이브) 이전에 PS-1/2/3 선행 필수** — 지금 코딩하면 권한분리·ingest신뢰·비밀위생이 실제로 성립 안 함 | 🔴 |

### P.4G — 코어망 관측 정합성 (4G 인프라, 라이브 실측)
| # | 갭 | 심각도 · 라이브 근거 |
|---|---|---|
| **P4-1** | ★ **IMSI↔동적IP 귀속이 실은 가능** — SMF 로그가 `UE IMSI[001010000000001] IPv4[10.45.0.2]`(생성)·`Removed Session: UE IMSI:[…] IPv4:[10.45.0.3]`(삭제)로 **IMSI↔할당IP 바인딩 발행**. FEASIBILITY §2 "IMSI 조인 불가→시간창만" **정정**. → MDG가 SMF 로그 테일로 IMSI↔tun-IP 세션테이블 유지 → 교차평면 correlation 조인 + **docker pause 대상해석(A-1/C-3) 해소**. mongo subscribers엔 IMSI만(동적IP 없음) | 🟠 **capability+정정** |
| **P4-2** | metric→NF 완전표 부재. 라이브 확정: **SMF**(10.50.0.4) delete/create/`*_parse_failed`/peers/sessions/ues/bearers · **UPF**(10.50.0.7) `fivegs_ep_n3_gtp_in/outdatapktn3upf`(N3 데이터량)·session/qos · **MME**(10.50.0.2) enb/enb_ue/mme_session(희소) · **PCRF** 빈 metric | 🟡 |
| **P4-3** | 미활용 방어신호 — `s5c_rx_parse_failed`·`gtp_node_*_parse_failed`·`gtp_new_node_failed`(변형 GTP-C=이상)·UPF `fivegs_ep_n3_gtp_*`(데이터평면 볼륨이상). 설계 IMPL표는 deletesession만 씀 → 관측면 확장 | 🟠 |
| **P4-4** | 세션삭제 소스귀속 — per-peer metric(`{addr="10.50.0.3"}`)은 SGWC 단일peer만 구분, **어느 UE/세션 삭제인지는 metric으로 불가** → **SMF 로그 `Removed Session: UE IMSI:[…] IPv4:[…]` 테일이 유일 귀속원**(P4-1과 동일 소스) | 🟡 |
| **P4-5** | attach/IMSI/service-request 관측은 **MME 로그 유일**(MME metric 희소). Rogue-UE attach(TM3) 탐지=MME 로그 테일. 로그는 **ANSI 컬러 이스케이프 포함**(파서 ANSI-strip이 EPC 로그에도 적용돼야) | 🟡 |
| **P4-6** | RTT baseline 셀룰러 변동 — 라이브 uav_ue→gcs_proxy = 14.5/30.2/38.6ms, **mdev 11ms(고지터)**. 문서 21~28ms보다 변동 큼 → 단일임계 RTT는 오탐, 창+지터 허용 필요 | 🟡 |
| **판정** | **4G 방어 관측 착수 가능** — 소스는 전부 라이브 실재(SMF/UPF/MME metric+로그). 단 P4-1(IMSI↔IP 세션테이블)을 관측설계에 편입하면 귀속·pause대상·correlation이 동시 해소 | ✅ (P4-1 반영 권장) |

---

## S. 라이브 자율구동 실증 중 발견 — 다틱 정체 근본원인 = driver `stream(None)` 연속화 버그

> 발견경위: `live_autorun.py`(recon + 6 collector + build_graph + run_driver + `Backend(allow_live=True)`)로
> **idle + A5(mongo) 자율 탐지가 실증**된 뒤, 다틱 자율 런을 돌리자 tick 0 이후 **틱이 정체**됨(crash·leak
> 아님, run.jsonl 8줄 고정). 최초엔 air-tap 세마포어 경합으로 추정했으나, **로컬/서버 langgraph 최소
> 재현으로 진짜 원인을 driver로 확정**. 세마포어 관련 변경은 유효한 부수 하드닝이나 정체의 원인·해법은
> 아니었음(오귀속 정정).

### S-0. 🔴 ★진짜 근본원인 — driver의 `stream(None)` 연속화가 END-thread에서 no-op (S1 수정)

**증상:** 다틱 자율 런이 tick 0 후 정체(run.jsonl 8줄 고정, 프로세스 state=S·strace no-syscall·wchan=0).

**근본원인(재현 실증):** 모든 틱의 그래프는 **END로 종료**(토폴로지: Green→END·act→effect_confirm→END·
escalate→END). LangGraph에서 **END 도달 thread는 pending work가 없어 `graph.stream(None, cfg)`가
0 업데이트 반환**(재실행 안 함). driver는 tick 0 후 `stream(None)`로 연속화하려 했으므로 → `tick_i`가
1에 영구 고정 → 브레이크 조건(`tick_i>=max_iters`) **영원히 거짓** → **무한 무진행 루프**. InMemorySaver라
syscall이 없어 strace 공백·wchan=0과 정확히 일치.

**최소 재현(서버 langgraph):** 2노드(sense→decide→END) 그래프 + InMemorySaver.
| 방식 | tick1~3 updates | tick_i | operator.add log_len |
|---|---|---|---|
| 동일 thread_id + `stream(None)` (기존) | **0** | **1 고정** | 정체 |
| **틱마다 fresh thread_id + carry state (수정)** | 2씩 | **1→2→3→4** | 2→4→6→8 (중복누적 0) |

**수정 (`core/driver.py`):** 틱마다 **fresh thread_id(`{run_id}-t{tick}`) + 직전 read-back state를
입력으로 re-seed**. `stream(None)` 폐기. fresh thread에서 operator.add 채널(ledger/decisions/incidents)은
carried value에 **정확히 1회** reduce(동일 thread re-seed 시의 중복누적을 회피 — 재현으로 확인). thread_id는
결정론이라 run.jsonl replay 바이트동일(GATE2) 유지. **결과: idle 6틱 6초 완주·집행0·누수0·pytest154 무회귀.**

### S-1. 🟠 (부수 하드닝, 정체와 별개) read-only 관측이 집행 pool=1 세마포어를 공유

> 정정: 아래는 다틱 정체의 원인이 **아니다**(S-0가 원인). 그러나 read-only 관측이 집행 세마포어를
> 공유하는 것은 독립적으로 옳지 않아 함께 수정했다(3전문가 적대검증 approve).

**내용:** air-tap collector의 `tcpdump`가 idle 인터페이스에서 블로킹하면 모든 `Backend.run`이 공유하는
**단일 `PrioritySemaphore(1)`**(5762/nsenter 자원단일화용)을 오래 점유해, 원리상 집행이 직렬 대기할 수
있다(정체의 관측된 원인은 아님).

**수정(2파일):**
- (A) `safe_exec/backend.py` — `Backend.run`에서 **read-only 관측(`read_only=True`)은 세마포어를
  획득하지 않고 곧장 `_spawn`**하도록 분기 분리. 집행(`read_only=False`)만 `with self._sem`(pool=1)
  경로로 자원단일화. 기존 DRY 가드(`not allow_live and not read_only`)는 그대로 유지. **추가로
  `read_only`는 caller-asserted 신뢰경계이므로 `is_read_only_argv`(관측바이너리 allowlist
  {tcpdump,ss,docker-logs} + `-w/-W/-G/-z` 금지 + nsenter prefix 스트립)로 argv를 검증**해야만
  fast-path(allow_live 우회 + 세마포어 skip)를 연다 — 검증 실패 시 상태변경 요청으로 강등(적대검증
  low finding 반영).
- (B) `collector/air_side.py` — `AirCommandTap`/`AirTelemetryTap`의 `_observe` 호출에 **짧은 deadline**
  주입(command **2.0s** / telemetry **3.0s**). idle이면 타임아웃이 count 대기보다 먼저 끊고 빈
  stdout(n≤0)으로 즉시 반환. `-c count`는 유지(공격 시 즉시 캡처).
- (C) `collector/__init__.py` `build_collectors` — 두 air 탭만 **`interval_s≈0.1`** 로 배선해
  tcpdump를 back-to-back 재무장(~100% 듀티사이클) → 명령평면 단발 COMMAND_LONG(disarm/SET_MODE)
  blind-gap 소실 위험 복원(적대검증 medium finding 반영). read-only가 더 이상 세마포어를 잡지 않으므로
  연속 재무장이 act 노드/타 collector를 굶기지 않음.

**불변식 무손상:**
- **불변식②(누수-0):** `_spawn`의 R1(TimeoutExpired→`kill_group`)·R6(`finally: reap_proc`) teardown은
  세마포어 획득 여부와 독립적으로 read-only 경로에서도 그대로 실행. 노드 subprocess 0·단일 spawn 사이트 불변.
- **불변식①(결정론 제어흐름):** `run()`의 분기 추가는 관측/집행 실행 스케줄링만 바꿀 뿐 조건부 엣지
  수치 라우팅·결정론 제어흐름에 무영향.
- **5762 pool=1 의도 무손상:** WebProbe의 `ss`는 read-only·미connect라 애초에 5762 소켓 슬롯을
  연결/집행으로 점유하지 않음(자원단일화 대상 아님). 실제 5762 직렬 집행도구(`serial5762.py` 등,
  `read_only=False`)는 여전히 `with self._sem` 경로로 단일화.

**검증(3전문가 적대검증, 전원 approve):**
| 관점 | verdict | 요지 |
|---|---|---|
| 누수-0 / 스레드안전 | ✅ approve (issue 0) | read-only는 세마포어 획득만 우회, R1~R6 teardown 무관하게 실행. 유일 `BoundedSemaphore(1)`은 집행경로만 획득(중첩/순서 위험 0). nsenter는 별 subprocess라 read-only read 충돌 없음, 상태변경 nsenter는 여전히 직렬화. `verify_no_fw_subproc` 0 위반. |
| 자원단일화 / 신뢰경계 | ✅ approve (low 1) | 집행(`read_only=False`) 3콜러 전부 pool=1 유지 → 자원단일화 무손상. **low: `read_only`가 argv 미검증 신뢰경계** → **`is_read_only_argv` allowlist로 수정 반영**. |
| 순수관측 정합 | ✅ approve (medium 1·low 1) | tick_once `finally`가 `_last_hb` 갱신 → idle 즉시반환이 liveness 무손상(watchdog 여유 개선). **medium: 명령탭 duty-cycle blind-gap** → **`interval_s≈0.1` 재무장으로 수정 반영**. **low: 텔레탭 손실-온셋 지연/오탐** → **telemetry `timeout_s=3.0s`로 완화 반영**. |

**결과:** 3 finding(low argv·medium duty-cycle·low telemetry) 전부 **코드에 반영**. 정체 버그 해소 —
read-only 관측이 집행 pool=1을 더 이상 점유하지 않아 다틱 자율 런이 직렬 대기 없이 진행.

---

## F. 착수 순서 (갭 닫기 → GATE)

1. **실측값 이관(A·B):** InputSpec 기본 role 매핑 + 파서 fixture(로그 문자열·metric 명칭·음수게이지 회피)를 config/테스트로 고정.
2. **C-2 설계 판단:** signer-shim 키 비확산 배치 확정(별도 설계 문서).
3. **E 정본화:** mission_profile/thresholds.yaml + Trust 최종함수 + WorldState 완전표 + verify-suite 3종.
4. **D 환경:** mdg 컨테이너 빌드 스펙 + LLM 키/모델 확정.
5. **GATE0**(형식·실행계약) → **GATE1**(누수-0, C-1 포함 GATE2 가역 실측 전 라이브 금지) → **GATE2**(자율성·이식성·효력).

> 운영 제약(불변): 인가 샌드박스 · read-only/가역 · 컨테이너 stop 금지 · 키(/sign.key·ARIA) 반출 금지 · 검증 중 상태변경(DROP·pause·서명명령) 금지.
