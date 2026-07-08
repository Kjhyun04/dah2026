# MDG 전체 코드 점검 — 자율 DROP 실현 갭 감사 (2026-07-08)

> 방법: 7차원 병렬 감사(response-wiring·불변식①②·귀속모델·collector·config·test) → high/blocker 적대검증(22/22 확정) → 종합. 30 에이전트.
> 근거: 라이브 검증 사실 위에서 실코드 Read/Grep. 모든 앵커 파일·라인 확정.

## 결론 (한 줄)
**사용자의 4곳 수정(web.py peer방출 / correlate target / select_policy 5762→nsenter / config enforce_at)은 필요하지만 불충분.** 4곳을 다 적용해도 자율 DROP은 발화 못 한다. 3개 숨은 blocker(A 레거시티 별칭키·B SensorEv 셀렉터 운반 부재·C 탐지 netns 오배선)와 3개 high(D kind 라우팅·E priors 등록·F enforce_at 키공간)가 4곳의 **상류·하류를 모두 막고 있고**, 이 상태에서도 pytest 154는 계속 green이다(e2e가 `role_verified["target"]=True` 인위주입으로 A갭을 가림).

## 추가 필수 수정 (blocker/high) — 자율 DROP 실현에 필수

| # | 심각도 | 파일:라인 | 문제 | 수정 |
|---|---|---|---|---|
| **A** | 🔴blocker | `core/legality.py:30`, `tools/registry.py:105/109/112/116` | AUTO 도구 precond가 `role_verified.target`/`.gcs` **리터럴 별칭키**를 조회하나 라이브 `role_verified`는 **컨테이너명 키**(uav_ue 등)만 가짐 → nsenter_input_drop·docker_pause·send_signed_mode 전부 illegal → `legal_actions=[]` → chosen_action=None. **최종 관문** | `is_legal`에 action의 enforce_at/target 컨테이너키를 넘겨 `role_verified[<그 키>]` 동적 검증. 또는 recon이 별칭 노출 |
| **B** | 🔴blocker | `collector/ingest.py:64`, `core/state.py:34` | `envelope_to_ev`가 metric/value/band/domain/channel/confidence 6개만 복사 → SensorEv에 ip/imsi/source 필드 없어 귀속 셀렉터가 **파싱시 폐기**. peer IP를 실어나를 채널 자체가 없음 | SensorEv+envelope_to_ev에 opaque `source` 필드 추가·배선 |
| **C** | 🔴blocker | `collector/__init__.py:79`, `web.py:46`, `defaults.py:210` | WebProbe가 **web_backend netns** 관측, 5762 LISTEN/ESTAB는 **uav_ue netns** → ss가 딴 netns 실행 → 증거 미방출 → A4 incident 미출생. **탐지측 최상류** | `m.get("web_backend")`→`m.get("uav_ue")`, verify_anchor 토폴로지 교정 |
| **D** | 🟠high | `core/nodes/correlate.py:21`, `select_policy.py:17` | 모든 tripped 신호가 kind=`single-signal`, select_policy는 kind로만 라우팅 → 단순 5762→nsenter 재매핑하면 **RTT/mongo/NAS/telemetry 전부 uav_ue 5762 DROP 오라우팅** | correlate가 5762에 전용 kind(`BACKDOOR_5762`) 발급 + `_INCIDENT_RECOVERY`에 그 kind만 매핑 |
| **E** | 🟠high | `rank_recovery.py:55`, `defaults.py:116`, `recovery_priors.yaml` | 신설 rtype 미등록시 `_succ` 기본 0.5<0.70 feasibility 탈락 + enforce_at gcs_proxy 폴백 | 5762 rtype을 **yaml+defaults 양쪽**에 succ≥0.70·response_tool=nsenter_input_drop·enforce_at=uav_ue 등록 |
| **F** | 🟠high | `safe_exec/response.py:107`, `defaults.py:200` | `pid_map.get(enforce_sel)`, pid_map은 **컨테이너 키**인데 문서는 'role key' → enforce_at="uav"(역할)로 쓰면 `pid_map.get("uav")=None`→inert | enforce_at 반드시 컨테이너명 `uav_ue`. 키공간 문서/코드 정합 |
| **G** | 🟠high(self-DoS) | `collector/network.py:127` | `_SIGNAL_MAP.get(name,('PFCP_Delete_Attempt',...))` 기본폴백 → UPF N3 데이터플레인 볼륨(정상)이 매 사이클 **danger PFCP로 날조** → 자율 DROP 활성화 후 **실제 self-DoS** | 미지 카운터 PFCP 폴백 제거·skip, N3 비-트립 분리 |
| **+** | 🟠high(self-DoS) | `config/defaults.py:116` vs `recovery_priors.yaml:9` | D.RECOVERY_PRIORS에 response_tool/flight 누락 → **pyyaml-absent fallback에서 backdoor_pause가 OPER→AUTO 역전** + 도구 오치환(pause→DROP) | defaults를 yaml과 완전 미러링, 또는 response_tool 부재시 fail-closed |

## 안전 원칙 (급소)
**A(legality)를 여는 순간 fail-closed 방벽 하나가 열린다.** 그러므로 A는 반드시 **G(오탐 소스 제거)·F(enforce_at 컨테이너키)·D(kind 분리) 이후에** 활성화해야 오DROP self-DoS를 막는다. 현재 모든 실패가 안전측(inert DRY)이라 자율 DROP이 발화 못 하는 것이며, 목표는 fail-closed를 유지하며 정당 경로만 여는 것.

## 최소 변경셋 (자율 DROP 실현) — 의존 순서

| 순 | 항목 | 파일 | 선행 |
|---|---|---|---|
| 1 | C 탐지 netns | `collector/__init__.py:79`,`web.py:46` | — (최상류) |
| 2 | G N3 오매핑 제거 | `collector/network.py:127` | — (오탐 선제거) |
| 3 | B 셀렉터 운반 | `ingest.py:64`,`state.py:34` | C |
| 4 | ① web peer 방출 | `web.py` | B,C |
| 5 | D 전용 kind | `correlate.py:21`,`select_policy.py:17` | B |
| 6 | ② correlate target | `correlate.py:24` | 3,5 |
| 7 | ③ select_policy 매핑 | `select_policy.py:18` | 5 |
| 8 | ④+F enforce_at=uav_ue(컨테이너) | `recovery_priors.yaml`,`defaults.py`,`response.py` | 7 |
| 9 | E priors 등록(yaml+defaults) | `recovery_priors.yaml`,`defaults.py:116` | 8 |
| 10 | A legality 동적 바인딩 | `legality.py:30`,`registry.py` | **최종 관문** |
| 11 | 관통 회귀 테스트 | `tests/test_p4_response.py` | 1-10 |

## 전체 건전성 보완셋 (medium/low, 28건 요약)

**불변식②(누수-0) 방어심층·검증 커버리지**
- `backend.py:196` teardown()/R4 reap이 `not allow_live`에서 dead — read_only가 실제 spawn하는 기본모드에서 크래시-고아 회수 primitive 꺼짐. reap을 `mode=='mock'`만 게이트.
- `verify_no_fw_subproc.py:24` 정적 subprocess-0 검사가 core/만 스캔 → collector/ingest/replay 미스캔. 스캔 루트 확대.
- `driver.py:78` 매틱 fresh thread_id인데 checkpointer pruning 없음 → InMemorySaver 무한누적. delete_thread(t-1).
- `mdg/live_autorun` 프로덕션 런처 부재 → collector.stop()/join() 소유자 없음(종료시 관측자 미회수).

**불변식①(결정론) 정적 강제**
- `verify_routing.py:39` FORBIDDEN_KEYS 스캔이 edges.py에만 한정 → gate/legality/rank_recovery/select_policy 무방비(현 누출 0, 회귀가드 없음).

**collector 오탐 억제**
- `air_side.py:127` Packet_Loss value=100인데 band='warning'(계약 위반). METRICS band-range 미소비(compute_trust가 domain/weight만). 미방출 metric(RTT/Signature_Verify_Fail/NAS_Cipher_Order). `mongo.py:99` dedupe 키 ts 없음. `sense.py:81` command 도메인 2 collector 충돌.

**config 죽은 표면**
- `recovery_priors.yaml:10` pfcp_firewall enforce_at=gcs_proxy(PFCP는 net_core, 미지남) — epc_smf/upf가 role 아님. mongo_acl 삼중 데드(고아+web_backend 오정합+cellular 미검증). `act.py:71` reverse_container_for_ip 데드코드.

**테스트 회귀 잠금**
- `backend.py:52` is_read_only_argv 유닛 0. `driver.py:86` fresh thread_id re-seed·operator.add-1회누적 회귀 0(스텁만). `correlate.py:20` 직접 유닛 0. `test_p4_response.py:319` 5762 ESTAB→non-inert argv e2e 부재.

## self-DoS 정렬 (자율 DROP 활성화 후 현실화 위험)
| 위험 | 원인 | 완화 선행 |
|---|---|---|
| N3 볼륨→PFCP 오DROP | G(network.py:127) | A 이전 G 필수 |
| tier inversion 잘못된 도구 auto-DROP | defaults.py:116 | E와 동시 |
| kind-collapse 엉뚱 소스 DROP | D | A 이전 D 필수 |
| 재할당 IP 무고 UE DROP | recon stale binding(response.py:65 smf_table 미참조) | 교차확인 |

---
*요약: 자율 DROP은 4곳이 아니라 **최소 11단계(4곳+6교정+회귀테스트)**를 의존순서대로 적용해야 실현되며, 급소는 10-A(legality 별칭)와 1-C(탐지 netns)다. 이 둘이 빠지면 나머지가 조용한 no-op가 되고 154 pytest는 green을 유지한다. A는 G·F·D 이후에 마지막으로 열어야 self-DoS를 막는다.*
