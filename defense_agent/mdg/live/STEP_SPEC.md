# STEP_SPEC — S1~S5 라이브 실집행 명세 (Phase PREP)

> 지위: 본 문서와 동거 스크립트(`s3a_pfcp.sh`, `s3c_command.sh`,
> `s4_e4_autodrop.sh`, `run_autonomous.sh`)는 **operator 명시 승인 하에서만** 실행되는
> 라이브 실집행 절차다. 기본은 DRY / read-only. 2대 불변식·운영제약이 항상 우선한다.
>
> - 불변식① 결정론 제어흐름(조건부 엣지 수치 라우팅) — 스크립트는 MDG 그래프를 건드리지 않는다.
> - 불변식② 누수-0 실행(부작용은 safe-exec `Backend.run` 단일경로, R1~R6 reap, 노드 subprocess 0).
> - 운영제약: testbed 상태변경 자동실행 0. 유일 예외 = **S4의 단일 가역 nsenter DROP**(operator
>   승인·즉시 revert·흔적 0). docker pause·서명명령(비가역)은 이 스펙 범위 밖.

---

## 0. 환경·상수 (모든 스크립트 공통)

| 항목 | 값 |
|---|---|
| testbed | `<TESTBED-IP>` (AWS `<aws-host>`, dahv2 split-core) |
| SSH 키 | `~/.ssh/<KEY>.pem` (**v3** — 설계문서의 `dah_v2.pem`은 오기) |
| 접속 | `ssh -i "$SSH_KEY" ${TESTBED} "<cmd>"` (sudo NOPASSWD, docker 그룹) |
| MDG 배포 | 서버 `~/mdg` (venv `~/mdg_venv`, Python 3.12.3) |
| 자율런처 | `~/mdg_venv/bin/python -m mdg.live_autorun` (recon+5 collector+build_graph+run_driver+Backend) |
| run.jsonl | `~/mdg/live_out/<run_id>/run.jsonl` (run_driver `jsonl_path`) |
| 공격도구 | `~/dah_exec/A_TM1/tm1_inject_oracle.py` · `~/dah_exec/B_TM2_V3/pfcp_delete.py` |

### 라이브 실측값 (관측원 ↔ MDG collector)

| 평면 | 실측 | MDG collector / 탐지원 |
|---|---|---|
| 명령 uplink | `gcs_proxy` eth0 UDP **14556** (idle=0, 공격 시만 트래픽) | `AirCommandTap` → `Unauthorized_Command` |
| 텔레 downlink | **14560** + `uav_ue` lo **14550** 평문 HB(~1Hz) | `AirTelemetryTap` → `Link_Heartbeat`/`Packet_Loss` |
| PFCP delete | `smf` 로그 `Removed Session` + :9090 `s5c_rx_deletesession` 단조증가 | `SmfSession`(PFCP_Delete_Attempt) · `NetworkMetric`(:9090) |
| IMSI↔IP | `smf` 로그 `UE IMSI[00101...] IPv4[10.45.0.x]` | `SmfSession` (imsi_to_ip / ip_to_imsi, P4-1) |
| 서명 강제 | **uav_proxy**(복호→SITL) `🔒 MAVLink2 서명 강제 ON` + `[proxy] ⛔ 서명검증 실패 → SITL 차단 (누적 N)` | proxy 로그 카운터(윈도잉). ※`gcs_proxy` env만 보면 OFF 오판 |
| DB 접속 | `docker logs epc_mongo` `remote:10.44.0.3x` (RAN CIDR) | `MongoLog` → `DB_Access` |

### 역할·안전 앵커

| 역할 | IMSI | 관측 tun IP(예시, **런타임 재해석**) | 지위 |
|---|---|---|---|
| **UAV** | `001010000000001` (IMSI001) | 10.45.0.2 (session IP 10.45.0.4) | **보호대상 — 절대 DROP 금지** |
| **attacker** | `001010000000002` (IMSI002) | 10.45.0.11 (UE풀 tun 동적) | 차단대상(S4의 `-s`) |

> IP는 **런타임 read-only 재해석**(SMF IMSI↔IP + tun-scan). 하드코드 금지. 스크립트는
> 매 실행 시 IMSI002→attacker IP를 새로 풀고 **`attacker_ip != uav_ip` assert**(실패 시 fail-closed abort).

---

## S1 — 사전조건·베이스라인 (read-only, 상태변경 0)

**DO (전부 read-only SSH):**
1. GATE0 확인: `~/mdg_venv/bin/python -m pytest ~/mdg/mdg/tests -q` PASS, `verify_*` PASS.
2. 컨테이너 인벤토리: `docker ps --format '{{.Names}}'` — smf/upf/uav_ue/uav_proxy/gcs_proxy/web_backend/epc_mongo 존재 확인.
3. 역할 해석:
   - UAV IP  ← `docker logs <smf> | grep 'IMSI\[001010000000001\]'` 의 `IPv4[...]`.
   - attacker IP ← `docker logs <smf> | grep 'IMSI\[001010000000002\]'` 의 `IPv4[...]` (+ tun-scan 교차확인).
   - enforce_pid ← `docker inspect -f '{{.State.Pid}}' uav_ue` (chokepoint netns).
4. 서명 강제 ON 확인: `docker logs <uav_proxy> --since 10m | grep '서명 강제 ON'` (또는 `curl -s localhost/api/signing`).
5. command idle baseline: uav_ue 존재·서명검증 정상.

**VERIFY:** 위 5개 read-only 산출이 모두 성공 + `attacker_ip != uav_ip`(distinct) + `enforce_pid>0`.

**복원:** 없음(read-only).

**중단조건(self-DoS):** 역할 해석 실패 / attacker_ip==uav_ip / enforce_pid 미해석 → **즉시 abort**(이후 스텝의 DROP 대상 오염 위험). S4 진입 금지.

---

## S2 — MDG 자율런 기동 (관측 read-only; allow_live 는 env MDG_ALLOW_LIVE 에 따름)

> ★ allow_live 는 env(`MDG_ALLOW_LIVE`) 또는 `--allow-live` 플래그로 결정된다. 배포된 `.env.example`
> 은 SITL 데모 기본이 `MDG_ALLOW_LIVE=1` 이라 `cp .env.example .env` 시 **allow_live=True**(집행 창 개방).
> 순수 관측(read-only) 검증을 원하면 `MDG_ALLOW_LIVE=0` 으로 기동할 것. 아래는 read-only(=False) 시나리오.

**DO:**
1. 서버에서 자율런처 배경기동(read-only 검증 시 `MDG_ALLOW_LIVE=0`):
   `MDG_ALLOW_LIVE=0 nohup ~/mdg_venv/bin/python -m mdg.live_autorun --out ~/mdg/live_out --run-id <RUN_ID> > ~/mdg/live_out/<RUN_ID>/autorun.log 2>&1 &`
   - `Backend(allow_live=False, mode='local')` — 관측(read_only=True)만 실행, 집행은 DRY.
   - recon이 uav_ue 등 host PID를 inspect(read-only)로 풀어 collector netns_prefix 주입.
2. 정체 회귀 없음 확인: air-tap tcpdump는 짧은 deadline(command 2.0s / telemetry 3.0s) + read-only라
   **세마포어 미획득** → 타 collector/act 노드가 직렬 대기하지 않음(경합 버그 수정 검증). 다틱 진행 확인:
   `tail -f run.jsonl` 의 `tick_i` 단조증가.

**VERIFY (read-only):** idle 상태에서 `run.jsonl`에 collector envelope가 흐르고 command 도메인 baseline=Green(0 신호).
누수-0 스냅샷: `docker ps | wc -l`, 잔존 tcpdump/nsenter proc 수 기록(BEFORE).

**복원:** S5에서 런처 종료. (기동 자체는 관측이라 무변경.)

**중단조건(self-DoS):** run.jsonl `tick_i` 정체(경합 버그 재발) / collector heartbeat 정지 → 런처 kill 후 조사.

---

## S3 — 공격 주입 → MDG 탐지 확인 (각 attack: read-only 검증 + 즉시 복원)

두 공격을 **독립**으로 주입. 각 스크립트는 read-only 검증 → 최소 상태변경(공격도구) → **즉시 복원**
→ read-only 재검증 순서. 안전 assert(대상≠UAV) 포함.

### S3-a `s3a_pfcp.sh` — A2 PFCP teardown (attacker→SMF)

**DO:** `pfcp_delete.py`가 PFCP 세션 SEID를 sniff→delete session 발행.
- **안전 assert:** delete 대상 SEID/IMSI가 **UAV(IMSI001) 세션이 아님** 확인. 대상은 attacker(IMSI002)
  또는 시험용 세션. UAV 세션 삭제 금지(C2 self-DoS).

**VERIFY (read-only, MDG 탐지원):**
- `docker logs <smf> --since 30s | grep 'Removed Session'` → 삭제 로그(SmfSession 탐지원).
- `curl -s <smf>:9090 | grep s5c_rx_deletesession` diff → 단조증가(NetworkMetric).
- `run.jsonl`에 `PFCP_Delete_Attempt`(domain=session_network) envelope.

**복원:** UAV 세션이 영향받았으면 **UAV 재attach**(UE detach→attach 또는 세션 재수립) → C2 회복.
- 재검증: `docker logs <smf> | grep 'IMSI\[001010000000001\]' IPv4` 재부여 + uav_ue lo:14550 HB 재개.

**중단조건(self-DoS):** UAV 세션이 삭제되고 재attach 후 30s 내 HB 미재개 → abort, operator 수동 세션복원.

### S3-c `s3c_command.sh` — A1 무서명 명령 주입 (서명차단 검증)

**DO:** `tm1_inject_oracle.py`가 **무서명 DO_SET_MODE**를 명령평면(→gcs_proxy:14556→uav_proxy)으로 주입.

**VERIFY (read-only):**
- `AirCommandTap` gcs_proxy:14556 → `run.jsonl`에 `Unauthorized_Command`(idle=0 이므로 ANY 패킷=신호).
- **서명차단 실증:** `docker logs <uav_proxy> --since 30s | grep '서명검증 실패'` (`[proxy] ⛔ 서명검증 실패
  → SITL 차단 (누적 N)`) 카운터 증가.
- **UAV 불변:** `custom_mode` 변경 없음 — 무서명이라 uav_proxy가 SITL 차단. (mode read-only 조회로 확인.)

**복원:** 없음(무서명이라 uav_proxy가 이미 차단 — UAV 상태 무변경). 주입 도구 종료만.

**중단조건(self-DoS):** UAV `custom_mode`가 실제로 바뀜(서명검증 우회 = 심각) → abort, operator에게
서명 강제 상태(uav_proxy) 재확인 지시.

---

## S4 `s4_e4_autodrop.sh` — E4 자율 차단 실증 (단일 가역 상태변경, operator 승인)

> **유일한 라이브 상태변경 스텝.** operator 서면 승인 + `allow_live=True` 창(window) 안에서만.

**DO:**
1. **read-only preflight:** S1 역할해석 재실행 — `attacker_ip`(IMSI002) · `uav_ip`(IMSI001) ·
   `enforce_pid`(uav_ue). **assert `attacker_ip != uav_ip`**(fail-closed).
   attacker→UAV 베이스라인 도달성 확인(collateral 0 조건).
2. **공격 지속:** `tm1_inject_oracle.py`를 **지속 무서명 주입** 모드로 배경 실행 → command 도메인 Red 유도.
3. **MDG 자율 집행:** allow_live=True 자율런이 `nsenter_input_drop` 계획→집행. 형태(act_host/response 코드 확정):
   ```
   nsenter --target <enforce_pid> --net -- iptables -w -I INPUT -s <attacker_ip> -j DROP
   ```
   - 2-endpoint 봉쇄: enforce netns(uav_ue chokepoint) ≠ source(attacker) — distinct 검증 통과 시만 argv 생성.
   - record_intent(guard 밖) 선기록 + revert_cmd(`-D`) 선기록(G3).
4. **effect_confirm — 주입 트래픽 실차단(E4):**
   - `nsenter --target <enforce_pid> --net -- iptables -w -S INPUT | grep '<attacker_ip>.*DROP'` → 규칙 설치됨.
   - 주입 트래픽 차단 관측: DROP 후 attacker 주입이 chokepoint 도달 중단
     (uav_proxy `서명검증 실패` 카운터 증가 **정지**, 또는 AirCommandTap 신호 소멸).
   - **UAV C2 무영향(self-DoS 0):** uav_ue lo:14550 HB 계속 3라인 캡처.

**VERIFY:** `run.jsonl`에 `applied[nsenter_input_drop].confirmed` + drop rule 설치 + attacker 신호 소멸 + UAV HB 정상.

**복원(revert, 필수):**
```
nsenter --target <enforce_pid> --net -- iptables -w -D INPUT -s <attacker_ip> -j DROP
```
- 재검증: `iptables -S INPUT`에 `<attacker_ip>` 규칙 **0** · UAV HB 정상 · attacker 도달성 원복.
- 주입 도구 종료.

**중단조건(self-DoS / §5 ABORT):**
- **assert 실패**(attacker_ip==uav_ip, 또는 DROP `-s`가 UAV IP) → 집행 전 abort. **절대 UAV DROP 금지.**
- DROP 후 UAV HB 30s 내 소멸 → **즉시 revert** + operator 보고.
- revert 후 규칙 잔존 → 수동 `-D` 반복 + `allow_live=False` 원복.

---

## S5 — 종료·누수-0 검증 (read-only, 원복)

**DO/VERIFY (read-only):**
1. `allow_live=False` 원복(자율런 종료 또는 flag off). 이후 상태변경 경로 DRY.
2. 누수-0(불변식②) AFTER 스냅샷 vs S2 BEFORE:
   - `docker ps | wc -l` diff **0**.
   - 잔존 tcpdump/nsenter proc **0**(관측 subprocess는 timeout/count 자기종료 + R1~R6 reap).
   - `iptables -S INPUT` attacker 규칙 **0**.
3. 자율런처 종료: `pkill -f 'mdg.live_autorun'`(서버) + run.jsonl flush 확인.

**복원:** 위 자체가 원복. testbed dahv2 컨테이너 최종 무변경.

**중단조건:** AFTER 스냅샷에서 컨테이너 수 diff≠0 / 좀비 proc / 잔존 DROP → 누수. §4 수동복원 + 보고.

---

## 부록 — 스크립트 공통 규약

- 모든 검증은 **read-only SSH**. 상태변경은 (i) 공격도구 실행 (ii) S4 단일 DROP뿐이며 각각 즉시 복원.
- 각 스크립트 상단에 `set -euo pipefail`, 안전 assert 함수 `assert_not_uav`, fail-closed abort.
- IP/PID는 런타임 해석 — 하드코드 금지. 해석 실패 시 abort.
- `revert`는 EXIT trap으로도 등록해 중간 실패 시 자동 복원 시도(멱등 `-D`).
</content>
</invoke>
