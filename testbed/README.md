# DAH testbed v2 — 국내 방산 4G UAV C2 인프라 랩 (자립형 통합 매뉴얼)

공격 계층 없는 **인프라 중심(infra-only)** 4G UAV C2 테스트베드.
Open5GS(4G EPC) + srsRAN(ZMQ 가상 RF) + ArduPilot SITL · **PDCP EEA2/EIA2 + 종단(end-to-end) ARIA-256-GCM** · SGi측 GCS · 커스텀 웹 대시보드(로그 + 3D, 클라이언트 렌더).

> **상태: 분리코어(epc-split) + Rogue-UE = 19 컨테이너 · 원-커맨드 `bringup.sh` · 2026-07-08**

> ⚠️ **범위·안전 경고 (Scope & Safety)**
> - 본 테스트베드는 **인가된 격리 샌드박스의 SITL(software-in-the-loop) 전용**이다. **실기체(real airframe)가 아니다.**
> - ZMQ 가상 RF·SITL·격리 컨테이너 네트워크 안에서만 동작하며, 공격/방어 실행은 이 인프라 랩의 설계 대상이 아니다(비행은 시각화 확인용).
> - 시크릿(`.env-aria` ARIA-256-GCM 키 · `.mav-sign-key` MAVLink v2 서명키 · USIM `K`/`OPc`)은 **격리 샌드박스 테스트값**(실 방산 비밀 아님)이나, **공개 git 업로드 금지 · 키 반출 금지 · 비공개 전송(scp) 전용**이다.

이 문서 하나로 **접속 → 생성 → 검증 → 운영/관측 → 복구 → 트러블슈팅**까지 전 과정을 수행할 수 있도록 재구성했다(자립형 매뉴얼). 변경 이력만 `CHANGELOG.md`로 분리한다.

---

## 목차 (파트 구성)

1. 개요 · 디렉터리 구조 · 게이트(G0~G5)
2. 사전 준비 · 접속(SSH · 대시보드 터널 · IP 가변 대응)
3. 테스트베드 생성 — (A) 원-커맨드 / (B) 신규 인스턴스 2-스텝 배포
4. 검증 · 성공 판정
5. 운영 · 관측 · 비행
6. 복구 — 리부팅 / AMI 복원 후 C2 살리기
7. 트러블슈팅 · 오탐(false negative)
8. 절대금지 · 비용 가드
9. 변경 이력(링크)

---

## 파트 1 — 개요 · 구조 · 게이트

### 문서 맵
| 문서 | 내용 |
|------|------|
| **`README.md`** (이 문서) | **자립형 통합 매뉴얼**(접속·생성·검증·운영·복구·트러블슈팅 전량) |
| `OPERATIONS.md` | 운영 런북 원본(참조용, 본 README에 통합됨) |
| `RECOVERY_C2_AFTER_RESTORE.md` | AMI 복원 후 C2 복구 절차 원본(검증본, 본 README 파트 6에 통합됨) |
| `../testbed-split/DEPLOY_NEW_INSTANCE.md` | 신규 인스턴스 2-스텝 배포 원본(본 README 파트 3-B에 통합됨) |
| `CHANGELOG.md` | 변경 이력 |

> 설계·과정 문서(ARCHITECTURE · CONFIG_SPEC · AWS_SETUP · ROADMAP · STATUS · SEPARATED_CORE_ROADMAP)는 `~/_testbed_설계문서_archive/` 및 로컬 `DAH2026_문서모음/06`으로 분리했다. 값 소스(configuration source)는 `CONFIG_SPEC.md`.

### 디렉터리 구조 (단계 매핑)
```
testbed/
  scripts/00-server-setup.sh # P0: 서버 셋업(docker/sctp/tun, idempotent)
  scripts/01-preflight.sh    # P0: 프리플라이트 검증(docker/sctp/tun/자원)
  .env.example               # P0: 설정값(→ .env 복사, 비밀 비커밋)
  .gitattributes             # P0: LF 강제(.sh CRLF 오염 예방)
  images/air/                # P1: SITL+ARIA 이미지 Dockerfile
  compose/                   # P2+: docker-compose (EPC/RAN/SITL/proxy/GCS/web)
  gps/                       # P5: GPS 인젝터 (v1 gps_inject.py seed, 10Hz)
  gcs/                       # P6: 능동 GCS (pymavlink, sysid=255)
  proxy/                     # P7: ARIA-GCM 프록시 (v1 mav_aria_proxy.py seed)
  web/backend/ web/frontend/ # P8: 대시보드 (FastAPI+ws / CesiumJS 3D)
```

### 게이트(Gate) G0~G5 — 전 게이트 통과(완성)
| 게이트 | 내용 | 결과 |
|--------|------|------|
| G0 | RAN attach + PDCP EEA2(AES) | ✅ |
| G1 | 데이터 베어러 + SGi 직접 라우팅 | ✅ |
| G2 | SITL + GPS fix | ✅ |
| G3 | 평문 C2-over-cellular | ✅ |
| G4 | ARIA-256-GCM 종단 암호 | ✅ |
| G5 | 웹 대시보드(로그+3D) | ✅ |

---

## 파트 2 — 사전 준비 · 접속

> 서버: AWS EC2 (c6i.4xlarge · Ubuntu 24.04) · 키 `<key.pem>` · 코드 `~/testbed/`.

### SSH 접속
```bash
ssh -i <key.pem> ubuntu@<server-ip>
# 대시보드 터널 포함(-L 8080):
ssh -i <key.pem> -L 8080:127.0.0.1:8080 ubuntu@<server-ip>
#  → 브라우저 http://localhost:8080  (CesiumJS 3D + 로그)
```

### IP 가변(EIP 미사용) 대응
> ⚠ IP가 바뀌면(Elastic IP 미사용, stop/start 후) **AWS 콘솔에서 새 IP를 확인**한다. 옛 IP가 `known_hosts`에 남아 SSH 호스트키 경고가 뜨면 정리:
```bash
ssh-keygen -R <옛IP>     # known_hosts에서 옛 IP 항목 제거
```

---

## 파트 3 — 테스트베드 생성

현재 구성 = **분리코어(epc-split) + Rogue-UE(2셀/2UE) = 19 컨테이너**. (구 `up-all.sh`/단일-epc는 **사용 금지** — 파트 8 참조.)

### A) 기존 서버 / 재시작·AMI 복원 후 — 원-커맨드
```bash
bash ~/testbed-split/bringup.sh --check   # 비파괴 사전검증(권장) → CHECK PASS
bash ~/testbed-split/bringup.sh           # 19 컨테이너를 '검증된 순서'로 콜드스타트
```
`bringup.sh` 흐름: 네트워크 → 분리코어 EPC → 가입자 2명(uav + attacker) → **RAN(eNB→20s→UE 순차, ZMQ desync 회피)** → SGi 라우트 → **ARIA lockstep** → web → G4/G5 검증. 근거 순서: 파트 6(복구 절차).

> 리부팅/AMI 복원/stop-start 후 C2가 죽어 있는데 `bringup.sh`로도 안 살아나면 → 파트 6(복구 절차)의 명령 시퀀스를 따른다.

### B) 신규 인스턴스 — 2-스텝 배포 (ARIA·서명 키까지 동일)

목적: 새 EC2 인스턴스에서 **기존과 동일한 테스트베드**(분리코어 EPC + RAN 2셀/2UE + SITL + ARIA + web, 19 컨테이너)를 재현한다. ARIA·서명 키까지 동일하게 전송 → 이후 공격/방어 에이전트 배포·실행 시 **키불일치 오류 0**.

**STEP 0 — (기존 서버에서 1회) 배포 패키지 생성**
```bash
bash ~/testbed-split/package.sh          # → ~/dah-testbed-deploy.tgz (소스 + 시크릿)
```
패키지 내용: `testbed/`(compose·configs·scripts·images/Dockerfile·**.env-aria**·**.mav-sign-key**) + `testbed-split/`(bringup.sh 등). `.bak`/logs/.git 제외.

**STEP 1 — 전송 + 전개**
```bash
scp -i <key.pem> ~/dah-testbed-deploy.tgz ubuntu@<new-ip>:~/
ssh -i <key.pem> ubuntu@<new-ip>
tar xzf ~/dah-testbed-deploy.tgz -C ~/     # → ~/testbed + ~/testbed-split (키 포함)
```

**STEP 2 — 시스템 준비(docker/SCTP/TUN) 후 ★재로그인**
```bash
bash ~/testbed/scripts/00-server-setup.sh
```
설치: docker.io + **SCTP 커널모듈**(S1AP 필수, 부팅영속) + **TUN** + docker compose 플러그인 + docker 그룹.
> ⚠️ **여기서 반드시 재로그인**(docker 그룹 활성화 — 같은 세션에선 docker 무-sudo 안 먹음):
> ```bash
> exit
> ssh -i <key.pem> ubuntu@<new-ip>
> ```

**STEP 3 — 테스트베드 생성 (원-커맨드)**
```bash
bash ~/testbed/scripts/01-preflight.sh           # (선택) docker/compose/SCTP/TUN 확인
bash ~/testbed-split/bringup.sh --check          # (권장) 비파괴 사전검증 → CHECK PASS
bash ~/testbed-split/bringup.sh                  # 이미지 자동빌드 + 19 컨테이너 검증 순서 기동
```

**동일성 범위 (정직 · honest scope)**
| 항목 | 동일? |
|---|---|
| 19 컨테이너 구성·토폴로지·포트 | ✅ 완전 동일(소스 결정) |
| **ARIA 키·서명 키** | ✅ 동일(`.env-aria`·`.mav-sign-key` 전송) → **에이전트 배포 시 키불일치 0** |
| UE풀 tun IP(`10.45.0.x`) | 동적 할당(재시작마다 변동) — **정찰로 특정, 하드코딩 금지** |
| 접속 IP(Elastic IP) | 인스턴스별 상이 — **에이전트 config의 `host`만 교체** |

> 원본 상세: `../testbed-split/DEPLOY_NEW_INSTANCE.md`. 실패 시 파트 6(복구) 절차로 RAN/ARIA lockstep 재적용.

---

## 파트 4 — 검증 · 성공 판정

### bringup 말미 자동 검증
- `bringup` 말미 **G4(`71-verify-aria`) · G5(`81-verify-web`)** 통과. (22/41은 monolithic 오탐이라 제외 — 파트 7 참조.)

### 성공 판정 3항 (복구/생성 공통)
- **양방향 C2:** `gcs_c2` 로그에 **`✓ DOWNLINK HEARTBEAT` + `✓ UPLINK ACK` + `✓ PARAM roundtrip`** = 양방향 C2 성립.
- **G4(암호):** `71-verify-aria.sh` 통과 — 셀룰러 `14555`에 **ARIA 암호문**이 흐르고 평문 `14550`은 없음.
- **G5(대시보드):** `81-verify-web.sh` 통과 — 대시보드 **`pos_rate ≥ 1Hz`**, 드론 위치/HB/GPS fix 라이브.

### 안정성 관찰
- `docker logs -f gcs_c2`를 **2~3분** 지켜봐 "양방향 성립"이 유지되면(연속 텔레메트리가 베어러를 살림) 완료.

### 대시보드
```bash
ssh -i <key.pem> -L 8080:127.0.0.1:8080 ubuntu@<ip>   # → http://localhost:8080
```

---

## 파트 5 — 운영 · 관측 · 비행

### 개별 단계 (디버깅용) 스크립트 표
| 단계 | 기동 | 검증(게이트) |
|------|------|--------------|
| EPC | `20-epc-up.sh` + `21-provision.sh` | `22-verify-epc.sh` |
| RAN attach | `30-ran-up.sh` | `31-verify-ran.sh` (G0) |
| SGi 라우팅 | `40-sgi-up.sh` | `41-verify-sgi.sh` (G1) |
| SITL+GPS | `50-sitl-up.sh` | `51-verify-sitl.sh` (G2) |
| 평문 C2(대안) | `60-c2-up.sh` | `61-verify-c2.sh` (G3) |
| ARIA 암호 | `70-aria-up.sh` | `71-verify-aria.sh` (G4) |
| 웹 대시보드 | `80-web-up.sh` | `81-verify-web.sh` (G5) |

> ⚠ 전체 종료는 `down-all.sh` 계열도 **`--remove-orphans` 없이** 사용한다(파트 8 금지 참조). 이미지·mongo 볼륨은 보존된다.

### 자주 쓰는 관측 6종
```bash
docker ps --format '{{.Names}}\t{{.Status}}'          # 전체 상태
docker logs -f gcs_c2                                  # C2 왕복(HB/ACK/PARAM)
docker logs uav_gps | tail                             # GPS 주입율
docker exec uav_ue ip -o -4 addr show tun_srsue        # UE 셀룰러 IP(10.45.0.x)
docker exec uav_ue tcpdump -ni tun_srsue udp port 14555 -c5   # 셀룰러 ARIA 암호문
docker exec ran_enb grep -i "Selected EEA" /tmp/enb.log       # PDCP 암호 협상
docker exec web_backend python3 -c 'import urllib.request;print(urllib.request.urlopen("http://127.0.0.1:8080/stats").read().decode())'   # web /stats
```

### 비행 (텔레메트리/3D 관측용, C2 통해)
```bash
# GCS netns(gcs_proxy)에서 arm→takeoff→land 를 pymavlink로 (SITL은 serial1 tcp:5762도 개방)
docker run -i --rm --network container:uav_ue dahv2/air python3 -c "
from pymavlink import mavutil, time
m=mavutil.mavlink_connection('tcp:127.0.0.1:5762'); m.wait_heartbeat()
m.set_mode_apm('GUIDED'); ...  # arm/takeoff 예시는 별도"
```
> ※ 공격/방어 실행은 이 인프라 랩의 대상이 아님(설계상 제외). 비행은 **시각화 확인용**.

---

## 파트 6 — 복구 (리부팅 / AMI 복원 후 C2 살리기)

> **분리코어(epc-split) 배포 전용.** 실측으로 검증(C2 양방향 + G4/G5 통과 + 2.5분 무붕괴 확인). 값 소스 `CONFIG_SPEC.md`.

### §0. 증상 & 근본 원인 (왜 이 절차가 필요한가)
**AMI 복원/리부팅/stop-start 후, 컨테이너는 전부 `Up`이지만 C2(셀룰러 MAVLink)가 죽어 있다.**
- 부팅 직후 ~1분간은 attach 상태(UPF 세션 2, C2 잠깐 성립)였다가, **UE가 RRC IDLE로 빠지며 detach → UPF/SGWU 세션 2→0 → 셀룰러 SGi 포워딩(PDR/FAR) 소실 → C2 영구 다운.**
- 대시보드(8080)는 뜨지만 텔레메트리 0Hz(빈 지도). `gcs_c2`가 "✗ UAV HEARTBEAT 미수신(셀룰러 C2 불통)" 반복 + 재시작 루프.
- 원인: **RAN 라디오 attach는 재부팅/복원 후 자동으로 살아나지 않는다.** RRC 유휴 타이머 튜닝 knob은 없음 — 안정성은 **기동 순서 + lockstep 재생성 + 연속 텔레메트리**로만 확보된다.

### §2. ✅ 검증된 복구 절차 (이 순서 그대로)
```bash
cd ~/testbed

# ── (선택) EPC가 불안정하면 의존순서로 재시작 후 정합 확인 ──
docker restart epc_hss epc_pcrf epc_upf epc_sgwu; sleep 6
docker restart epc_sgwc epc_smf;                 sleep 6
docker restart epc_mme;                          sleep 10
docker logs epc_hss 2>&1 | grep "CONNECTED TO 'mme.localdomain'" | tail -1   # S6a OK
docker logs epc_upf 2>&1 | grep "PFCP associated" | tail -1                  # PFCP OK

# ── 1) netns 공유 컨테이너 먼저 stop (uav_ue를 rm 하려면 필수) ──
docker stop uav_sitl uav_gps uav_proxy

# ── 2) eNB·UE 둘 다 rm -f  (stale ZMQ endpoint 제거 = 핵심) ──
docker rm -f ran_enb uav_ue

# ── 3) eNB 먼저 up → 20초 대기 → 그다음 UE  (ZMQ desync 방지) ──
docker compose -f compose/docker-compose.ran.yml up -d ran_enb
sleep 20
docker compose -f compose/docker-compose.ran.yml up -d uav_ue
#   attach 확인 (10.45.0.x 나올 때까지 최대 ~60s):
docker exec uav_ue ip -o -4 addr show tun_srsue

# ── 4) SGi 라우트 재적용 (uav_ue 재생성으로 소실됨) ──
docker exec uav_ue  ip route replace 172.30.0.0/24 dev tun_srsue
docker exec sgi_test ip route replace 10.45.0.0/16 via 172.30.0.2
docker exec uav_ue ping -c2 172.30.0.10        # → 0% loss 여야 정상

# ── 5) ARIA C2 lockstep (SITL+GPS+proxy + gcs 함께 재생성) ──
bash scripts/70-aria-up.sh

# ── 6) 검증 (SITL 부팅 ~40s 후) ──
docker logs --tail 5 gcs_c2                     # "✓ … 양방향 C2 성립"
bash scripts/71-verify-aria.sh                  # G4 통과
bash scripts/80-web-up.sh                       # 대시보드 (8080)
```

### §3. 성공 판정
- `gcs_c2` 로그: **`✓ DOWNLINK HEARTBEAT` + `✓ UPLINK ACK` + `✓ PARAM roundtrip` = 양방향 C2 성립**
- `71-verify-aria.sh` **G4 통과** (셀룰러 14555에 ARIA 암호문 흐름, 평문 14550 없음)
- `81-verify-web.sh` **G5 통과** — 대시보드 `pos_rate ≥ 1Hz`, 드론 위치/HB/GPS fix 라이브
- **안정성:** `docker logs -f gcs_c2`로 2~3분 지켜봐 "양방향 성립"이 유지되면(연속 텔레메트리가 베어러를 살림) 복구 완료. (지난 실패 때는 ~1분에 붕괴했음.)

### §5. 왜 이 순서인가 (근거표)
| 단계 | 이유 |
|------|------|
| eNB·UE **둘 다 rm** 후 **eNB→20s→UE** | 한쪽만 재생성하면 상대가 구 ZMQ endpoint에 물려 desync. 둘 다 지우고 eNB가 먼저 떠서 UE가 붙을 셀을 준비해야 함 |
| SGi 라우트 **재적용** | `tun_srsue`·역경로는 재시작 시 소실 → up-script가 다시 넣어야 UE↔SGi(gcs_proxy 172.30.0.10) 도달 |
| ARIA **lockstep** (`70-aria-up`) | SITL·GPS·proxy가 `uav_ue` netns 공유 → uav_ue 재생성 후 함께 재생성해야 정합. GPS 10Hz + HEARTBEAT 1Hz **연속 흐름이 베어러를 살려 detach 재발 방지** |

> 원본: `RECOVERY_C2_AFTER_RESTORE.md`.

---

## 파트 7 — 트러블슈팅 · 오탐

### 트러블슈팅 표
| 증상 | 해결 |
|------|------|
| G0 attach 실패(tun 없음) | PLMN/IMSI/K/OPc 불일치(`CONFIG_SPEC`) · sctp 미로드 · ZMQ desync(30은 eNB→8s→UE 순차) |
| G2 GPS fix=0 | uav_sitl + uav_gps **함께 재생성**(lockstep). `docker compose -f compose/docker-compose.uav.yml up -d --force-recreate` |
| G4 셀룰러에 평문 노출 | uav_proxy/gcs_proxy 미가동 or 키 불일치(`.env-aria`) |
| 디스크 full | srsue 로그 폭증 — `docker exec uav_ue truncate -s 0 /tmp/ue.log` + RAN 재기동(warning 설정) |
| 대시보드 접속 안 됨 | 포트 루프백 전용 — SSH `-L 8080` 터널 필수(파트 2) |
| SGi ping 실패 | epc net_sgi(172.30.0.2) 연결 + SGi 호스트 역경로 확인(40) |

### 알아둘 오탐(false negative) / 무해한 것
- `22-verify-epc` · `41-verify-sgi`는 **✗로 뜬다** — 옛 monolithic `epc` 컨테이너를 찾기 때문(split엔 `epc_upf` 등). **C2(G4)가 통과하면 EPC/SGi는 실제로 정상.** 실기능 게이트 G0·G2·G4·G5만 보면 됨.
- 드론 `5762` 직접관측이 `Connection refused`여도 C2·대시보드와 무관(관측 도구 이슈). 드론은 **8080 대시보드**로 본다.

---

## 파트 8 — 절대금지 · 비용 가드

### ⚠️ 절대금지 (어기면 ZMQ desync / 코어 오염 — 실증됨)
- ❌ **`up-all.sh` / `docker-compose.epc.yml`** — 구 **단일-epc(monolithic) 전용**. split 배포와 "Address already in use" 충돌(`set -e` 중단, epc_mongo 오염). **split 정본은 `bringup.sh`이며 up-all.sh는 사용하지 않는다.**
- ❌ **eNB와 UE 동시 재생성/재시작** → **ZMQ RF desync**. 증상: UE가 `Found Cell` 없이 `Attaching UE…`에서 멈춤, MME에 `InitialUEMessage` 없음, `Holding S1 Context`.
- ❌ **`docker compose … --remove-orphans`** → 프로젝트명 `dahv2` 공유로 다른 컨테이너(epc 등) 삭제. (orphan 경고 자체는 무해.)
- ❌ **`docker ps | grep …`로 컨테이너 kill/stop** → 정상 프록시(uav_proxy/gcs_c2 등이 python3로 실행)를 오폭.

### 비용 가드
- 미사용 시 인스턴스 **stop**(컴퓨트 0). 재기동 후 파트 3-A의 `bringup.sh`로 다시 기동.
- ⚠ **terminate 금지**(디스크·이미지 소멸).

---

## 파트 9 — 변경 이력

변경 이력은 통합하지 않고 별도 파일로 유지한다: **[`CHANGELOG.md`](CHANGELOG.md)**.

원본 운영 문서(참조용): [`OPERATIONS.md`](OPERATIONS.md) · [`RECOVERY_C2_AFTER_RESTORE.md`](RECOVERY_C2_AFTER_RESTORE.md) · [`../testbed-split/DEPLOY_NEW_INSTANCE.md`](../testbed-split/DEPLOY_NEW_INSTANCE.md)
