# DAH testbed v2 — 운영 런북

> 서버: AWS EC2 (c6i.4xlarge · Ubuntu 24.04) · 키 `~/Downloads/<KEY>.pem` · IP 가변(EIP 권장).
> 코드: `~/testbed/`. 값 소스: `CONFIG_SPEC.md`.

## 접속
```bash
ssh -i ~/Downloads/<KEY>.pem ubuntu@<서버IP>
# 대시보드 터널 포함:
ssh -i ~/Downloads/<KEY>.pem -L 8080:localhost:8080 ubuntu@<서버IP>
#  → 브라우저 http://localhost:8080  (CesiumJS 3D + 로그)
```
> ⚠ IP가 바뀌면(EIP 미사용, stop/start 후) 콘솔에서 새 IP 확인. `ssh-keygen -R <옛IP>`로 known_hosts 정리.

## 기동 / 검증 / 종료
```bash
cd ~/testbed
bash scripts/up-all.sh        # 전체 기동 (EPC→가입자→RAN→SGi→ARIA→웹, ~4분)
bash scripts/verify-all.sh    # G0~G5 전 게이트 검증
bash scripts/down-all.sh      # 전체 종료 (이미지·mongo 볼륨 보존)
```
> ⚠ **`docker compose ... --remove-orphans` 절대 금지** — 프로젝트명이 dahv2로 공유돼 다른 컨테이너(epc 등)를 지웁니다. orphan 경고는 무해.

> 🔴 리부팅/AMI 복원/stop-start 후 C2가 죽어 있으면 → up-all.sh 쓰지 말고 RECOVERY_C2_AFTER_RESTORE.md 절차를 따르세요. AMI 복원 후 RAN attach·C2 자동 미복구(부팅 ~1분 내 UE detach). eNB·UE 동시 재생성 금지(ZMQ desync).

## 개별 단계 (디버깅용)
| 단계 | 기동 | 검증(게이트) |
|------|------|--------------|
| EPC | `20-epc-up.sh` + `21-provision.sh` | `22-verify-epc.sh` |
| RAN attach | `30-ran-up.sh` | `31-verify-ran.sh` (G0) |
| SGi 라우팅 | `40-sgi-up.sh` | `41-verify-sgi.sh` (G1) |
| SITL+GPS | `50-sitl-up.sh` | `51-verify-sitl.sh` (G2) |
| 평문 C2(대안) | `60-c2-up.sh` | `61-verify-c2.sh` (G3) |
| ARIA 암호 | `70-aria-up.sh` | `71-verify-aria.sh` (G4) |
| 웹 대시보드 | `80-web-up.sh` | `81-verify-web.sh` (G5) |

## 자주 쓰는 관측
```bash
docker ps --format '{{.Names}}\t{{.Status}}'          # 전체 상태
docker logs -f gcs_c2                                  # C2 왕복(HB/ACK/PARAM)
docker logs uav_gps | tail                             # GPS 주입율
docker exec uav_ue ip -o -4 addr show tun_srsue        # UE 셀룰러 IP
docker exec uav_ue tcpdump -ni tun_srsue udp port 14555 -c5   # 셀룰러 ARIA 암호문
docker exec ran_enb grep -i "Selected EEA" /tmp/enb.log       # PDCP 암호 협상
docker exec web_backend python3 -c 'import urllib.request;print(urllib.request.urlopen("http://127.0.0.1:8080/stats").read().decode())'
```

## 비행 (텔레메트리/3D 관측용, C2 통해)
```bash
# GCS netns(gcs_proxy)에서 arm→takeoff→land 를 pymavlink로 (SITL은 serial1 tcp:5762도 개방)
docker run -i --rm --network container:uav_ue dahv2/air python3 -c "
from pymavlink import mavutil, time
m=mavutil.mavlink_connection('tcp:127.0.0.1:5762'); m.wait_heartbeat()
m.set_mode_apm('GUIDED'); ...  # arm/takeoff 예시는 별도"
```
> ※ 공격/방어 실행은 이 인프라 랩의 대상이 아님(설계상 제외). 비행은 시각화 확인용.

## 트러블슈팅
| 증상 | 해결 |
|------|------|
| G0 attach 실패(tun 없음) | PLMN/IMSI/K/OPc 불일치(CONFIG_SPEC) · sctp 미로드 · ZMQ desync(30은 eNB→8s→UE 순차) |
| G2 GPS fix=0 | uav_sitl+uav_gps **함께 재생성**(lockstep). `docker compose -f compose/docker-compose.uav.yml up -d --force-recreate` |
| G4 셀룰러에 평문 노출 | uav_proxy/gcs_proxy 미가동 or 키 불일치(`.env-aria`) |
| 디스크 full | srsue 로그 폭증 — `docker exec uav_ue truncate -s 0 /tmp/ue.log` + RAN 재기동(warning 설정) |
| 대시보드 접속 안 됨 | 포트 루프백 전용 — SSH -L 8080 터널 필수 |
| SGi ping 실패 | epc net_sgi(172.30.0.2) 연결 + SGi 호스트 역경로 확인(40) |

## 비용 가드
미사용 시 인스턴스 stop(컴퓨트 0). 재기동 후 `up-all.sh`. ⚠ terminate 금지(디스크·이미지 소멸).
