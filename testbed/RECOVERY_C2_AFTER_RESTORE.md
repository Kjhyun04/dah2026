# testbed-split — 리부팅 / AMI 복원 후 C2 복구 절차 (검증됨)

> 작성 2026-07-05. **분리 코어(epc-split) 배포 전용.** 실측으로 검증(C2 양방향 + G4/G5 통과 + 2.5분 무붕괴 확인).
> 값 소스 `CONFIG_SPEC.md` · 아키텍처 `../dah_attack/DAH2026_테스트베드_INFRA_아키텍처통신_LATEST-ROGUE-UE-R6_20260704.html`.

---

## 0. 증상 & 근본 원인 (왜 이 문서가 필요한가)

**AMI 복원/리부팅/stop-start 후, 컨테이너 19개는 전부 `Up`이지만 C2(셀룰러 MAVLink)가 죽어 있다.**
- 부팅 직후 ~1분간은 attach 상태(UPF 세션 2, C2 잠깐 성립)였다가, **UE가 RRC IDLE로 빠지며 detach → UPF/SGWU 세션 2→0 → 셀룰러 SGi 포워딩(PDR/FAR) 소실 → C2 영구 다운.**
- 대시보드(8080)는 뜨지만 텔레메트리 0Hz(빈 지도). `gcs_c2`가 "✗ UAV HEARTBEAT 미수신(셀룰러 C2 불통)" 반복 + 재시작 루프.
- 원인: **RAN 라디오 attach는 재부팅/복원 후 자동으로 살아나지 않는다**(문서화된 사실: `../testbed/testbed-4g/scripts/aws-resume.sh` 헤더, `../세션로그_2026-07-01_AWS이관-ARIA-G1.md §4`). RRC 유휴 타이머 튜닝 knob은 없음 — 안정성은 **기동 순서 + lockstep 재생성 + 연속 텔레메트리**로만 확보된다.

## 1. ⚠ 절대 금지 (이걸 어기면 더 망가진다 — 실증됨)

- ❌ **eNB와 UE를 동시에 재생성/재시작** → **ZMQ RF desync**. 증상: UE가 `Found Cell` 없이 `Attaching UE…`에서 멈춤, MME에 `InitialUEMessage` 없음, `Holding S1 Context`. (문서 §4-4 "가장 골치" 버그.)
- ❌ **`up-all.sh` / `docker-compose.epc.yml`** 실행 → 이건 **monolithic `epc` 컨테이너용**이라 split 배포와 충돌("Address already in use", `set -e` 중단, epc_mongo 오염).
- ❌ **`docker ps | grep …`로 컨테이너 kill/stop** → 정상 프록시(uav_proxy/gcs_c2 등이 python3로 실행)를 오폭.
- ❌ **`docker compose … --remove-orphans`** → 프로젝트명 `dahv2` 공유로 다른 컨테이너 삭제.

## 2. ✅ 검증된 복구 절차 (이 순서 그대로)

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

## 3. 성공 판정

- `gcs_c2` 로그: **`✓ DOWNLINK HEARTBEAT` + `✓ UPLINK ACK` + `✓ PARAM roundtrip` = 양방향 C2 성립**
- `71-verify-aria.sh` **G4 통과** (셀룰러 14555에 ARIA 암호문 흐름, 평문 14550 없음)
- `81-verify-web.sh` **G5 통과** — 대시보드 `pos_rate ≥1Hz`, 드론 위치/HB/GPS fix 라이브
- **안정성:** `docker logs -f gcs_c2`로 2~3분 지켜봐 "양방향 성립"이 유지되면(연속 텔레메트리가 베어러를 살림) 복구 완료. (지난 실패 때는 ~1분에 붕괴했음.)

## 4. 알아둘 오탐 / 무해한 것

- `verify-all.sh`의 **`22-verify-epc` · `41-verify-sgi`는 ✗로 뜬다** — 옛 monolithic `epc` 컨테이너를 찾기 때문(split엔 `epc_upf` 등). **C2(G4)가 통과하면 EPC/SGi는 실제로 정상.** 실기능 게이트 G0·G2·G4·G5만 보면 됨.
- 드론 5762 직접관측(`dah_exec/DEMO/demo_obs.py`)이 `Connection refused`여도 C2·대시보드와 무관(관측 도구 이슈). 드론은 **8080 대시보드**로 본다.
- 대시보드 접근: `ssh -i ~/Downloads/<KEY>.pem -L 8080:127.0.0.1:8080 ubuntu@<IP>` → `http://localhost:8080`.

## 5. 왜 이 순서인가 (요약)

| 단계 | 이유 |
|------|------|
| eNB·UE **둘 다 rm** 후 **eNB→20s→UE** | 한쪽만 재생성하면 상대가 구 ZMQ endpoint에 물려 desync. 둘 다 지우고 eNB가 먼저 떠서 UE가 붙을 셀을 준비해야 함 |
| SGi 라우트 **재적용** | `tun_srsue`·역경로는 재시작 시 소실 → up-script가 다시 넣어야 UE↔SGi(gcs_proxy 172.30.0.10) 도달 |
| ARIA **lockstep** (`70-aria-up`) | SITL·GPS·proxy가 `uav_ue` netns 공유 → uav_ue 재생성 후 함께 재생성해야 정합. GPS 10Hz + HEARTBEAT 1Hz **연속 흐름이 베어러를 살려 detach 재발 방지** |
