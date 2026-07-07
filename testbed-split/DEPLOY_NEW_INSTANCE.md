# 신규 인스턴스에 테스트베드 배포 (B안 · 2-스텝 · 키 동일)

> 목적: 새 EC2 인스턴스에서 **기존과 동일한 테스트베드**(분리코어 EPC + RAN 2셀/2UE + SITL + ARIA + web, 20 컨테이너)를 재현.
> ARIA·서명 키까지 **동일**하게 전송 → 이후 공격/방어 에이전트 배포·실행 시 **키불일치 오류 없음**.
> 근거: `RECOVERY_C2_AFTER_RESTORE.md`(검증 순서), `00-server-setup.sh`, `bringup.sh`.

---

## 0. (기존 서버에서 1회) 배포 패키지 생성

```bash
bash ~/testbed-split/package.sh          # → ~/dah-testbed-deploy.tgz (소스 + 시크릿, 약 61KB)
```
패키지 내용: `testbed/`(compose·configs·scripts·images/Dockerfile·**.env-aria**·**.mav-sign-key**) + `testbed-split/`(bringup.sh 등). `.bak`/logs/.git 제외.

## 1. 전송 (로컬 → 신규 인스턴스)

```bash
scp -i <key.pem> ~/dah-testbed-deploy.tgz ubuntu@<new-ip>:~/     # 기존서버→로컬→신규, 또는 직접
ssh -i <key.pem> ubuntu@<new-ip>
tar xzf ~/dah-testbed-deploy.tgz -C ~/                            # → ~/testbed + ~/testbed-split (키 포함)
```

## 2. ★ STEP 1 — 시스템 준비 (docker/SCTP/TUN)

```bash
bash ~/testbed/scripts/00-server-setup.sh
```
설치: docker.io + **SCTP 커널모듈**(S1AP 필수, 부팅영속) + **TUN** + docker compose 플러그인 + docker 그룹.

> ⚠️ **여기서 반드시 재로그인** (docker 그룹 활성화 — 같은 세션에선 docker 무-sudo 안 먹음):
> ```bash
> exit
> ssh -i <key.pem> ubuntu@<new-ip>
> ```

## 3. ★ STEP 2 — 테스트베드 생성 (원-커맨드)

```bash
bash ~/testbed/scripts/01-preflight.sh          # (선택) docker/compose/SCTP/TUN 확인
bash ~/testbed-split/bringup.sh --check          # (권장) 비파괴 사전검증 → CHECK PASS
bash ~/testbed-split/bringup.sh                  # 이미지 자동빌드 + 20 컨테이너 검증 순서 기동
```
`bringup.sh`가 하는 일: 네트워크 생성 → 분리코어 EPC → 가입자 2명 → **RAN(eNB→20s→UE 순차, ZMQ desync 회피)** → SGi 라우트 → **ARIA lockstep** → web → 검증. (상세: 스크립트 헤더 / `RECOVERY_C2_AFTER_RESTORE.md`)

## 4. 성공 판정 (bringup 말미 + 수동)

- `71-verify-aria.sh` **G4** · `81-verify-web.sh` **G5** 통과 (22/41은 monolithic 오탐이라 제외).
- **안정성**: `docker logs -f gcs_c2` 2~3분 관찰 → "양방향 C2 성립" 유지되면 완료.
- 대시보드: `ssh -i <key> -L 8080:127.0.0.1:8080 ubuntu@<new-ip>` → `http://localhost:8080` 텔레메트리 라이브.

## 5. 동일성 범위 (정직)

| 항목 | 동일? |
|---|---|
| 20 컨테이너 구성·토폴로지·포트 | ✅ 완전 동일(소스 결정) |
| **ARIA 키·서명 키** | ✅ 동일(.env-aria·.mav-sign-key 전송) → **에이전트 배포 시 키불일치 0** |
| UE풀 tun IP(10.45.0.x) | 동적 할당(재시작마다 변동) — 정찰로 특정, 하드코딩 금지 |
| 접속 IP(Elastic IP) | 인스턴스별 상이 — 에이전트 config의 host만 교체 |

## 6. 실패 시

`bringup.sh`가 C2까지 못 살리면 `RECOVERY_C2_AFTER_RESTORE.md` §2 절차로 RAN/ARIA lockstep 재적용. 절대금지(§1): eNB·UE 동시 재생성 / monolithic `up-all.sh`·`docker-compose.epc.yml` / `--remove-orphans`.
