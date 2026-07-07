# CHANGELOG — testbed (분리코어 + Rogue-UE)

## 2026-07-08 · 원-커맨드 생성 · 배포 · 문서 정리

### 원-커맨드 콜드스타트
- **`testbed-split/bringup.sh`** (+`--check` 비파괴 사전검증): 분리코어(epc-split)+Rogue-UE(2셀/2UE) **20 컨테이너**를 검증된 순서로 생성.
  네트워크 선생성 → 분리코어 EPC → 가입자 2명 → **RAN(eNB→20s→UE 순차, ZMQ desync 회피)** → SGi 라우트 → **ARIA lockstep** → web → G4/G5.
- 절대금지(`RECOVERY_C2_AFTER_RESTORE.md` §1) 내장 회피: monolithic `up-all.sh`/`docker-compose.epc.yml`, eNB·UE 동시 재생성, `--remove-orphans`.
- 근본 에러(문서화): RAN attach는 재시작 후 자동복구 안 됨(UE RRC IDLE→detach→C2 붕괴) → 순서·lockstep으로만 안정.

### 신규 인스턴스 배포 (2-스텝 · 키 동일)
- **`testbed-split/package.sh`** → `~/dah-testbed-deploy.tgz`(소스 + 시크릿 동봉).
- **`testbed-split/DEPLOY_NEW_INSTANCE.md`**: 전송 → `00-server-setup.sh`(재로그인) → `bringup.sh`.
- ARIA·서명 키 동봉 → 공격/방어 에이전트 배포 시 **키불일치 오류 0**.

### 문서 정리 (git엔 운영문서만)
- 설계·과정 문서 → `~/_testbed_설계문서_archive/` 및 로컬 `DAH2026_문서모음/06`으로 분리:
  `ARCHITECTURE.md · CONFIG_SPEC.md · AWS_SETUP.md · ROADMAP.md · STATUS.md · SEPARATED_CORE_ROADMAP.md`.
- 잔존(운영): `README.md`(실행법) · `OPERATIONS.md` · `RECOVERY_C2_AFTER_RESTORE.md` · `../testbed-split/DEPLOY_NEW_INSTANCE.md`.

### 배포 실행 검증 (2026-07-08 · 비파괴 최대)
- 배포 패키지를 신규 인스턴스처럼 임시 전개(68파일) → 문서 명령이 참조하는 스크립트·시크릿·이미지 Dockerfile(4) 전량 완비 확인.
- `bringup.sh`·`00-server-setup.sh` 구문 OK · `bringup.sh --check` = **CHECK PASS**(파일·compose·서비스·네트워크·provision 경로·금지패턴 전량 통과).
- ⚠ 미검증(설계상 불가): 실제 런타임 bringup 1회(RAN attach 타이밍·ZMQ 순차·C2 안정성)는 신규 인스턴스/재생성에서만 확증. 다만 순서는 검증된 `RECOVERY_C2_AFTER_RESTORE.md` + 현행 up-스크립트를 그대로 재사용.

### 시크릿 (⚠ 테스트값)
- `.env-aria`(ARIA-256-GCM 키) · `.mav-sign-key`(MAVLink v2 서명키) · USIM K/OPc(`ue.conf`·`ue2.conf`) = 격리 샌드박스 **테스트값**(실 방산 비밀 아님).
- 배포 패키지에 동봉(키 동일 목적) → **공개 git 업로드 금지**, 비공개 전송(scp) 전용.
