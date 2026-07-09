# 신규 인스턴스에 테스트베드 배포 (B안 · 2-스텝 · 키 동일)

> 목적: 새 EC2 인스턴스에서 **기존과 동일한 테스트베드**(분리코어 EPC + RAN 2셀/2UE + SITL + ARIA + web, 19 컨테이너)를 재현.
> ARIA·서명 키까지 **동일**하게 전송 → 이후 공격/방어 에이전트 배포·실행 시 **키불일치 오류 없음**.
> 근거: `RECOVERY_C2_AFTER_RESTORE.md`(검증 순서), `00-server-setup.sh`, `bringup.sh`.

---

## 0-A. git clone 배포 (권장 · 단독 실행 · 시크릿 자동생성) ★감독관용

**이 경로만으로 완결**된다(패키지·키 전송 불필요). 테스트베드가 자체 키를 생성하고 proxy sign/verify·ARIA·
에이전트가 **인스턴스 내 같은 키**를 쓰므로 C2·서명·배포가 전부 정합(키불일치 0). 새 인스턴스에서:

```bash
# ★ 수동 cp 불필요 — bringup 이 경로를 자기해석(testbed-split 형제 dir=testbed). clone 위치에서 바로 실행.
git clone https://github.com/Kjhyun04/dah2026 ~/dah2026
bash ~/dah2026/testbed/scripts/00-server-setup.sh   # docker+SCTP+TUN+python venv/openssl/curl
# ── ★반드시 재로그인 (docker 그룹): exit → 다시 ssh 접속 ──
bash ~/dah2026/testbed-split/bringup.sh             # 키 자동생성·sgi_test 재시도·경로 자기해석 → 이미지 빌드 + 19 컨테이너
docker logs -f gcs_c2                                # 2~3분 양방향 C2 유지 확인 (Ctrl-C)
# ── 방어 에이전트 ──
cd ~/dah2026/defense_agent && python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
./dah.sh verify && ./dah.sh test                     # ALL GATES PASS + 269 passed / 1 skipped
# .env 채움(cp .env.example .env) — ★키+모델 slug 만: 아무 플랫폼(OpenRouter/Anthropic/OpenAI/Gemini) 동작.
#   MDG_LLM_API_KEY=<키>  MDG_ORIENT_MODEL=<slug>  MDG_DECIDE_MODEL=<slug>
#   (예 OpenRouter: openrouter/anthropic/claude-sonnet-4.5 · OpenAI: openai/gpt-4o-mini · Anthropic: anthropic/claude-sonnet-4-5)
#   비우면 결정론 폴백(안전, advisory 침묵). SITL 데모: MDG_ALLOW_LIVE=1 MDG_OPERATOR_AUTO=1
sudo -E bash dah.sh monitor                          # 24/7 자율 감시 (netns 관측엔 sudo -E · 5762 DAH5762 계수 포착)
bash dah.sh viewer live_out/monitor/run.jsonl        # 실시간 뷰어(127.0.0.1:8787, 출력 URL 접속)
# ── 공격 에이전트 (동일 인스턴스, 자율 공방전) ──
cd ~/dah2026/attack_agent && python3 -m venv .venv && . .venv/bin/activate && pip install -e .
./dah.sh verify                                      # 11 게이트 ALL PASS
./dah.sh build-tools                                 # ★캠페인 전 1회: 툴링 사이드카 이미지 dahv2/air-tools 빌드(recon/주입 스크립트 baked)
# .env 채움 — ★키+모델 slug 만: LLM_MODEL=<slug>  LLM_API_KEY=<키>  TESTBED_HOST=127.0.0.1
#   (관례키 재사용 시 LLM_API_KEY_ENV=OPENROUTER_API_KEY. ARIA_KEY 는 testbed/.env-aria 자동해석)
./dah.sh campaign                                    # 자율 공방전 (기본 goal.land · LLM 계획 + 독립 감독)
```
> **시크릿 자동생성(자체정합):** `.mav-sign-key`(bringup 0-pre)·`.env-aria`(70-aria-up)가 없으면 fresh
> 64-hex로 생성되어 인스턴스 내 모든 컴포넌트가 동일 키를 쓴다. 방어 에이전트는 **key-free**(서명은 gcs_c2
> 위임)라 키를 쥐지 않는다. → **감독관은 위 명령만 입력하면 실행된다.** 키불일치 문제 없음.

> 아래 §0~§5(패키지 + '키 동일' 전송)는 **기존 서버와 키·아티팩트를 맞춰야 할 때만** 쓴다(옛 캡처 pcap
> 재사용·서버 간 상호통신 등). 단독 데모/제출 실행에는 위 **0-A**로 충분하다.

---

## 0. (기존 서버에서 1회) 배포 패키지 생성 — (§0~§5는 '키 동일' 연속성용, 선택)

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
bash ~/testbed-split/bringup.sh                  # 이미지 자동빌드 + 19 컨테이너 검증 순서 기동
```
`bringup.sh`가 하는 일: 네트워크 생성 → 분리코어 EPC → 가입자 2명 → **RAN(eNB→20s→UE 순차, ZMQ desync 회피)** → SGi 라우트 → **ARIA lockstep** → web → 검증. (상세: 스크립트 헤더 / `RECOVERY_C2_AFTER_RESTORE.md`)

## 4. 성공 판정 (bringup 말미 + 수동)

- `71-verify-aria.sh` **G4** · `81-verify-web.sh` **G5** 통과 (22/41은 monolithic 오탐이라 제외).
- **안정성**: `docker logs -f gcs_c2` 2~3분 관찰 → "양방향 C2 성립" 유지되면 완료.
- 대시보드: `ssh -i <key> -L 8080:127.0.0.1:8080 ubuntu@<new-ip>` → `http://localhost:8080` 텔레메트리 라이브.

## 5. 동일성 범위 (정직)

| 항목 | 동일? |
|---|---|
| 19 컨테이너 구성·토폴로지·포트 | ✅ 완전 동일(소스 결정) |
| **ARIA 키·서명 키** | ✅ 동일(.env-aria·.mav-sign-key 전송) → **에이전트 배포 시 키불일치 0** |
| UE풀 tun IP(10.45.0.x) | 동적 할당(재시작마다 변동) — 정찰로 특정, 하드코딩 금지 |
| 접속 IP(Elastic IP) | 인스턴스별 상이 — 에이전트 config의 host만 교체 |

## 6. 실패 시

`bringup.sh`가 C2까지 못 살리면 `RECOVERY_C2_AFTER_RESTORE.md` §2 절차로 RAN/ARIA lockstep 재적용. 절대금지(§1): eNB·UE 동시 재생성 / monolithic `up-all.sh`·`docker-compose.epc.yml` / `--remove-orphans`.
