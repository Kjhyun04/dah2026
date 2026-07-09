# attack_agent 배포·실행·점검 런북 (Safe Verification)

이 문서는 **인가된 격리 테스트베드**에서 `attack_agent`를 배포하고,  
**비침투 검증(verify + recon-only)** 을 수행할 때의 표준 절차를 정리한다.

- 목적: 배포 재현성, 실행 안정성, 점검 일관성 확보
- 범위: 환경 배포/기동, 검증 실행, 실행 중 상태 확인, 종료/정리
- 제외: 공격/주입 실행 절차(INJECT/full 공격 체인)

---

## 1. 사전 준비

### 로컬(운영자 PC)
- 프로젝트 경로: `C:\Users\user\Desktop\dah\dah_attack\attack_agent`
- SSH 키: `C:\Users\user\Downloads\<KEY>.pem`
- PowerShell에서 `tar`, `ssh` 사용 가능해야 함

### 원격(테스트베드 서버)
- 접속 계정 예: `ubuntu@<TESTBED_IP>`
- Python 3.12+
- Docker 접근 권한(필요 시 `docker` 그룹)

---

## 2. SSH 연결 확인

```powershell
ssh -i "C:\Users\user\Downloads\<KEY>.pem" ubuntu@<TESTBED_IP>
```

웹 점검이 필요하면 로컬 터널:

```powershell
ssh -i "C:\Users\user\Downloads\<KEY>.pem" -L 8080:localhost:8080 ubuntu@<TESTBED_IP>
```

---

## 3. 코드 배포

로컬 PowerShell에서 프로젝트를 서버 홈에 전송:

```powershell
tar -czf - -C "C:\Users\user\Desktop\dah\dah_attack" attack_agent `
| ssh -i "C:\Users\user\Downloads\<KEY>.pem" ubuntu@<TESTBED_IP> "cd ~ && tar -xzf -"
```

서버에서 확인:

```bash
cd ~/attack_agent
ls
```

---

## 4. 서버 환경 구성

```bash
cd ~/attack_agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

환경 기본값 자동 주입(비밀값 제외):

```bash
# (env 기본값은 dah.sh 에 내장)
```

필수 환경변수(export):

```bash
export LLM_MODEL="openrouter/anthropic/claude-sonnet-4"   # 아무 플랫폼 slug (openai/gpt-4o 등)
export LLM_API_KEY="..."                                  # provider 무관 키값(관례키 재사용 시 LLM_API_KEY_ENV 지정)
export ARIA_KEY="..."
```

확인:

```bash
python - <<'PY'
import os
print("LLM_API_KEY:", bool(os.getenv("LLM_API_KEY") or os.getenv("OPENROUTER_API_KEY")))
print("ARIA_KEY:", bool(os.getenv("ARIA_KEY")))
PY
```

---

## 5. 사전 검증

```bash
python verify.py   # 8개 게이트 단일 러너
```
 (반드시 선실행)

```bash
cd ~/attack_agent
source .venv/bin/activate
python supervisor/verify_grep0.py
python viewer/verify_viewer.py
```

기준:
- 전부 `PASS` 또는 `ALL CHECKS PASSED`
- 실패 시 실행 중단, 실패 로그부터 수정

---

## 6. 실행 (비침투 검증 모드)

기본 실행(오프라인/검증, 기본값: `recon-only + no-llm`):

```bash
python run.py --config configs/config.testbed.yaml --goal goals/goal.testbed.yaml
```

산출 파일 확인:

```bash
ls -l run*.jsonl evaluation*.json supervisor*.jsonl
```

---

## 7. 실행 중 체크리스트

### 프로세스/리소스
```bash
ps -ef | rg "python|run.py|run_live_gate5.py" || true
free -h
df -h
```

### Docker 상태
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
```

### 출력 로그 증가/오류 감시
```bash
tail -n 50 -f run.jsonl
```

별도 터미널에서:

```bash
rg -n "Traceback|ERROR|CRSError|Exception" run*.jsonl evaluation*.json supervisor*.jsonl
```

### 단일 연결 민감 포트(예: 5762) 점검
```bash
ss -antp | rg 5762 || true
```

판단 기준:
- 비정상적으로 연결 수가 누적되지 않아야 함
- 실행 종료 후 잔여 프로세스/컨테이너가 계속 증가하면 즉시 중단 후 원인 분석

---

## 8. 종료 및 정리

1) 실행 프로세스 종료 확인

```bash
ps -ef | rg "run.py|run_live_gate5.py" || true
```

2) 산출물 백업(타임스탬프 디렉토리 권장)

```bash
mkdir -p runs/archive_$(date +%Y%m%d_%H%M%S)
cp -a run*.jsonl evaluation*.json supervisor*.jsonl runs/archive_$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
```

3) 필요 시 위생 검증 재실행

```bash
```

---

## 9. 장애 대응 기본 원칙

- `verify_*` 실패 상태로 실행 진행하지 않는다.
- 런타임 오류 발생 시:
  1. 마지막 200줄 로그 확보
  2. 환경변수/경로/권한 점검
  3. 동일 입력으로 재현되는지 확인
- 임시 우회보다 원인 수정 우선(재현 가능성 유지)
