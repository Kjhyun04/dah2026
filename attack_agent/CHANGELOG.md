# CHANGELOG — attack_agent

## 2026-07-10 · 5762 직결 주입 벡터 제거

- **제거:** `serial5762` 주입 tool · `./dah.sh land` 서브커맨드 · `land_demo.py` · `goals/goal.land.yaml`. (5762 관측/정찰 벡터와 `forceland` 강제착륙 tool 은 유지.)
- **enabler 레지스트리 6 → 5**(`naive`·`oracle`·`webcmd`·`forge`·`forceland`), **ToolSpec 총수 23 → 22**(tool 3자 정합).
- **campaign 기본 goal `goal.land` → `goals/goal.example.yaml`**(mode_set mode=4 GUIDED — 방어가 탐지 가능한 능동주입).

## 2026-07-08 · 재구성 · 보안 · 검증 강화

### 구조 정리 (GitHub 배포 대응)
- 루트 파일 → 디렉터리화: `config*.yaml`→`configs/`, `goal*.yaml`→`goals/`, `verify_*.py`→`tests/`.
- **단일 셸 진입점 `dah.sh`** (`verify|recon|campaign|land|viewer|status`) — 캠페인·착륙 오케스트레이션 내장(별도 .sh 제거).
- **단일 게이트 러너 `verify.py`** (= `./dah.sh verify`).
- 개발·세션 문서는 저장소 밖 `../DAH2026_문서모음/`으로 분리 → git엔 운영문서만(README·QUICKSTART·docs/{DESIGN,DEPLOY_VERIFY_RUNBOOK}).
- `.gitignore`(.venv·캐시·runs·출력물·`.env*`·`*.pem`) + `.gitattributes`(LF 강제) + `pyproject.toml` 의존성.

### 검증 게이트 8 → 11
- 신규 `tests/verify_structure.py`: 데드코드 0 · 모듈 docstring · 하드코딩 리터럴 0(tokenize 주석/문자열 제외).
- 신규 `tests/verify_prompt.py`: 레시피 금지 불변식 · Jinja StrictUndefined 실렌더 · tool 3자 정합(REGISTRY·ToolId·yaml, 23개).
- 신규 `tests/verify_quality.py`: 타입힌트 완전(119함수 0누락) · CLI 스키마 · 구조↔문서 · 비밀 리터럴 0 · 언어정책 · 스텁↔문서(은폐금지). *(P8=수동 리뷰)*
- 정적 감사 반영: 미사용 import 제거, `types.py`/`registry.py` BOM 제거(ast docstring 복원).

### 보안 (비밀·서버정보 외부화)
- 배포 의존값(테스트베드 IP·SSH키)·비밀 → **`.env`** 외부화. `core/common/config.py`의 `_load_yaml`에 `${VAR:-default}` env 치환 추가.
- `configs/*.yaml`: `host/user/ssh_key` → `${TESTBED_HOST/USER/SSH_KEY}`. 실 IP·키파일명 전수 genericize(주석 포함).
- `.env.example`(템플릿, 커밋) + `.env`(실값, gitignore), `dah.sh`가 `.env` 자동 로드.
- 감사 결과: **git 추적 파일에 실제 키값·서버 IP 0**.

### 실측 결과 (프로토타입)
- **GATE5 라이브 LLM 캠페인**: agent 자기보고 ↔ 독립 감독 ground-truth 일치(`autonomy_accuracy.agree=True`, decrypted_frames=36219, modes[4,5]). Differential BlockProof.
- **지속 착륙 시각화**: 5762 직결 LAND(9)·비복원 → 대시보드 Altitude 49.64m→0(3중 증거).
- **배포 실행 검증**(2026-07-08, 최종): 새 `git clone`(107파일·.venv/.env 없음) → `pip install -e .`(rc=0) → `./dah.sh verify` **11/11 PASS** → `./dah.sh recon` 정상. `.env` 외부화 후에도 `config host=127.0.0.1` 기본값으로 동작(하드코딩·비밀 0). **문서 명령만으로 즉시 실행 확정.**

### 정직성
- README §6.5 알려진 한계 명시: `forge_aria`/`forge_sign` 스텁(실 crypto 미구현), pfcp 기본 제외.
