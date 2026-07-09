# sidecar/air — `dahv2/air-tools` 툴링 사이드카 (A/D 계층 · `./dah.sh build-tools`)

> 오프라인 골격 · 테스트베드 무접속 · 실제 `docker build`/scp/배포는 **통제단계**에서 수행.
> 근거: doc13(연결·vantage 실행모델) · doc14(타깃식별) · doc18(구현결정) · doc19(누수-안전 R1~R6).

## 1. 정체

`attacker_ue`(순수 rogue UE 라디오 엔드포인트, python3·nc 없음)에는 도구가 없다.
그래서 pymavlink 등 클라이언트 툴링을 **이 이미지에 baked** 하고,
**장수(long-lived) 사이드카**로 1회 기동한 뒤 host 실행기가 `docker exec` 로만 구동한다.

- `arducopter`/SITL 미포함 — 우리는 **클라이언트 측 툴링**만(서버 SITL 은 대상, 우리가 안 띄움).
- 이미지 1종을 두 vantage 가 공유(doc13 §2):
  - `tools_ue`  = `--network container:attacker_ue`(rogue UE netns 공유 → UE풀·net_cellular 시야)
  - `tools_sgi` = `net_sgi` 연결(D 계층 SGi vantage)

## 2. 실행 모델 (netns 공유 + `docker exec`, 누수 0)

```
[agent 컨테이너] --/var/run/docker.sock--> docker exec --> [dahv2/air-tools 사이드카] --(baked script)-->
```

- **금지(하드):** `docker run --rm` 단명 사이드카 · ENTRYPOINT 자동 공격실행 · SSH.
  대신 장수 사이드카(CMD `sleep infinity`) + `docker exec`(doc13 §2, 종료계약).
- **netns 공유:** `tools_ue` 는 `--network container:attacker_ue` 로 rogue UE 의 netns 를
  공유한다(UE-to-UE 로 uav 5762 · net_cellular 도달). 사이드카는 대상 컨테이너를 오염시키지
  않는다(별 컨테이너, netns 만 공유).
- **동적 IP:** UE풀 10.45.x 는 런타임 가변 → 하드코딩 금지. init 이 `docker inspect`/
  `docker exec <name> ip -br addr show tun_srsue` 로 해석(doc14 §3).

## 3. 누수-안전 불변식(R1~R6)이 이미지에 요구하는 것

| 불변식 | 이미지 제공 | 실행기(host) 책임 |
|--------|-------------|-------------------|
| **R1** in-container timeout + JOB 마커 kill | `coreutils`(timeout) · `util-linux`(setsid) · `procps`(pkill) | `docker exec $SC sh -c "exec -a $JOB setsid timeout -s TERM -k 5 $T <script> > /tmp/out.$JOB 2>&1"` · 회수=`pkill -KILL -f $JOB`(마커, 넓은 grep 금지) |
| **R2** 라벨 + teardown + reap | 이미지 라벨 `org.dah.image=dahv2/air-tools` | 컨테이너 라벨 `dahv2.owner=agent`,`dahv2.run_id=$RUN` 을 `docker create/run --label` 로 부여 · 부팅 reap(우리 라벨만) |
| **R3** preflight | vendor `aria_gcm.py` COPY · openssl aria-256-gcm **build-time 확인** · pymavlink 핀(ARG) | init 이 사이드카 안에서 aria-256-gcm 확인 + placeholder sentinel 부재 확인 + pymavlink 버전 정합 + golden-frame 1회 |
| **R5** reaper 백스톱 | `iproute2`(ss) · `procps`(pkill) | 10s 마다 5762 established>1 이면 `pkill -KILL -f job_` · 5762 단일 TCP(세마포어=1) |
| **R6** 비밀 stdin | 스크립트가 `--<name>-stdin` 로 stdin 수신(비밀 baked 금지) | vault→`printf %s "$SECRET" | docker exec -i $SC <script> --<name>-stdin` |

> **PIPE 데드락 회피:** `docker exec` 출력은 컨테이너 내부에서 **파일**(`/tmp/out.$JOB`)로
> 리다이렉트하고 실행기가 파일/스트림으로 읽는다(`subprocess` PIPE 캡처 금지, doc19).

## 4. vendor / baked 스크립트 채움 (★ 통제단계에서만)

이 저장소는 테스트베드 무접속이므로 두 슬롯을 **비워 두고 참조만** 한다.
`docker build` 전에 통제단계에서 read-only scp 로 채운다:

1. **`vendor/aria_gcm.py`** — 현재 **placeholder**(import 시 예외 · sentinel
   `__DAH_VENDOR_PLACEHOLDER__=True`). 통제단계에서
   `testbed/proxy/mav_aria_proxy.py` 의 `AriaGCM` + ARIA 봉투 파서만 추출(doc18 D8:
   전체복사 아님, 원본 경로·해시 주석)하여 **덮어쓴다**. 실 파일로 교체되면 sentinel 이
   사라져 R3 preflight 통과.
2. **`exec/`** — baked 공격 스크립트 트리(경로=registry `script`). `exec/README.md` 참조.
   dah_attack 공격 코퍼스에서 read-only scp 로 채운다.

## 5. build (참고 · 통제단계 명령, 여기서 실행하지 않음)

```bash
# 통제단계에서 vendor/aria_gcm.py 와 exec/ 를 scp 로 채운 뒤:
docker build \
  --build-arg PYMAVLINK_VERSION="$(python3 -c 'import pymavlink,importlib.metadata as m; print(m.version("pymavlink"))')" \
  -t dahv2/air-tools ./sidecar/air
```
> ★ 편의: `./dah.sh build-tools` 가 위 빌드(host pymavlink 버전 핀)를 대신 수행한다.
> ★ 태그는 `dahv2/air-tools` — 테스트베드 SITL 이미지 `dahv2/air`(arducopter 포함)와 **태그 충돌 회피**.

- `PYMAVLINK_VERSION` 은 **host 주입기와 동일 버전**으로 맞춘다(R3 ③).
- `config.tools.image.air = dahv2/air-tools`(configs/config.*.yaml) 가 이 태그를 가리킨다.
- init 은 라벨/이름이 이미 있으면 build/기동을 스킵(doc18 C6, "config만 채우면 실행").

## 6. 정직성 노트

- 이 디렉터리는 **이미지 정의(Dockerfile)와 채움 계약**만 담는다. 공격 스크립트·ARIA
  구현 자체는 여기서 생성하지 않는다(오프라인 · 통제단계 vendor).
- vendor/exec 가 채워지지 않은 상태로 사이드카를 기동하면 R3 preflight 가 실패하여
  해당 계층 실행이 봉쇄된다(허위 실행 방지).
