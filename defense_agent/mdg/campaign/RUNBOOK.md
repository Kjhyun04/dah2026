# RUNBOOK — MDG E2E 캠페인 라이브 실집행 절차 (operator-go)

> 지위: 본 문서는 **라이브 상태변경을 수반하는 실집행 절차**를 정의한다. `mdg/campaign/e2e.py`
> 하네스는 기본 **DRY(operator-go 유보)**로만 동작하며, 아래 절차는 **operator가 명시적으로
> 승인·집행**할 때에만 유효하다. 2대 불변식·운영제약 우선.
>
> 운영제약(절대): testbed `<TESTBED-IP>` 상태변경 자동실행 금지 — DROP·docker pause·서명명령·
> 컨테이너 stop·설정수정·설치 금지. 관측은 read-only SSH만:
> `ssh -i "~/.ssh/<KEY>.pem" ${TESTBED} "<read-only cmd>"`.

---

## 0. 실집행이 유보된 항목 (부록B — 코드+dry까지만 확정)

| 항목 | 코드 상태 | 실집행 게이트 |
|---|---|---|
| PS-4 egress allowlist iptables 실적용 | compose/정책 파일 | operator-go |
| 모든 actuation (nsenter DROP·docker pause·docker net-disconnect) | ExecRequest 조립·DRY | GATE1 누수0 실측 + GATE2 효력 |
| escalate/act 서명명령 발행 (send_signed_mode) | record_intent(operator-gate) 까지 | operator-go (gcs_c2 out-of-band, /sign.key 재마운트 금지) |
| tmpfs 0400 시크릿 실마운트·operator/verifier 프로세스 배치 | compose 정책 | operator-go |

`Backend.allow_live=False`가 코드레벨 가드다. 아래 절차 없이 `allow_live=True`로 뒤집는 것을 금지.

---

## 1. 사전조건 (PRECONDITIONS — 전부 충족 전 집행 금지)

1. **인가.** 인가된 격리 샌드박스 보안평가 범위 내 · operator 서면 승인(decision_id 스코프).
2. **GATE0 통과.** `python -m pytest mdg/tests -q` 및 `mdg/verify/verify_*` 전부 PASS
   (형식·계약·불변식① 라우팅·불변식② 노드 subprocess 0).
3. **GATE1 누수-0 실측 준비.** `IntentLedger`/`SeqWatermark` durable 경로가 0600·비공유 볼륨에
   존재하고 `recover_on_boot`가 sense 드레인 이전에 실행되도록 부팅 순서 확정(PS-6).
4. **DRY 사전검증.** 본 캠페인을 DRY로 완주:
   `python -m mdg.campaign.e2e <out_dir>` → `report.json`의 `chapters.1.live_state_changes == 0`,
   각 attack `run.jsonl`이 viewer fail-closed scan 통과(secret-free, PS-3) 확인.
5. **가역성 확인.** 집행 대상 응답이 `reversible=True`(nsenter DROP·docker pause). 비가역
   (send_signed_mode/flight)은 이 RUNBOOK 범위 밖 — 별도 operator 서명 콘솔.
6. **타깃 검증.** dispatch가 `dry_argv`(inert 아님)를 만들려면 `enforce_at`·`source`가 서로 다른
   **VERIFIED WorldState 바인딩**으로 풀려야 한다(P4-Q1/P4-2). 미검증 셀렉터는 self-DoS 방지를 위해
   구조적으로 inert-DRY. 라이브 UE-pool src IP는 stage-2 tun-scan(read-only)로만 확정.

---

## 2. 안전 원칙 (SAFETY)

- **최소권한.** 라이브 집행 프로세스는 `nsenter-helper`(CAP_NET_ADMIN[+SYS_ADMIN])만 보유.
  core/orient/decide/signer는 docker.sock·프록시 URL·docker sdk 미참조(verify_no_sock_in_core).
- **단일 subprocess 경로.** 모든 부작용은 `Backend.run(ExecRequest)` 경유(불변식②). 노드/collector
  직접 spawn 0.
- **read-only 우선.** 관측(ss/tcpdump/docker logs/inspect/:9090)은 상태변경 아님 — 자유 실행 가능.
- **2-endpoint 봉쇄.** DROP은 enforcement netns(chokepoint)와 source(attacker)가 **서로 다른**
  검증 엔드포인트일 때만 argv 생성. 같은 엔드포인트/미해석 → inert-DRY(자기격리 no-op 차단, PS-7).
- **operator 명령바인딩.** OPER 응답은 `(decision_id, command_digest, nonce, expiry)` HMAC로
  스코프 바인딩(PS-9). 캡처 승인은 다른 command_digest 승인 불가.
- **egress.** MDG egress는 `api.anthropic.com:443` + 관측 대상 내부망만. 그 외 DROP(PS-4).

---

## 3. 집행 순서 (per-response, 가역 AUTO 기준)

각 응답은 `act` 노드 계약 순서를 따른다(PA-6): **legality 선체크 → record_intent(guard 밖) →
tool_wrap(Backend.run)**.

1. **legality 재확인.** 현재 WorldState + `config_version`(X7 TOCTOU 핀)으로 재검증. 불법 → 부작용 0.
2. **record_intent (실행 전 항상).** `Intent{rule, revert_cmd, ts, decision_id, config_version,
   command_digest}`를 durable JSONL + ledger 채널에 **먼저** 기록. → 크래시 시 `recover_on_boot`가
   revert 근거 보유(G3).
3. **operator 승인 대기 (OPER tier).** docker_pause / docker_net_disconnect / 서명명령은 tier-2 OPER
   → 자동 집행 금지. operator가 command_digest 검증 후에만 out-of-band로 발행.
4. **집행 (AUTO tier, `allow_live=True`).** nsenter DROP만 자율 집행 가능. 다음 명령 형태:
   ```
   nsenter --target <enforce_pid> --net -- iptables -I INPUT -s <attacker_src_ip> -j DROP
   ```
   `enforce_pid`는 chokepoint netns(inspect .State.Pid, read-only), `attacker_src_ip`는 stage-2
   tun-scan로 확정된 UE-pool IP. 둘은 반드시 distinct.
5. **effect_confirm.** act 직후 관측 델타(ss/pcap/:9090 s5c_rx_deletesession diff / 14560 HB /
   uav_ue lo:14550 교차탭 / **5762 백도어 소켓 상태**) 재관측 → `applied[rule].confirmed`. 실행
   게이트 아님(이미 실행됨, D-3). A4 응답의 경우 `ss -tnp state established '( dport = :5762 or
   sport = :5762 )'`(또는 `docker exec web_backend ss`)로 5762 ESTAB 세션이 pause 후 사라졌는지
   read-only 확인.
6. **독립 검증.** `run.jsonl`을 별 프로세스 Verifier로 접어 truth 산출:
   `python -m mdg.verifier.verifier <run.jsonl> --out truth.jsonl`. agent≠truth 발산 여부 확인(H-K).

---

## 4. 가역·복원 (REVERT / RESTORE)

모든 가역 응답은 record_intent 시 `revert_cmd`를 선기록한다. 복원은 역순:

| 응답 | 집행 | 복원(revert) |
|---|---|---|
| `nsenter_input_drop` | `... iptables -I INPUT -s <ip> -j DROP` | `... iptables -D INPUT -s <ip> -j DROP` |
| `docker_pause` (OPER) | `POST /containers/<id>/pause` (sock-proxy) | `POST /containers/<id>/unpause` |
| `docker_net_disconnect` (OPER) | net disconnect | net reconnect (원 network·IP 복원) |
| `send_signed_mode` (OPER, 비가역) | gcs_c2 서명발행 | 자동 revert 없음 — operator LAND/RTL 수동 |

복원 절차:
1. **부팅 시 자동 정리.** `boot_recover(ledger, seqwm, backend, revert_fn, op_ledger)`가 이전 run의
   미완 가역 Intent를 스캔해 `revert_fn`(safe-exec)으로 정리(G3). operator_gate Intent는 revert 대상
   제외(부작용 0이었음).
2. **수동 전체 복원.** operator가 `intent_ledger.jsonl`을 역순 순회하며 각 `revert_cmd`를
   `Backend.run(ExecRequest(reversible=True))`로 집행. docker pause는 unpause, DROP은 -D.
3. **검증.** 복원 후 read-only로 상태 확인: `iptables -S`(체인 비움), `docker ps`(paused 0),
   :9090 카운터 정상화, lo:14550 HEARTBEAT 재개, **5762 백도어 소켓 clean**. 5762 clean 명시 앵커
   (A4_5762_backdoor 잔존 세션 0 확인, read-only):
   ```
   ss -tnp state established '( dport = :5762 or sport = :5762 )'   # 잔존 ESTAB 0 이어야 함
   #  또는 컨테이너 내부: docker exec web_backend ss -tnp state established '( sport = :5762 )'
   ```
   docker_pause(web_backend) OPER tier 복원(unpause) 후 위 ss 출력이 공집합이어야 A4 백도어
   ESTAB 세션 잔존 0. 비공집합이면 §5 ABORT — 백도어 소켓이 재복원되었음을 의미.
4. **비가역 잔여.** 서명명령/flight-mode는 자동 revert 불가 — operator가 지상국에서 LAND/RTL 수동
   지시. FLIGHT_ACTION_AUTO_REVERT=False(설계 고정).

---

## 5. 중단·롤백 트리거 (ABORT)

즉시 중단하고 §4 복원을 개시하는 조건:
- self-DoS 징후: 정상 UE/operator IP가 DROP 대상에 포함(타깃 검증 실패) → 즉시 revert.
- agent≠truth 발산이 예상 밖으로 급증(Verifier truth = SILENCE인데 agent가 계속 actuate).
- 누수 감지: 크래시 후 미완 Intent 잔존 / 라벨된 좀비 프로세스(R4 reap 실패).
- 범위 이탈: 승인 decision_id 스코프 밖 command_digest 발행 시도(PS-9 거부).

롤백 = §4 수동 전체 복원 + `Backend.allow_live=False`로 되돌림 + operator 보고.

---

## 6. 실행 커맨드 요약

```bash
# DRY 캠페인 (기본, 상태변경 0) — 사전검증
python -m mdg.campaign.e2e ./campaign_out
#   -> ./campaign_out/<attack_id>/run.jsonl, ./campaign_out/report.json

# 독립 Verifier (별 프로세스, replay 전용, core 미import)
python -m mdg.verifier.verifier ./campaign_out/A6_telemetry_silence/run.jsonl --out truth.jsonl

# 3패널 뷰어 (loopback·bearer 토큰, read-only) — 심사원 재생
MDG_VIEWER_TOKEN=<tok> python -m mdg.viewer.app ./campaign_out/A1_command_hijack_cr01/run.jsonl --host 127.0.0.1 --port 8787

# GATE0 회귀
python -m pytest mdg/tests -q
```

라이브 집행(`allow_live=True`)은 §1 사전조건 전부 충족 + operator 서면 승인 후에만. 승인 없이는
DRY로만 사용한다.
