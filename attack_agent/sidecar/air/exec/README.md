# exec/ — baked 공격 스크립트 트리 (VENDOR SLOT · 통제단계 채움)

이 디렉터리는 `dahv2/air` 사이드카에 baked 되는 스크립트 트리의 **자리표시자**다.
이 워크플로우(오프라인·테스트베드 무접속)에서는 실제 스크립트를 생성하지 않는다.

`core/modules/registry.py` 의 `exec_binding.script` 경로(=exec_binding 정본, doc18 C5)가
여기에 대응한다. `air` 사이드카(sidecar ∈ {ue, sgi})가 참조하는 트리:

```
exec/
  dah_exec/
    R4_UE_ENTRY/recon_ue_entry.sh
    R5_ROGUE_ATTACK/{read_mode.py, atk_direct5762.py}
    A_TM1/{tm1_inject_oracle.py, tm1_naive_blocked.py}
    B_TM2_V3/v3_attacker.py
    C_TM3_V1_V4_V5/{extract_downlink.py, v4_forge.py, v1_replay.py, analyze_tm3_v5.py}
    DEMO/sign_mode.py
  ext_exec/
    N3_SUBDB/{subdb_dump.sh, subdb_canary.sh}
    N4_WEBCMD/webcmd_inject.py
    N6_SIGNKEY/{signkey_exposure.sh, sign_forge.py}
```

통제단계(control stage)에서 read-only scp 로 dah_attack 공격 코퍼스에서 채운 뒤
`docker build` 한다. 이 저장소에는 트리를 만들지 않는다(경로 계약만 문서화).

주의(R6): `sign_forge.py`·`v4_forge.py`·`v1_replay.py` 는 비밀(sign_key/aria_key/
ciphertext)을 **argv 가 아니라 stdin** 으로 받아야 한다(registry `secret_params`).
스크립트는 `--<name>-stdin` 규약으로 stdin 을 읽고, 이미지에 비밀을 baked 하지 않는다.
