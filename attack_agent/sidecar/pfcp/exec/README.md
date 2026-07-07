# exec/ — baked PoC 스크립트 트리 (VENDOR SLOT · 통제단계 채움)

`dahv2/pfcp-poc` 사이드카에 baked 되는 스크립트 트리의 **자리표시자**다.
오프라인 워크플로우에서는 실제 스크립트를 생성하지 않는다.

`core/modules/registry.py` 에서 `sidecar="core"` 인 스크립트가 여기에 대응한다:

```
exec/
  core_exec/
    D_TM2_PFCP/{learn_seid.py, pfcp_delete.py, pfcp_flood.py}
    E_TM3_S1U/capture_s1u.sh
    F_TM2_LATERAL/pivot_exploit.sh
```

통제단계(control stage)에서 read-only scp 로 채운 뒤 `docker build` 한다.
이 저장소에는 트리를 만들지 않는다(경로 계약만 문서화).
