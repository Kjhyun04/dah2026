"""recon_boot (PA-1) — OUT-OF-GRAPH 일회성 부트. DefInputSpec 로부터 state0 구성:
role->container->IP 2단계 해석+검증 (H-I; UE-pool tun IP 은 라이브 netns 스캔으로,
A-1), signing/NAS/port/IP-map 베이스라인, ledger+seq HWM 복구. 틱 그래프에는
recon 노드가 없다.

부트 베이스라인 (P2 범위):
  - signing : 관측 자세는 SigningObs.UNKNOWN 로 시작 (P2-Q2 3상태, "off" 아님).
    §9-B signing 은 라이브로 강제되지만, 이는 uav_proxy 권위 신호
    (drop-log / ON-banner / /api/signing) 로 P3+ collector 에서만 CONFIRMED 되며 —
    gcs_proxy env 로는 절대 판정하지 않고, drop-부재는 OFF 증거가 아니다 (MEMORY 오판 가드). recon 은
    out-of-graph 이고 로그 tail 을 하지 않으므로, 부트 시 확인 소스의 부재는
    구조적으로 옳다. spec.signing_expected 는 정책 기대값(EXPECTATION)
    (신뢰 사전값)을 담으며 관측된 강제 상태를 절대 승격시키지 않는다 (expected≠observed).
  - NAS     : 위협 도메인은 "none" 으로 시드 (clean 자세); NAS-cipher 이상은 이후
    MME 로그에서 관측된다 (P4-5).
  - ports   : closed reach 어휘는 False 로 시드 (collector 가 True 로 관측).
  - ip map  : role->container->IP 는 라이브 해석 (resolve_targets); UE-pool IP 는 동적이며
    config 에서 절대 고정하지 않는다 (A-1).

PS-6 순서: recover_on_boot (ledger/seq HWM) 이 sense drain 이전에 여기서 실행된다.
"""
from __future__ import annotations

from ..config import loader
from ..targets.behavioral import apply_behavioral_verification
from ..targets.inputspec import DefInputSpec
from ..targets.resolve import ResolveResult, resolve_targets
from .state import MDGState, initial_state
from .worldstate import Baseline, SigningObs, WorldState

# 도메인은 clean 베이스라인 자세로 시드 (NAS/command/등 = 부트 시 이상 없음).
_BASELINE_DOMAINS = ["communication", "identity_access", "session_network", "command", "mission"]


def recon_boot(cfg: dict | None = None, seqwm=None, ledger=None, docker=None,
               backend=None, spec: DefInputSpec | None = None) -> MDGState:
    """tick-0 MDGState 를 구성한다. docker (duck-typed inspect) + backend (safe-exec)
    가 라이브 role/IP 해석을 가능케 한다; 둘 다 없으면 => config-only 불활성 베이스라인.

    spec 은 로드된 DefInputSpec 을 덮어쓴다 (테스트). 모든 라이브 해석은 read-only 이며
    operator-go 안전: non-allow_live Backend 는 DRY-RUN 을 반환하므로, UE-pool tun IP 는
    지어내지 않고 미해석 상태(verified False)로 남는다.
    """
    spec = spec or DefInputSpec.load(cfg.get("input_spec") if cfg else None)
    thr = loader.thresholds()
    config_version = spec.config_version or loader.config_version()

    # PS-6: sense drain 이전에 seq HWM 재로드 + 누출된 intent 복구 (G3).
    if seqwm is not None:
        seqwm.recover_on_boot()
    if ledger is not None:
        ledger.recover_on_boot()

    state = initial_state(config_version)

    world = WorldState(
        config_version=config_version,
        reach=spec.initial_reach(),                       # closed 어휘, 전부 False
        signing=SigningObs.UNKNOWN,                        # 관측 자세 미확인; 기대값은 spec 에 (P2-Q2)
        threat={d: "none" for d in _BASELINE_DOMAINS},    # clean NAS/자세 베이스라인
        baseline=Baseline(
            rtt_baseline_ms=float(thr.get("rtt_baseline_ms", 27.7)),
            rtt_mdev_ms=float(thr.get("rtt_mdev_ms", 11.0)),
        ),
    )

    # H-I role->container->IP 2단계 해석 (read-only; tun 스캔은 operator-go).
    result: ResolveResult = resolve_targets(spec, docker=docker, backend=backend)
    world.roles.update(result.bindings)
    world.pid.update(result.pidmap)
    world.ip_map.update(result.ip_map)
    world.imsi_container.update(result.imsi_container)         # static IMSI->container 부트 맵 (P4 stale-binding 교차검증)
    world.role_verified.update(result.role_verified())        # RESOLVED/PRESENT (적법성 술어)

    # Behavioural verify (finding P2-1): 각 role 의 verify_anchor 를 별개인
    # behaviorally_verified 술어로 소비한다. 부트 시엔 라이브 anchor 증거가 없으므로
    # (탭은 operator-go), 전부 False 로 시드 — presence 를 behavioural
    # verify 로 과장하지 않는다. 런타임은 관측이 도착하는 대로 collector/effect-confirm
    # 단계에서 라이브 AnchorEvidence 를 공급한다 (targets/behavioral.apply_behavioral_verification).
    world.behaviorally_verified.update(apply_behavioral_verification(spec.roles, evidence=None))

    state["worldstate"] = world
    return state
