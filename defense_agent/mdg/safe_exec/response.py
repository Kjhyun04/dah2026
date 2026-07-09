"""response.py — Response Controller: ``act`` 그래프 노드와 safe-exec 백엔드 사이의
dispatch 계층.

선택된 Intent 에 대해 순서대로 적용:
  1. bundle discipline (core.bundle): 멱등 applied()-skip, 이어서 N-tick debounce. 두 경로 모두 SKIP 으로 끝난다.
  2. 2-tier gate (core.gate): AUTO 도구 -> live 작동 계획; OPER 도구 (flight / docker
     pause / net-disconnect) -> operator_required (작동 없음; act 는 signer_shim 이 바인딩한
     operator-gate Intent 를 기록, side-effect 0).
  3. AUTO 도구 (``nsenter_input_drop``)에 대해 act_host 를 통해 netns-DROP ExecRequest 를 만든다.

유일한 subprocess 경로는 ``Backend.run`` 으로 유지된다 (불변식2.) — 이 컨트롤러는 argv 만 조립하여
넘긴다. Live 작동은 operator-go 유보 (Backend.allow_live=False -> DRY-RUN)이므로,
``dispatch`` 는 operator 가 플래그를 뒤집기 전까지 테스트베드에서 아무것도 바꾸지 않는다. 컨트롤러는
docker sdk import 도, sock 리터럴도 보유하지 않는다 (act_host 가 docker 백엔드를 duck-type).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..core import bundle as bundle_mod
from ..core import gate as gate_mod
from ..core.state import Intent
from ..core.worldstate import WorldState
from .act_host import ActHost
from .backend import Backend, ExecRequest, ExecResult
from .signer_shim import emit_signed


@dataclass
class ResponsePlan:
    """선택된 하나의 Intent 에 대한 dispatch 결정 (pure — 아직 side effect 없음)."""
    rule: str
    tool_id: str
    tier2: str                       # "AUTO" | "OPER"
    skip: bool = False               # 멱등 / debounce -> no-op
    operator_required: bool = False  # OPER tier -> operator 로 위임 (side-effect 0)
    operator_auto_confirmed: bool = False  # Phase 1: sandbox operator_auto 로 OPER 가 auto 로 확장됨
    exec_request: Optional[ExecRequest] = None
    pause_container: str = ""         # Phase 4: operator_auto docker_pause 대상 (act_host.pause)
    signed_intent: Optional[Intent] = None  # send_signed_mode: KEY-FREE emit 대상 (emit_signed)
    revert_cmd: str = ""
    reason: str = ""


class ResponseController:
    """safe-exec 백엔드 위에서 대응을 계획하고 (AUTO 의 경우) dispatch 한다."""

    def __init__(self, backend: Optional[Backend] = None, docker=None,
                 gate=None, min_ticks: Optional[int] = None,
                 act_host: Optional[ActHost] = None, smf_table=None,
                 operator_auto: bool = False):
        self.backend = backend or Backend(allow_live=False)     # operator-go 유보 기본값
        self.act_host = act_host or ActHost(backend=self.backend, docker=docker)
        self.gate = gate                                        # 선택적 OperatorGate (binding)
        self.min_ticks = min_ticks
        # Phase 1 (sandbox demo): True 일 때 2-tier gate 가 등록된 OPER 도구를 auto 로 확장하여
        # (docker_pause / flight recovery) OPER 회복 경로가 위임 대신 실행되게 한다.
        # 결정론적 (env bool), 투명성은 GateDecision.registry_tier 로 보존 (불변식1.).
        self.operator_auto = bool(operator_auto)
        # LIVE SMF 세션 테이블 (SmfSessionTable, ``imsi_for_ip(ip)->imsi|None``) — 선택적. 배선되면
        # (그래프 밖 collector 가 소유), ip-kind 소스 selector 가 live IMSI<->tun-IP 바인딩과
        # 교차 확인되어, 탐지와 강제 사이에 재할당된 UE-pool IP 가
        # 거부된다 (P4 stale-binding, 재할당 IP self-DoS 차단). 부재 -> best-effort recon 전용 확인.
        self.smf_table = smf_table

    # -- P1: 보호 대상 관측/C2 인프라 shield (결정론적, 불변식1.) --------------- #
    @staticmethod
    def _infra_shielded(tool_id: str, enforce_at: str) -> bool:
        """True -> 컨테이너 전체 파괴형 도구 (docker_pause / docker_net_disconnect)가
        보호 대상 관측/C2 컨테이너 (web_backend 대시보드 / gcs_proxy C2
        chokepoint)를 무너뜨릴 것 -> 호출자는 반드시 plan 을 inert 해야 한다. 순수 config 집합
        소속 (defaults.INFRA_DESTRUCTIVE_TOOLS × PROTECTED_INFRA_CONTAINERS); LLM 필드 없음, live
        해석 없음 — 적대적 조언은 도구 집합도 컨테이너 집합도 넓힐 수 없다.
        수술적/keyed 대응 (nsenter_input_drop '-s <attacker>' DROP, gcs_proxy 를 통한
        send_signed_mode emit)은 파괴형 도구 집합에 없으므로, 실제 위협 회복은
        보존된다 (pfcp_firewall/mongo_acl nsenter DROP 영향 없음)."""
        from ..config import defaults as _D
        if tool_id not in _D.INFRA_DESTRUCTIVE_TOOLS:
            return False
        return (enforce_at or "").strip() in _D.PROTECTED_INFRA_CONTAINERS

    # -- 대상 해석: 검증된 WorldState 바인딩 맵으로의 PURE LOOKUP (P4-Q1) --- #
    @staticmethod
    def _binding_verified(sel: str, world: WorldState) -> bool:
        """selector KEY 는 어떤 DROP argv 도 만들어지기 전에 검증된 RoleBinding 으로 해석되어야 한다.

        Verified = resolve.py 검증 술어 (inspect 존재 ∧, UE-pool 의 경우 tun IP 가
        pool CIDR 내부 — stage-2 의 ground truth). 위조/미지 selector (operator IP,
        pool 밖 리터럴, 미검증 role, 미투영 IMSI)는 어떤 검증 바인딩과도 매치되지 않음 ->
        호출자는 inert DRY 로 간다. Fail-closed: 맵 부재 -> False.
        """
        if not sel:
            return False
        if (world.role_verified or {}).get(sel) is True:
            return True
        for rb in (world.roles or {}).values():
            if rb.verified and sel in (rb.role, rb.container, rb.ip):
                return True
        return False

    @staticmethod
    def _verified_container_for_ip(ip: str, world: WorldState) -> str:
        """최신 recon 바인딩 (world.roles tun-scan, ip_map 역방향)에서 현재 ``ip`` 를 소유하는
        recon 귀속 엔티티 (검증된 RoleBinding 컨테이너), 없으면 "".

        이는 P4 stale-binding 교차 확인을 위한 "원래 귀속 엔티티" ground truth 이다: UE-pool
        IP 는 여기서 검증 바인딩에 여전히 매핑되는 동안에만 drop 가능한 소스이다. Fail-closed:
        부재/미검증 -> "".
        """
        if not ip:
            return ""
        for rb in (world.roles or {}).values():
            if rb.verified and rb.ip == ip:
                return rb.container or rb.role
        # ip_map 역방향 (ip -> container) 폴백 (resolve 가 ip_map[ip]=container 구성, C-3)
        return (world.ip_map or {}).get(ip, "") or ""

    def _source_ip_still_attributed(self, ip: str, world: WorldState) -> bool:
        """ip-kind raw 소스를 위한 P4 stale-binding 가드: ``ip`` 가 recon 이 검증한 것과 여전히
        같은 엔티티에 귀속되는가? UE-pool IP 는 attach 마다 순환하므로, 탐지 시점에 포착된
        공격자 IP 가 강제 시점에는 무고한 UE 의 것일 수 있음 -> 그것을 drop 하면 피해자를 self-DoS 한다.

        독립적인 두 교차 확인, 둘 다 fail-closed:
          (a) 최신 recon 바인딩 (world.roles/ip_map): IP 는 여전히 검증된 귀속
              컨테이너로 해석되어야 한다. 사라짐/미검증 -> stale -> False.
          (b) LIVE SMF 세션 테이블 (``self.smf_table``, 선택적): 배선되면 IP 는 여전히
              live-bound (``imsi_for_ip`` non-None)이어야 AND — 정적 IMSI->container 맵이
              알려져 있을 때 (world.imsi_container) — (a)와 같은 컨테이너로 해석되어야 한다. 해제된 IP
              (unbound)나 다른 컨테이너로 재할당된 IP 는 stale -> False. 테이블 부재
              -> best-effort (a) 전용 (smf_table 은 아직 live act 경로에 연결되지 않음).
        """
        boot_container = ResponseController._verified_container_for_ip(ip, world)
        if not boot_container:
            return False                                   # (a) no current verified attribution
        smf = self.smf_table
        if smf is None:
            return True                                    # best-effort: recon 바인딩 재확인됨
        try:
            cur_imsi = smf.imsi_for_ip(ip)                 # live IMSI<->tun-IP (SmfSessionTable)
        except Exception:                                  # 조회 결함이 작동시켜선 안 됨 -> inert
            return False
        if not cur_imsi:
            return False                                   # 세션 사라짐: IP 해제됨/재할당 가능
        imsi_container = world.imsi_container or {}
        if imsi_container:                                 # live IMSI 를 컨테이너로 재귀속 가능
            live_container = imsi_container.get(cur_imsi, "")
            if not live_container or live_container != boot_container:
                return False                               # 다른 엔티티로 재할당됨 -> stale
        return True

    def _resolve_endpoints(self, intent: Intent, world: WorldState) -> tuple[Optional[int], str]:
        """선택된 Intent 를 두 개의 독립적 검증 조회로 (enforce_pid, drop_src_ip)로 해석한다
        — 정합적 two-endpoint 봉쇄 (finding P4-2).

        이전에는 단일 불투명 selector 가 nsenter netns pid 와 iptables ``-s`` 소스 양쪽으로
        붕괴되어, 자연스러운 봉쇄 케이스 (selector = 공격자)에서 DROP 이
        공격자 자신의 netns 에 진입해 공격자 자신의 ip 로부터의 INBOUND 패킷을 drop 했다 —
        공격자의 악성 OUTBOUND (PFCP-delete / 무단 명령)를 결코 멈추지 못하는 near no-op. 효과적
        봉쇄는 공격자 SOURCE 를 별개의 chokepoint/피해자 netns 에서 필터링하므로, 두 KEY 로
        두 endpoint 를 해석한다:
          - ENFORCEMENT: ``enforce_at`` CONTAINER KEY -> netns pid (INPUT 이 필터링하는
            chokepoint). keyspace 는 CONTAINER 이름 (pid/role_verified 는 container-keyed,
            예: "gcs_proxy" 가 command-plane netns 소유) — role alias 가 아니다. ``rb.role`` 을 통해
            ``_binding_verified`` 를 통과하는 role-alias 키는 아래 container-keyed pid 맵을
            놓치고 (``pid_map.get`` -> None) inert DRY 로 유지된다 (fail-closed).
          - SOURCE:      ``target``/``target_kind`` (drop_src) -> ``-s`` 용 공격자 UE-pool ip.
        둘 다 독립적으로 ``_binding_verified`` 를 통과하고 별개 엔티티로 해석되어야 하며, 아니면
        (None, "") -> act_host 가 inert DRY 결과를 낸다 (오조준 / self-DoS DROP 없음; 누수-0
        정합, PS-7). 신뢰되지 않은 어떤 selector 도 결코 raw arg 가 아니다 — 각각은 오직
        검증된 WorldState 바인딩 맵으로의 KEY 이다. live 강제-지점 라우팅은 GATE2/operator-go
        유보; 동적 UE-pool src IP 는 resolve.py stage-2 가 고정한다.
        """
        enforce_sel = (getattr(intent, "enforce_at", "") or "").strip()
        src_sel = (getattr(intent, "target", "") or "").strip()
        src_kind = getattr(intent, "target_kind", "") or ""
        pid_map = world.pid or {}
        ip_map = world.ip_map or {}

        # 두 endpoint 모두 필수 (single-selector 폴백 없음 — 그것이 비정합 동일 엔티티 argv 를
        # 낳았다) 이며 각각은 fail-closed 검증된다.
        if not enforce_sel or not src_sel:
            return None, ""
        if not ResponseController._binding_verified(enforce_sel, world):
            return None, ""
        if not ResponseController._binding_verified(src_sel, world):
            return None, ""

        # ENFORCEMENT netns pid — 검증된 pid 맵으로의 CONTAINER-KEY 조회 전용. pid 맵은
        # 컨테이너 이름으로 keyed (WorldState.pid[container]); role alias (컨테이너 아님)인
        # enforce_sel 은 여기서 놓침 -> None -> inert DRY. 이것이 _binding_verified 범위와 무관하게
        # enforce_at keyspace 를 CONTAINER 로 고정하는 load-bearing gate 이다.
        enforce_pid = pid_map.get(enforce_sel)
        # SOURCE ip — 리터럴 ip-kind selector 가 ``-s`` 로 허용되는 것은 오직 검증 gate 가
        # 그것을 검증된 UE-pool 바인딩에 매치했기 때문; 그 외에는 검증 맵으로의 KEY 조회.
        drop_src_ip = src_sel if src_kind == "ip" else ip_map.get(src_sel, "")
        if not enforce_pid or not drop_src_ip:
            return None, ""

        # P4 STALE-BINDING 가드 (self-DoS 차단): raw ip-kind 소스는 탐지 시점에 포착된 공격자 IP 다.
        # UE-pool IP 는 attach 마다 재할당되므로, 강제 시점에는 이미
        # 무고한 UE 의 것일 수 있음 -> 그것을 drop 하면 피해자를 self-DoS 한다. IP 가 여전히
        # 같은 recon 검증 엔티티에 귀속됨을 재확인하고 (world.roles/ip_map), live SMF
        # 세션 테이블이 배선된 경우 그것이 여전히 같은 컨테이너에 live-bound 임을 재확인. 불일치 /
        # 불확실 -> inert DRY (fail-closed). role/imsi selector 는 검증 맵을 통해 현재 ip 로
        # 해석되는 안정적 identity KEY 이므로, 이 raw-IP drift 의 영향을 받지 않는다.
        if src_kind == "ip" and not self._source_ip_still_attributed(drop_src_ip, world):
            return None, ""

        # DISTINCT-binding 가드: 강제 netns 와 drop 소스는 반드시 서로 다른 엔티티여야 한다.
        # 소스 자신의 netns 에 진입해 자기 ip 를 drop 하는 DROP 은 위의 비정합 near-no-op
        # -> inert DRY.
        if enforce_sel == src_sel:
            return None, ""
        src_pid = pid_map.get(src_sel)
        if src_pid is not None and int(src_pid) == int(enforce_pid):
            return None, ""
        enforce_ip = ip_map.get(enforce_sel, "")
        if enforce_ip and enforce_ip == drop_src_ip:
            return None, ""
        return int(enforce_pid), drop_src_ip

    # -- plan (pure) ------------------------------------------------------ #
    def plan(self, intent: Intent, world: WorldState, tick_i: int, *,
             risk: str, reversible: bool) -> ResponsePlan:
        rule, tool_id = intent.rule, intent.tool_id

        # 1) bundle discipline: 멱등 skip -> debounce skip
        if bundle_mod.already_applied(world, rule):
            return ResponsePlan(rule, tool_id, "AUTO", skip=True,
                                reason="idempotent: rule already applied+confirmed")
        # Phase 2 (B3/PS-7) — debounce hold. 명시적 min_ticks 가 우선; 아니면 operator_auto
        # (sandbox demo) 하에서 hold 가 config demo_mode.debounce_ticks 로 축소되어 재선택된
        # 회복이 다음 tick 내에 재바인딩됨; 아니면 None -> bundle 의 엄격한 physical_action_min.
        #
        # 축소는 inert-DRY 경로로 제한된다 (여기 argv 빌더가 없는, operator_auto 로 확장된 OPER
        # 도구 — docker_pause / flight; side-effect 0). LIVE netns-삽입
        # 도구 ``nsenter_input_drop`` 은 제외되며 전체 physical_action_min hold 를 유지한다: 그
        # actuator (act_host.drop_argv)는 비멱등 iptables ``-I`` 를 사용하고 (``-C`` 사전 확인 없음),
        # live observe=None (Phase 4 미배선)에서는 effect_confirm 이 확인하지 않음 -> already_applied
        # 가 항상 False -> debounce 가 유일한 재작동 throttle. 거기서 축소하면
        # 동일한 '-I ... -s <attacker> -j DROP' 를 매 demo tick 마다 재삽입하여 (1-tick 에서 3배), 단일
        # '-D' de-escalation revert 로는 완전히 되돌릴 수 없는 N 개
        # 중복 규칙이 누적됨 -> 기록된 '복구/해제' 에도 불구하고 피해자 netns 가
        # 소스를 계속 차단 (가역성/leak-0 위반). 따라서 Live 삽입은
        # 멱등화되거나 Phase 4 observe 가 배선될 때까지 3-tick damped 로 유지된다.
        eff_min_ticks = self.min_ticks
        if (eff_min_ticks is None and self.operator_auto
                and tool_id != "nsenter_input_drop"):
            from ..config import loader as _loader
            eff_min_ticks = int(_loader.demo_mode().get("debounce_ticks", 1))
        if bundle_mod.debounce_blocked(world, rule, tick_i, eff_min_ticks):
            _held = eff_min_ticks if eff_min_ticks is not None else bundle_mod.min_debounce_ticks()
            return ResponsePlan(rule, tool_id, "AUTO", skip=True,
                                reason=f"debounced: applied < {_held} ticks ago")

        # 2) 2-tier gate (operator_auto 가 등록된 OPER 결정을 auto 로 확장 — Phase 1)
        gd = gate_mod.gate_for(tool_id, risk, reversible, self.operator_auto)
        if gd.operator_required:
            return ResponsePlan(rule, tool_id, "OPER", operator_required=True, reason=gd.reason)
        oper_auto = gd.tier2 == "AUTO_BY_OPERATOR"

        # P1 PROTECTED-INFRA SHIELD (구조적, 어떤 작동이 조립되기 전에): 보호 대상
        # 관측/C2 컨테이너를 겨냥한 컨테이너 전체 파괴형 도구 (docker_pause / docker_net_disconnect)는
        # 여기서 INERT 된다 — 탐지 신호 (오탐 포함)나 operator_auto 와 무관하게. 대시보드
        # (web_backend/:8080)와 C2 chokepoint (gcs_proxy/:14556)는
        # 결코 자율적으로 동결/차단되지 않는다. 수술적 봉쇄는 영향받지 않는다:
        # pfcp_firewall/mongo_acl (nsenter DROP)와 send_signed_mode emit 은 파괴형 도구가 아니다.
        enforce_at = (getattr(intent, "enforce_at", "") or "").strip()
        if self._infra_shielded(tool_id, enforce_at):
            return ResponsePlan(rule, tool_id, gd.tier2, exec_request=None,
                                operator_auto_confirmed=oper_auto,
                                reason=(f"INERT: protected observation/C2 infra '{enforce_at}' "
                                        f"shielded from destructive '{tool_id}' (P1)"))

        # 3a) operator_auto 로 auto 확장된 docker_pause -> act_host (duck-typed docker 백엔드)를 통해
        # 컨테이너 pause 를 DISPATCH. 이는 backdoor_pause 가 선택+기록되었으나 결코 작동되지 않아
        # ``inspect_paused`` 가 True 에 도달할 수 없고
        # S1 회복-완료 신호에 도달할 수 없던 Phase 4 갭을 메운다. enforce_at 컨테이너 KEY 는 dispatch
        # 전에 검증됨 (fail-closed); pause 는 가역적이며 (docker unpause), 여기의 모든 작동과 마찬가지로
        # operator 가 docker 백엔드의 allow_live 를 뒤집기 전까지 DRY 로 유지된다 (누수-0 정합, 2.).
        if tool_id == "docker_pause" and oper_auto:
            container = (getattr(intent, "enforce_at", "") or "").strip()
            if container and ResponseController._binding_verified(container, world):
                return ResponsePlan(rule, tool_id, "AUTO", pause_container=container,
                                    operator_auto_confirmed=oper_auto,
                                    revert_cmd=f"docker unpause {container}",
                                    reason=gd.reason + f" -> docker pause {container}")
            return ResponsePlan(rule, tool_id, "AUTO", exec_request=None,
                                operator_auto_confirmed=oper_auto,
                                reason=gd.reason + " -> inert DRY (pause container unverified)")
        # 3a2) operator_auto 로 auto 확장된 send_signed_mode -> KEY-FREE signed-mode
        # 교정 명령을 EMIT (GUIDED/LOITER 30 m hold 또는 RTL). MDG 는 어떤 경로에서도
        # uplink-signing 키를 보유하지 않는다: emit 은 오직 command_digest (토큰 재료)만 계산하고
        # 실제 서명은 인증된 채널로 gcs_c2 (이미 자기 키 보유)에 위임한다
        # (E11 non-proliferation — emitter 는 정적으로 key-free, verify_signer_no_keyopen).
        # enforce_at chokepoint (gcs_proxy)는 먼저 검증된 바인딩이어야 한다 (fail-closed, 합법성
        # 전제조건 role_verified.gcs 가 해석되는 동일 gate) — 아니면 inert DRY, emit 없음.
        # allow_live=False 에서는 operator-go DRY 로 유지된다 (SITL 수용은 server-deploy 검증됨).
        if tool_id == "send_signed_mode" and oper_auto:
            enforce = (getattr(intent, "enforce_at", "") or "").strip()
            if enforce and ResponseController._binding_verified(enforce, world):
                return ResponsePlan(rule, tool_id, "AUTO", signed_intent=intent,
                                    operator_auto_confirmed=oper_auto,
                                    reason=gd.reason + f" -> emit send_signed_mode "
                                    f"(KEY-FREE, delegate gcs_c2, enforce_at={enforce})")
            return ResponsePlan(rule, tool_id, "AUTO", exec_request=None,
                                operator_auto_confirmed=oper_auto,
                                reason=gd.reason + " -> inert DRY (signed-mode enforce_at unverified)")
        # 3b) auto 로 확장된 그 밖의 OPER 도구 (docker_net_disconnect)는 여기 actuator 가 없다 — 그
        # live 작동은 operator-tooling 으로 지연된다. INERT DRY plan (side-effect 0)을 내어
        # sandbox 가 잘못 만들어진 argv 없이 강제 결정을 기록하게 한다 (누수-0 정합, 2.).
        if tool_id != "nsenter_input_drop":
            return ResponsePlan(rule, tool_id, "AUTO", exec_request=None,
                                operator_auto_confirmed=oper_auto,
                                reason=gd.reason + " -> inert DRY (no argv builder for this tool)")
        # (enforce_pid, src_ip)는 Intent 의 두 검증 selector 에 대한 PURE LOOKUP (P4-Q1/P4-2);
        # 어느 한 endpoint 가 미검증이거나 둘이 별개가 아니면 -> inert DRY (비정합 DROP 없음).
        pid, src_ip = self._resolve_endpoints(intent, world)
        argv = None
        from .act_host import drop_argv, drop_revert_cmd
        argv = drop_argv(pid, src_ip)
        revert = drop_revert_cmd(pid, src_ip)
        req = None
        if argv is not None:
            req = ExecRequest(argv=argv, revert_cmd=revert, reversible=True)
        return ResponsePlan(rule, tool_id, "AUTO", exec_request=req, revert_cmd=revert,
                            operator_auto_confirmed=oper_auto,
                            reason=gd.reason if req is not None
                            else "AUTO but netns target unresolved -> inert DRY")

    # -- 계획된 AUTO 작동 실행 (Backend.run — allow_live 아니면 DRY) #
    def run_plan(self, plan: ResponsePlan) -> ExecResult:
        # Phase 4: operator_auto docker_pause plan 은 ExecRequest 경로가 아니라 act_host (duck-typed
        # docker 백엔드)를 통해 작동한다. live docker 백엔드가 없으면 호출은
        # operator-go DRY dict 로 강등된다 (side-effect 0). dict 결과를 ExecResult 로 정규화하여
        # act 노드의 world_update/ledger 계약이 바뀌지 않게 한다.
        if plan.pause_container:
            r = self.act_host.pause(plan.pause_container)
            return ExecResult(ok=bool(r.get("ok", False)), code=0,
                              dry_run=bool(r.get("dry_run", False)),
                              note=r.get("note", f"docker pause {plan.pause_container}"))
        # send_signed_mode: KEY-FREE 인가 (command_digest 만)를 emit 하고 서명을
        # gcs_c2 에 위임 — MDG 는 signing-key 경로를 결코 열지 않는다 (verify_signer_no_keyopen).
        # emit 의 dry_run 은 backend.allow_live 를 반영한다 (operator-go 유보 -> digest 전용 DRY; live ->
        # 위임된 out-of-band 서명). 로컬 spawn 없음 (위임은 out-of-band).
        if plan.signed_intent is not None:
            emit = emit_signed(plan.signed_intent, backend=self.backend)
            note = (f"send_signed_mode emit (KEY-FREE, delegate {emit.delegate}, "
                    f"digest {emit.command_digest[:12]}…): {emit.note}")
            return ExecResult(ok=bool(emit.ok), code=0, dry_run=bool(emit.dry_run), note=note)
        if plan.exec_request is None:
            return ExecResult(ok=True, code=0, dry_run=True,
                              note=f"INERT: no exec_request for rule '{plan.rule}' ({plan.reason})")
        return self.backend.run(plan.exec_request)

    def dispatch(self, intent: Intent, world: WorldState, tick_i: int, *,
                 risk: str, reversible: bool) -> tuple[ResponsePlan, Optional[ExecResult]]:
        """계획 후, non-skip AUTO plan 이면 실행. OPER/skip -> (plan, None)."""
        plan = self.plan(intent, world, tick_i, risk=risk, reversible=reversible)
        if plan.skip or plan.operator_required:
            return plan, None
        return plan, self.run_plan(plan)
