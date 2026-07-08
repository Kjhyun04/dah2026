"""response.py — Response Controller: the dispatch layer between the ``act`` graph node and
the safe-exec backends.

Given the chosen Intent it applies, in order:
  1. bundle discipline (core.bundle): idempotent applied()-skip → N-tick debounce. Either -> SKIP.
  2. the 2-tier gate (core.gate): AUTO tool -> plan a live actuation; OPER tool (flight / docker
     pause / net-disconnect) -> operator_required (no actuation; act records an operator-gate
     Intent bound by signer_shim, side-effect 0).
  3. for the AUTO tool (``nsenter_input_drop``) build the netns-DROP ExecRequest via act_host.

The SOLE subprocess path stays ``Backend.run`` (불변식②) — this controller only assembles argv
and hands it over. Live actuation is operator-go RESERVED (Backend.allow_live=False -> DRY-RUN),
so ``dispatch`` changes nothing on the testbed until an operator flips the flag. The controller
holds NO docker sdk import and NO sock literal (act_host duck-types the docker backend).
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


@dataclass
class ResponsePlan:
    """The dispatch decision for one chosen Intent (pure — no side effect yet)."""
    rule: str
    tool_id: str
    tier2: str                       # "AUTO" | "OPER"
    skip: bool = False               # idempotent / debounced -> no-op
    operator_required: bool = False  # OPER tier -> defer to operator (side-effect 0)
    operator_auto_confirmed: bool = False  # Phase 1: OPER widened to auto by sandbox operator_auto
    exec_request: Optional[ExecRequest] = None
    pause_container: str = ""         # Phase 4: operator_auto docker_pause target (act_host.pause)
    revert_cmd: str = ""
    reason: str = ""


class ResponseController:
    """Plans and (for AUTO) dispatches responses over the safe-exec backends."""

    def __init__(self, backend: Optional[Backend] = None, docker=None,
                 gate=None, min_ticks: Optional[int] = None,
                 act_host: Optional[ActHost] = None, smf_table=None,
                 operator_auto: bool = False):
        self.backend = backend or Backend(allow_live=False)     # operator-go 유보 default
        self.act_host = act_host or ActHost(backend=self.backend, docker=docker)
        self.gate = gate                                        # optional OperatorGate (binding)
        self.min_ticks = min_ticks
        # Phase 1 (sandbox demo): when True the 2-tier gate widens a registered OPER tool to auto
        # (docker_pause / flight recovery) so the OPER recovery path executes instead of deferring.
        # DETERMINISTIC (env bool), transparency preserved via GateDecision.registry_tier (불변식①).
        self.operator_auto = bool(operator_auto)
        # LIVE SMF session table (SmfSessionTable, ``imsi_for_ip(ip)->imsi|None``) — OPTIONAL. When
        # wired (out-of-graph collector owns it), an ip-kind source selector is cross-checked against
        # the live IMSI<->tun-IP binding so a UE-pool IP RE-ASSIGNED between detection and enforcement
        # is refused (P4 stale-binding, 재할당 IP self-DoS 차단). Absent -> best-effort recon-only check.
        self.smf_table = smf_table

    # -- target resolution: PURE LOOKUP into the verified WorldState binding map (P4-Q1) --- #
    @staticmethod
    def _binding_verified(sel: str, world: WorldState) -> bool:
        """The selector KEY must resolve to a VERIFIED RoleBinding before any DROP argv is built.

        Verified = resolve.py verified predicate (inspect presence ∧, for UE-pool, tun IP inside
        the pool CIDR — ground truth from stage-2). A forged/unknown selector (operator IP,
        out-of-pool literal, unverified role, un-projected IMSI) matches NO verified binding ->
        the caller goes inert DRY. Fail-closed: absent maps -> False.
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
        """The recon-attributed entity (verified RoleBinding container) that currently owns ``ip``
        in the LATEST recon binding (world.roles tun-scan, ip_map reverse), or "" if none.

        This is the "원래 귀속 엔티티" ground truth for the P4 stale-binding cross-check: a UE-pool
        IP is only a droppable source while it still maps to a VERIFIED binding here. Fail-closed:
        absent/unverified -> "".
        """
        if not ip:
            return ""
        for rb in (world.roles or {}).values():
            if rb.verified and rb.ip == ip:
                return rb.container or rb.role
        # reverse ip_map (ip -> container) fallback (resolve builds ip_map[ip]=container, C-3)
        return (world.ip_map or {}).get(ip, "") or ""

    def _source_ip_still_attributed(self, ip: str, world: WorldState) -> bool:
        """P4 stale-binding guard for an ip-kind raw source: is ``ip`` STILL attributed to the SAME
        entity that recon verified? UE-pool IPs rotate per attach, so the attacker IP captured at
        DETECTION may, at ENFORCEMENT, belong to an innocent UE -> dropping it self-DoSes the victim.

        Two independent cross-checks, both fail-closed:
          (a) latest recon binding (world.roles/ip_map): the IP must still resolve to a VERIFIED
              attributed container. Gone/unverified -> stale -> False.
          (b) LIVE SMF session table (``self.smf_table``, OPTIONAL): if wired, the IP must STILL be
              live-bound (``imsi_for_ip`` non-None) AND — when the static IMSI->container map is
              known (world.imsi_container) — resolve to the SAME container as (a). A released IP
              (unbound) or one RE-ASSIGNED to a different container is stale -> False. Absent table
              -> best-effort (a)-only (the smf_table is not yet threaded into the live act path).
        """
        boot_container = ResponseController._verified_container_for_ip(ip, world)
        if not boot_container:
            return False                                   # (a) no current verified attribution
        smf = self.smf_table
        if smf is None:
            return True                                    # best-effort: recon binding re-affirmed
        try:
            cur_imsi = smf.imsi_for_ip(ip)                 # live IMSI<->tun-IP (SmfSessionTable)
        except Exception:                                  # a lookup fault must not actuate -> inert
            return False
        if not cur_imsi:
            return False                                   # session gone: IP released/reassignable
        imsi_container = world.imsi_container or {}
        if imsi_container:                                 # can re-attribute the live IMSI to a container
            live_container = imsi_container.get(cur_imsi, "")
            if not live_container or live_container != boot_container:
                return False                               # RE-ASSIGNED to a different entity -> stale
        return True

    def _resolve_endpoints(self, intent: Intent, world: WorldState) -> tuple[Optional[int], str]:
        """Resolve the chosen Intent to (enforce_pid, drop_src_ip) via TWO INDEPENDENT verified
        lookups — the coherent two-endpoint containment (finding P4-2).

        A single opaque selector was previously collapsed into BOTH the nsenter netns pid AND the
        iptables ``-s`` source, so for the natural containment case (selector = attacker) the DROP
        entered the ATTACKER's OWN netns and dropped INBOUND packets from the attacker's OWN ip — a
        near no-op that never stops the attacker's malicious OUTBOUND (PFCP-delete / unauthorized
        command). Effective containment filters the attacker SOURCE at a DISTINCT chokepoint/victim
        netns, so we resolve two endpoints from two KEYS:
          - ENFORCEMENT: ``enforce_at`` CONTAINER KEY -> netns pid (the chokepoint whose INPUT
            filters). The keyspace is the CONTAINER name (pid/role_verified are container-keyed,
            e.g. "uav_ue" owns the 5762 LISTEN netns) — NOT a role alias. A role-alias key that
            still passes ``_binding_verified`` via ``rb.role`` misses the container-keyed pid map
            below (``pid_map.get`` -> None) and stays inert DRY (fail-closed).
          - SOURCE:      ``target``/``target_kind`` (drop_src) -> the attacker UE-pool ip for ``-s``.
        BOTH must independently pass ``_binding_verified`` AND resolve to DISTINCT entities, else
        (None, "") -> act_host emits an inert DRY result (no mis-targeted / self-DoS DROP; 누수-0
        정합, PS-7). Neither untrusted selector is EVER a raw arg — each is only a KEY into the
        verified WorldState binding map. The live enforcement-point routing is GATE2/operator-go
        RESERVED; the dynamic UE-pool src IP is pinned by resolve.py stage-2.
        """
        enforce_sel = (getattr(intent, "enforce_at", "") or "").strip()
        src_sel = (getattr(intent, "target", "") or "").strip()
        src_kind = getattr(intent, "target_kind", "") or ""
        pid_map = world.pid or {}
        ip_map = world.ip_map or {}

        # BOTH endpoints are required (no single-selector fallback — that produced the incoherent
        # same-entity argv) and each is fail-closed verified.
        if not enforce_sel or not src_sel:
            return None, ""
        if not ResponseController._binding_verified(enforce_sel, world):
            return None, ""
        if not ResponseController._binding_verified(src_sel, world):
            return None, ""

        # ENFORCEMENT netns pid — CONTAINER-KEY lookup only into the verified pid map. The pid map
        # is keyed by container name (WorldState.pid[container]); an enforce_sel that is a role
        # alias (not a container) misses here -> None -> inert DRY. This is the load-bearing gate
        # that pins the enforce_at keyspace to CONTAINER regardless of _binding_verified breadth.
        enforce_pid = pid_map.get(enforce_sel)
        # SOURCE ip — a literal ip-kind selector is admissible as ``-s`` ONLY because the verified
        # gate matched it to a verified UE-pool binding; otherwise KEY lookup into the verified map.
        drop_src_ip = src_sel if src_kind == "ip" else ip_map.get(src_sel, "")
        if not enforce_pid or not drop_src_ip:
            return None, ""

        # P4 STALE-BINDING guard (self-DoS 차단): a raw ip-kind source is the attacker IP captured
        # at DETECTION. UE-pool IPs are re-assigned per attach, so by ENFORCEMENT it may already
        # belong to an innocent UE -> dropping it self-DoSes the victim. Re-affirm the IP is STILL
        # attributed to the same recon-verified entity (world.roles/ip_map) and, when the live SMF
        # session table is wired, that it is STILL live-bound to that same container. Mismatch /
        # uncertainty -> inert DRY (fail-closed). role/imsi selectors are stable identity KEYs
        # resolved to a current ip via the verified map, so they are not subject to this raw-IP drift.
        if src_kind == "ip" and not self._source_ip_still_attributed(drop_src_ip, world):
            return None, ""

        # DISTINCT-binding guard: enforcement netns and drop source MUST be different entities. A
        # DROP that enters the source's OWN netns to drop its own ip is the incoherent near-no-op
        # above -> inert DRY.
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

        # 1) bundle discipline: idempotent skip -> debounce skip
        if bundle_mod.already_applied(world, rule):
            return ResponsePlan(rule, tool_id, "AUTO", skip=True,
                                reason="idempotent: rule already applied+confirmed")
        # Phase 2 (B3/PS-7) — debounce hold. Explicit min_ticks wins; else under operator_auto
        # (sandbox demo) the hold is SHRUNK to config demo_mode.debounce_ticks so a re-selected
        # recovery re-binds within the next tick; else None -> bundle's strict physical_action_min.
        #
        # The shrink is RESTRICTED to the inert-DRY paths (OPER tools widened by operator_auto that
        # have NO argv builder here — docker_pause / flight; side-effect 0). The LIVE netns-insertion
        # tool ``nsenter_input_drop`` is EXCLUDED and keeps the full physical_action_min hold: its
        # actuator (act_host.drop_argv) uses a NON-idempotent iptables ``-I`` (no ``-C`` pre-check),
        # and with live observe=None (Phase 4 unwired) effect_confirm never confirms -> already_applied
        # is always False -> debounce is the SOLE re-actuation throttle. Shrinking it there would re-insert an
        # identical '-I ... -s <attacker> -j DROP' every demo tick (3x under 1-tick), accumulating N
        # duplicate rules that the single '-D' de-escalation revert cannot fully undo -> victim netns
        # keeps blocking the source despite a recorded '복구/해제' (가역성/leak-0 위반). Live insertion
        # therefore stays 3-tick damped until it is made idempotent or Phase 4 observe is wired.
        eff_min_ticks = self.min_ticks
        if (eff_min_ticks is None and self.operator_auto
                and tool_id != "nsenter_input_drop"):
            from ..config import loader as _loader
            eff_min_ticks = int(_loader.demo_mode().get("debounce_ticks", 1))
        if bundle_mod.debounce_blocked(world, rule, tick_i, eff_min_ticks):
            _held = eff_min_ticks if eff_min_ticks is not None else bundle_mod.min_debounce_ticks()
            return ResponsePlan(rule, tool_id, "AUTO", skip=True,
                                reason=f"debounced: applied < {_held} ticks ago")

        # 2) 2-tier gate (operator_auto widens a registered OPER decision to auto — Phase 1)
        gd = gate_mod.gate_for(tool_id, risk, reversible, self.operator_auto)
        if gd.operator_required:
            return ResponsePlan(rule, tool_id, "OPER", operator_required=True, reason=gd.reason)
        oper_auto = gd.tier2 == "AUTO_BY_OPERATOR"

        # 3a) docker_pause widened to auto by operator_auto -> DISPATCH the container pause through
        # act_host (the duck-typed docker backend). This closes the Phase 4 gap where backdoor_pause
        # was selected+recorded but NEVER actuated, so ``inspect_paused`` could never reach True and
        # the S1 회복-완료 signal was unreachable. The enforce_at container KEY is verified (fail-
        # closed) before dispatch; the pause is reversible (docker unpause) and, like every actuation
        # here, stays DRY until an operator flips allow_live on the docker backend (누수-0 정합, ②).
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
        # 3b) any OTHER OPER tool widened to auto (flight / docker_net_disconnect) has NO actuator
        # here — its live actuation is operator-tooling deferred. Emit an INERT DRY plan (side-effect
        # 0) so the sandbox records the enforcement decision without a mis-built argv (누수-0 정합, ②).
        if tool_id != "nsenter_input_drop":
            return ResponsePlan(rule, tool_id, "AUTO", exec_request=None,
                                operator_auto_confirmed=oper_auto,
                                reason=gd.reason + " -> inert DRY (no argv builder for this tool)")
        # (enforce_pid, src_ip) is a PURE LOOKUP of the Intent's TWO verified selectors (P4-Q1/P4-2);
        # either endpoint unverified or the two not DISTINCT -> inert DRY (no incoherent DROP).
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

    # -- run the planned AUTO actuation (Backend.run — DRY unless allow_live) #
    def run_plan(self, plan: ResponsePlan) -> ExecResult:
        # Phase 4: an operator_auto docker_pause plan actuates via act_host (duck-typed docker
        # backend), NOT the ExecRequest path. Absent a live docker backend the call degrades to an
        # operator-go DRY dict (side-effect 0). Normalize the dict result to an ExecResult so the
        # act node's world_update/ledger contract is unchanged.
        if plan.pause_container:
            r = self.act_host.pause(plan.pause_container)
            return ExecResult(ok=bool(r.get("ok", False)), code=0,
                              dry_run=bool(r.get("dry_run", False)),
                              note=r.get("note", f"docker pause {plan.pause_container}"))
        if plan.exec_request is None:
            return ExecResult(ok=True, code=0, dry_run=True,
                              note=f"INERT: no exec_request for rule '{plan.rule}' ({plan.reason})")
        return self.backend.run(plan.exec_request)

    def dispatch(self, intent: Intent, world: WorldState, tick_i: int, *,
                 risk: str, reversible: bool) -> tuple[ResponsePlan, Optional[ExecResult]]:
        """Plan then, for a non-skip AUTO plan, run it. OPER/skip -> (plan, None)."""
        plan = self.plan(intent, world, tick_i, risk=risk, reversible=reversible)
        if plan.skip or plan.operator_required:
            return plan, None
        return plan, self.run_plan(plan)
