"""P0 실행검증 (mock 없음) — 실제 import + WorldState → legality → kb_update → goal_reached.

재현 시나리오 = 11 §4 예시 트레이스: `mode=GUIDED under signing=on` (signing_bypass).
registry = 22 원시 전량(04 §5). SetMode 미차단 경로 = forge_sign(signkey_leak 소비).
  oracle/forge_aria=Blocked(signing), replay=Blocked(timestamp), naive=baseline.
통과 기준 = 각 단계의 runnable/missing/effect_eval/goal_reached 가 설계(11 §4)와 일치 + 수정검증:
  (a) 미등록 id → KeyError  (b) forge_sign args_template 에 {sign_key} 부재 + secret_params
  (c) blocked InjectResult 는 mode 불변(가드)  (d) string target '4' 도 goal_reached True(양변 int).
"""

from __future__ import annotations
_import_sys=__import__('sys'); _import_os=__import__('os')
from pathlib import Path as _Path
_REPO=_Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path: _import_sys.path.insert(0,str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root → cwd-relative paths resolve

import sys

# Windows 콘솔(cp949)에서 유니코드(—·… 등) 출력 깨짐/크래시 방지.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

from core.common.results import CollectResult, InjectResult, ReconResult
from core.common.types import (
    Artifact,
    Fact,
    ToolSuccess,
    ToolError,
    container_access,
    reach,
)
from core.common.types import ReachTarget as RT
from core.modules.kb import (
    C2,
    EffectEvalKind,
    Goal,
    Signing,
    WorldState,
    goal_reached,
    kb_update,
    legality,
)
from core.common.types import ToolId
from typing import get_args as _get_args
from core.modules.registry import REGISTRY, get_spec
from core.modules.tool_wrap import CRSError, Err, Ok, tool_wrap

_fail = 0


def check(label: str, cond: bool) -> None:
    global _fail
    mark = "PASS" if cond else "FAIL"
    if not cond:
        _fail += 1
    print(f"  [{mark}] {label}")


def status_of(tool_id: str, kb: WorldState):
    return legality(get_spec(tool_id), kb)


print("=" * 70)
print("STEP 0 · 초기 KB (11 §4 스텝0): facts={attached}, +premise foothold(sgi)")
print("=" * 70)
# 19 PART1-5: premise footholds 필수. signkey_leak.requires=container_access(sgi).
kb = WorldState.initial(footholds=[container_access("sgi")])
check("attached in facts", any(f.pred.value == "attached" for f in kb.facts))
check("scalars all unknown (signing)", kb.scalars.signing == Signing.UNKNOWN)
check("scalars.mode unknown(None)", kb.scalars.mode is None)
check("artifacts empty", len(kb.artifacts) == 0)

st = status_of("recon_reach", kb)
check("recon_reach runnable (precond=attached)", st.runnable is True)
st = status_of("recon_defense", kb)
check("recon_defense NOT runnable (needs reach(sgi))", st.runnable is False)
check("recon_defense missing lists reach(sgi)",
      any("reach(sgi)" in m.detail for m in st.missing))
st = status_of("forge_sign", kb)
check("forge_sign NOT runnable (missing reach + sign_key)", st.runnable is False)
check("forge_sign missing includes sign_key artifact",
      any(m.kind == "artifact" and m.detail == "sign_key" for m in st.missing))

print()
print("=" * 70)
print("STEP 1 · recon_reach + recon_defense 결과 반영 → reach{...}, signing=on")
print("=" * 70)
recon_reach_res = ReconResult(
    reach=[f"{t}@10.50.0.1:0" for t in
           ("net_core", "mongo", "sgi", "uav5762", "s1u", "pivot",
            "gcs14555", "gcs14556", "web8080")],
    signing="unknown",
)
kb_update(kb, recon_reach_res)
check("reach(sgi) now in facts", reach(RT.SGI) in kb.facts)
check("reach(gcs14556) now in facts", reach(RT.GCS14556) in kb.facts)
check("prov[reach(sgi)]=recon", kb.prov.get("reach(sgi)") == "recon")

# recon_defense (이제 runnable) → signing=on 확정 (defense:on 시드 등가, 19 PART1-1)
st = status_of("recon_defense", kb)
check("recon_defense runnable after reach(sgi)", st.runnable is True)
kb_update(kb, ReconResult(signing="on"))
check("signing == on", kb.scalars.signing == Signing.ON)

# 11 §4 스텝1 핵심 effect_eval 판정
st_oracle = status_of("oracle", kb)
check("oracle runnable (reach gcs14556)", st_oracle.runnable is True)
check("oracle effect_eval == Blocked(signing) [ADAPT 회피 신호]",
      st_oracle.effect_eval.kind == EffectEvalKind.BLOCKED
      and st_oracle.effect_eval.blocked_by.value == "signing")

st_naive = status_of("naive", kb)
check("naive runnable (reach gcs14555)", st_naive.runnable is True)
check("naive effect_eval == Blocked(baseline) [대조군]",
      st_naive.effect_eval.kind == EffectEvalKind.BLOCKED
      and st_naive.effect_eval.blocked_by.value == "baseline")

st_forge = status_of("forge_sign", kb)
check("forge_sign STILL missing sign_key (reach 충족·consume 미충족)",
      st_forge.runnable is False
      and any(m.detail == "sign_key" for m in st_forge.missing))

st_sk = status_of("signkey_leak", kb)
check("signkey_leak runnable (container_access sgi foothold)", st_sk.runnable is True)

print()
print("=" * 70)
print("STEP 2 · signkey_leak → +sign_key (KB→ToolStatus 가 체인을 연다)")
print("=" * 70)
kb_update(kb, CollectResult(artifacts=["sign_key"], values={"sign_key": "a1b2…"}))
check("sign_key in artifacts", Artifact.SIGN_KEY in kb.artifacts)

st_forge = status_of("forge_sign", kb)
check("forge_sign NOW runnable (missing 해소) = 조합 창발",
      st_forge.runnable is True)
check("forge_sign effect_eval == SetMode (서명 무관 우회)",
      st_forge.effect_eval.kind == EffectEvalKind.SET_MODE)

print()
print("=" * 70)
print("STEP 3 · forge_sign(mode=4) 실행 결과 → mode=GUIDED")
print("=" * 70)
# 실행기가 반환할 InjectResult (ACK accepted + 공격자-관측 effect)
inj = InjectResult(accepted=True, signed=True, effect={"mode": "4"})
kb_update(kb, inj)
check("scalars.mode == 4 (GUIDED)", kb.scalars.mode == 4)
check("prov[mode]=asserted (완전분리: 자기판정)", kb.prov.get("mode") == "asserted")

print()
print("=" * 70)
print("STEP 4 · goal_reached 판정 (signing_bypass: mode==4 AND signing==on)")
print("=" * 70)
goal = Goal(type="signing_bypass", target={"mode": 4})
check("goal_reached(signing_bypass) == True", goal_reached(kb, goal) is True)
# 반례: signing이 on이 아니면 signing_bypass 불성립
kb2 = WorldState.initial()
kb2.scalars.mode = 4
kb2.scalars.signing = Signing.OFF
check("signing_bypass False when signing=off", goal_reached(kb2, goal) is False)
# mode_set 목표
check("mode_set(4) True", goal_reached(kb, Goal(type="mode_set", target={"mode": 4})))
check("mode_set(9) False", not goal_reached(kb, Goal(type="mode_set", target={"mode": 9})))
# (d) 양변 int 강제: string target '4' 도 mode==4 매칭
check("(d) mode_set(str '4') True [양변 int]",
      goal_reached(kb, Goal(type="mode_set", target={"mode": "4"})))
check("(d) signing_bypass(str '4') True [양변 int]",
      goal_reached(kb, Goal(type="signing_bypass", target={"mode": "4"})))
# exfil 목표
check("exfil(sign_key) True", goal_reached(kb, Goal(type="exfil", target={"artifact": "sign_key"})))
check("exfil(k_opc) False", not goal_reached(kb, Goal(type="exfil", target={"artifact": "k_opc"})))
# c2_disrupt
check("c2_disrupt False (c2 unknown)", not goal_reached(kb, Goal(type="c2_disrupt")))
# signing_bypass provenance 가드: mode 가 config 시드(asserted 아님)면 불성립
kb_seed = WorldState.initial(signing=Signing.ON)
kb_seed.scalars.mode = 4
kb_seed.prov["mode"] = "config"
check("signing_bypass False when prov[mode]=config (실주입 아님)",
      not goal_reached(kb_seed, Goal(type="signing_bypass", target={"mode": 4})))

print()
print("=" * 70)
print("STEP 5 · (c) blocked InjectResult 가드 — mode/c2/flags 불변")
print("=" * 70)
kb_blk = WorldState.initial()
check("pre: mode unknown(None)", kb_blk.scalars.mode is None)
# blocked_by=signing 이면서 accepted=True/effect={mode:4} 여도 mode 는 절대 안 바뀜(가드)
kb_update(kb_blk, InjectResult(accepted=True, blocked_by="signing", effect={"mode": "4"}))
check("(c) blocked → scalars.mode STILL None (effect 미적용)", kb_blk.scalars.mode is None)
check("(c) blocked(signing) → signing=on 확증만", kb_blk.scalars.signing == Signing.ON)
check("(c) prov[mode] 미기록", "mode" not in kb_blk.prov)
# accepted=False 도 당연히 불변
kb_blk2 = WorldState.initial()
kb_update(kb_blk2, InjectResult(accepted=False, effect={"mode": "4"}))
check("(c) not accepted → mode 불변", kb_blk2.scalars.mode is None)
# SetFlag(subscriber_written): accepted+미차단 → flags 갱신
kb_flag = WorldState.initial()
kb_update(kb_flag, InjectResult(accepted=True, effect={"subscriber_written": "true"}))
check("SetFlag: subscriber_written in flags", "subscriber_written" in kb_flag.flags)
kb_flag_blk = WorldState.initial()
kb_update(kb_flag_blk, InjectResult(accepted=True, blocked_by="auth", effect={"subscriber_written": "true"}))
check("SetFlag 가드: blocked → flags 불변", "subscriber_written" not in kb_flag_blk.flags)

print()
print("=" * 70)
print("EXTRA · tool_wrap 어댑터 (Ok→ToolSuccess / Err/CRSError→ToolError)")
print("=" * 70)
import asyncio


async def _ok_fn(x: int):
    return Ok(ReconResult(sessions=x))


async def _err_fn():
    return Err(CRSError("boom", extra={"why": "test"}))


async def _raise_fn():
    raise CRSError("raised", extra={"k": 1})


async def _blocked_pre(*a, **k):
    return ToolError("pre-blocked (legality gate)")  # runnable=false 시뮬


wrapped_ok = tool_wrap(_ok_fn)
wrapped_err = tool_wrap(_err_fn)
wrapped_raise = tool_wrap(_raise_fn)
wrapped_pre = tool_wrap(_ok_fn, pre_hooks=[_blocked_pre])

r_ok = asyncio.run(wrapped_ok(7))
check("Ok → ToolSuccess[ReconResult]", isinstance(r_ok, ToolSuccess) and r_ok.result.sessions == 7)
r_err = asyncio.run(wrapped_err())
check("Err → ToolError(error=boom)", isinstance(r_err, ToolError) and r_err.error == "boom")
r_raise = asyncio.run(wrapped_raise())
check("raised CRSError → ToolError", isinstance(r_raise, ToolError) and r_raise.error == "raised")
r_pre = asyncio.run(wrapped_pre(1))
check("pre_hook 차단 → ToolError (하드게이트)", isinstance(r_pre, ToolError))

print()
print("=" * 70)
print("EXTRA · 닫힘 강제 (registry 화이트리스트 23 전량)")
print("=" * 70)
check("REGISTRY has 23 tools (원시 전량)", len(REGISTRY) == 23)
# ToolId Literal 과 REGISTRY 키 일치(누락/유령 없음)
_ids = set(_get_args(ToolId))
check("ToolId Literal == REGISTRY keys (23)", _ids == set(REGISTRY.keys()) and len(_ids) == 23)
# 04 §5 명시 22 원시 전량 등록 확인
_expected = {
    "recon_reach", "recon_defense", "recon_session", "capture_downlink", "observe_mode",
    "serial5762", "s1u_capture",
    "subdb_dump", "subdb_canary", "pfcp_delete", "pfcp_flood", "pivot_exploit",
    "key_extract", "signkey_leak", "nonce_scan",
    "oracle", "webcmd", "forge_sign", "forge_aria", "replay", "peer_flood", "forceland", "naive",
}
check("23 원시 id 전량 일치 (04 §5)", set(REGISTRY.keys()) == _expected)
# (a) 미등록 id → KeyError
try:
    get_spec("nonexistent_tool")
    check("(a) unknown id rejected", False)
except KeyError:
    check("(a) unknown id rejected (KeyError)", True)

print()
print("=" * 70)
print("EXTRA · (b) 비밀 라우팅 — forge_sign args_template 에 {sign_key} 부재 + secret_params")
print("=" * 70)
_fs = get_spec("forge_sign").exec_binding
check("(b) forge_sign args_template 에 '{sign_key}' 없음",
      "{sign_key}" not in _fs.args_template and "sign_key" not in _fs.args_template)
check("(b) forge_sign secret_params == ('sign_key',)", _fs.secret_params == ("sign_key",))
_fa = get_spec("forge_aria").exec_binding
check("(b) forge_aria args_template 에 '{aria_key}' 없음", "aria_key" not in _fa.args_template)
check("(b) forge_aria secret_params == ('aria_key',)", _fa.secret_params == ("aria_key",))
_rp = get_spec("replay").exec_binding
check("(b) replay args_template 에 'ciphertext' 없음", "ciphertext" not in _rp.args_template)
check("(b) replay secret_params == ('ciphertext',)", _rp.secret_params == ("ciphertext",))
# sidecar Literal 준수(전 tool ∈ {ue,core,sgi,host})
_ok_sc = all(get_spec(i).exec_binding.sidecar in ("ue", "core", "sgi", "host") for i in REGISTRY)
check("모든 sidecar ∈ {ue,core,sgi,host}", _ok_sc)
# 비밀 소비 tool 은 args_template 에 어떤 비밀 원문도 없어야(누수 0)
for _tid in ("forge_sign", "forge_aria", "replay"):
    _eb = get_spec(_tid).exec_binding
    for _sp in _eb.secret_params:
        check(f"{_tid}: secret '{_sp}' args_template 에 원문 없음 (R6)",
              ("{" + _sp + "}") not in _eb.args_template)

print()
print("=" * 70)
print("EXTRA · 신규 tool 배선 (22 전량) legality/effect_eval 표본")
print("=" * 70)
# STEP1 이후 kb 재사용 대신 신선한 recon 상태 구성
kb_c = WorldState.initial(footholds=[container_access("sgi")])
kb_update(kb_c, ReconResult(reach=[f"{t}@10.50.0.1:0" for t in
          ("net_core", "mongo", "sgi", "uav5762", "s1u", "pivot",
           "gcs14555", "gcs14556", "web8080")]))
kb_update(kb_c, ReconResult(signing="on"))
# serial5762: reach(uav5762) 충족 → runnable, effect SET_MODE (서명 관통)
st = status_of("serial5762", kb_c)
check("serial5762 runnable + effect_eval SET_MODE (서명 관통)",
      st.runnable and st.effect_eval.kind == EffectEvalKind.SET_MODE)
# webcmd: reach(web8080) 있으나 unauth(web) 없음 → NOT runnable
st = status_of("webcmd", kb_c)
check("webcmd NOT runnable (missing unauth(web))",
      not st.runnable and any("unauth(web)" in m.detail for m in st.missing))
# forge_aria: signing=on → Blocked(signing) (aria_key 미보유이므로 runnable=False 이나 effect_eval 예측)
st = status_of("forge_aria", kb_c)
check("forge_aria effect_eval Blocked(signing) [서명계층이 막음]",
      st.effect_eval.kind == EffectEvalKind.BLOCKED
      and st.effect_eval.blocked_by.value == "signing")
# replay: signing=on → Blocked(timestamp)
st = status_of("replay", kb_c)
check("replay effect_eval Blocked(timestamp)",
      st.effect_eval.kind == EffectEvalKind.BLOCKED
      and st.effect_eval.blocked_by.value == "timestamp")
# nonce_scan: ciphertext/pcap 없음 → NOT runnable (require_any_artifact)
st = status_of("nonce_scan", kb_c)
check("nonce_scan NOT runnable (missing ciphertext|pcap)",
      not st.runnable and any("ciphertext" in m.detail and "pcap" in m.detail for m in st.missing))
# ciphertext 넣으면 열림 (require_any_artifact OR)
kb_update(kb_c, CollectResult(artifacts=["ciphertext"]))
st = status_of("nonce_scan", kb_c)
check("nonce_scan runnable after +ciphertext (OR 그룹 ≥1)", st.runnable)
# subdb_canary: effect_eval SET_FLAG
st = status_of("subdb_canary", kb_c)
check("subdb_canary effect_eval SET_FLAG (subscriber_written)",
      st.effect_eval.kind == EffectEvalKind.SET_FLAG)
# pfcp_delete: precond reach(net_core) 충족되나 seid 미보유 → NOT runnable (consumes 미충족)
st = status_of("pfcp_delete", kb_c)
check("pfcp_delete NOT runnable (reach(net_core) 충족·seid 미보유)", not st.runnable)
# forceland: in_flight 없음 → NOT runnable, HIGH risk
check("forceland risk == HIGH (HITL)", get_spec("forceland").risk.value == "HIGH")
st = status_of("forceland", kb_c)
check("forceland NOT runnable (missing in_flight)",
      not st.runnable and any("in_flight" in m.detail for m in st.missing))
# HITL 게이트 표식(절대규칙5·DESIGN §8): 기본 hitl_enabled → HIGH risk 는 requires_confirm=True
check("forceland requires_confirm True (HITL-on 기본)", st.requires_confirm is True)
check("forceland requires_confirm False when hitl_enabled=False (opt-out)",
      legality(get_spec("forceland"), kb_c, hitl_enabled=False).requires_confirm is False)
# 비-HIGH risk tool 은 표식 없음(기존 필드/판정 불변)
check("oracle requires_confirm False (LOW risk)",
      status_of("oracle", kb_c).requires_confirm is False)

print()
print("=" * 70)
if _fail == 0:
    print(f"ALL CHECKS PASSED (0 failures)")
    sys.exit(0)
else:
    print(f"{_fail} CHECK(S) FAILED")
    sys.exit(1)
