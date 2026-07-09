"""viewer.ingest — 순수 파서·재구성·redact (grep0: core/supervisor/fastapi import 0).

이 모듈은 dict 만 다룬다. pydantic 모델·registry·get_spec 을 참조하지 않는다.
표시용 상수(_LAYER/INJECT_TOOL_IDS 등)는 core.modules.registry §7 표와
core.common.results 계약에서 **offline baked** 한 분류표일 뿐 — 행동공간 확장이 아니다.

데이터 계약(정확 일치):
  action step   : core.driver.campaign_to_jsonl -> {"type":"step", **StepRecord}
  action final  : {"type":"campaign_result", goal_reached, steps, defenses_bypassed, win_causes, kb_final}
  evaluation    : supervisor.build_evaluation -> {schema, goal, ground_truth, verdict{...,autonomy_accuracy}}
  frame(뷰어정의): {schema:"dah.supervisor.frame/1", t, dir:up|down, mtype, mode, signed, src_ip}

작성 2026-07-06.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

# ═══════════════════════════════════════════════════════════════════════════
# 표시용 분류 상수 (registry §7 · results.py 주석에서 baked — 행동공간 아님)
# ═══════════════════════════════════════════════════════════════════════════

# 13 INJECT (kind==INJECT). 통신-주입로그 레인 필터용 표시 분류.
INJECT_TOOL_IDS: frozenset[str] = frozenset({
    "serial5762", "subdb_canary", "pfcp_delete", "pfcp_flood", "pivot_exploit",
    "oracle", "webcmd", "forge_sign", "forge_aria", "replay", "peer_flood",
    "forceland", "naive",
})
# RECON layer (recon 4종; capture_downlink 은 kind=COLLECT 이나 layer=RECON).
RECON_TOOL_IDS: frozenset[str] = frozenset({
    "recon_reach", "recon_defense", "recon_session", "capture_downlink", "observe_mode",
})
# COLLECT kind (capture_downlink 제외 — 그건 RECON 그룹으로 표시).
COLLECT_TOOL_IDS: frozenset[str] = frozenset({
    "s1u_capture", "subdb_dump", "key_extract", "signkey_leak", "nonce_scan",
})
# PROBE kind (상태불변 정찰).
_PROBE_TOOL_IDS: frozenset[str] = frozenset({
    "recon_reach", "recon_defense", "recon_session", "observe_mode",
})

# tool_id -> layer (registry §7 표 baked). RECON|A|B|C|D.
_LAYER: dict[str, str] = {
    "recon_reach": "RECON", "recon_defense": "RECON", "recon_session": "RECON",
    "capture_downlink": "RECON", "observe_mode": "RECON",
    "serial5762": "A", "s1u_capture": "A",
    "subdb_dump": "B", "subdb_canary": "B", "pfcp_delete": "B",
    "pfcp_flood": "B", "pivot_exploit": "B",
    "key_extract": "C", "signkey_leak": "C", "nonce_scan": "C",
    "oracle": "D", "webcmd": "D", "forge_sign": "D", "forge_aria": "D",
    "replay": "D", "peer_flood": "D", "forceland": "D", "naive": "D",
}

# ArduPilot COPTER custom_mode 표시명 (registry _MODE_PARAM: 0/4/5/9).
COPTER_MODE: dict[int, str] = {0: "STABILIZE", 4: "GUIDED", 5: "LOITER", 9: "LAND"}


def layer_of(tool_id: str) -> str:
    return _LAYER.get(tool_id, "?")


def kind_of(tool_id: str) -> str:
    if tool_id in INJECT_TOOL_IDS:
        return "INJECT"
    if tool_id == "capture_downlink" or tool_id in COLLECT_TOOL_IDS:
        return "COLLECT"
    if tool_id in _PROBE_TOOL_IDS:
        return "PROBE"
    return "?"


def mode_name(mode: Any) -> Optional[str]:
    """custom_mode int -> 표시명(모르면 원값 문자열). None->None."""
    if mode is None:
        return None
    try:
        m = int(mode)
    except (TypeError, ValueError):
        return str(mode)
    return COPTER_MODE.get(m, str(m))


# ═══════════════════════════════════════════════════════════════════════════
# redact — 방어심층 2차 마스킹 (상류가 1차). 원본 불변, 신규 반환.
# ═══════════════════════════════════════════════════════════════════════════

# 비밀 키명(dict 키가 이 이름이면 값 전체 마스킹).
_SECRET_KEY_RE = re.compile(
    r"(aria_key|sign_key|api_key|k_opc|opc|\bki\b|imsi|ciphertext|nonce|secret|passwd|password)",
    re.IGNORECASE,
)
# 값 안의 비밀 토큰: hex>=16 (앞뒤 hex 문자가 없어야 함) · base64>=24.
_HEX_RE = re.compile(r"(?<![0-9A-Fa-fx])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
# 오프라인 검증용 스캔 패턴 목록.
_SECRET_RE: list[re.Pattern] = [_HEX_RE, _B64_RE]

_MASK = "[REDACTED]"


def _mask_token(m: "re.Match") -> str:
    v = m.group(0)
    return f"{v[:4]}…[{len(v)}]"


def _mask_str(s: str) -> str:
    """문자열 내 긴 hex/base64 토큰만 마스킹(짧은 0x/mode/seid 값은 임계 미달로 보존)."""
    out = s
    for pat in _SECRET_RE:
        out = pat.sub(_mask_token, out)
    return out


def _mask_secret_value(v: Any) -> Any:
    """비밀 키명 하위 값 마스킹. 문자열은 앞 4자만, 그 외는 [REDACTED]."""
    if isinstance(v, str):
        if len(v) <= 4:
            return _mask_str(v)
        return f"{v[:4]}…[{len(v)}]"
    if isinstance(v, (dict, list)):
        return _MASK
    return v


def redact(obj: Any) -> Any:
    """dict/list/str 재귀 마스킹. 원본 불변, 신규 객체 반환."""
    if isinstance(obj, dict):
        out: dict = {}
        for k, val in obj.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k):
                out[k] = _mask_secret_value(val)
            else:
                out[k] = redact(val)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, tuple):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        return _mask_str(obj)
    return obj


# ═══════════════════════════════════════════════════════════════════════════
# 동작(action JSONL) 파서 — StepRecord / CampaignResult
# ═══════════════════════════════════════════════════════════════════════════


def parse_action_line(line: str) -> Optional[dict]:
    """action JSONL 1줄 -> redact 된 dict. type∈{step,campaign_result} 아니면 None."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or obj.get("type") not in ("step", "campaign_result"):
        return None
    return redact(obj)


def load_action_log(path: "str | Path") -> dict:
    """action JSONL 로드 -> {"steps":[step...], "campaign": dict|None, "count": int}."""
    steps: list[dict] = []
    campaign: Optional[dict] = None
    p = Path(path)
    if p.exists():
        for ln in p.read_text(encoding="utf-8").splitlines():
            rec = parse_action_line(ln)
            if rec is None:
                continue
            if rec.get("type") == "step":
                steps.append(rec)
            elif rec.get("type") == "campaign_result":
                campaign = rec
    return {"steps": steps, "campaign": campaign, "count": len(steps)}


# ═══════════════════════════════════════════════════════════════════════════
# 감독(evaluation.json) 로더 — 단일 JSON 객체
# ═══════════════════════════════════════════════════════════════════════════


def load_evaluation(path: "str | Path") -> Optional[dict]:
    """evaluation.json 전량 read + redact -> dict. 부재/파싱실패 -> None(직전 스냅샷 유지 계약)."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, TypeError, OSError):
        return None
    if not isinstance(obj, dict):
        return None
    return redact(obj)


# ═══════════════════════════════════════════════════════════════════════════
# 통신(supervisor.jsonl) 프레임 스트림 + evaluation 재구성 폴백
# ═══════════════════════════════════════════════════════════════════════════

_VALID_DIR = ("up", "down")


def parse_frame_line(line: str) -> Optional[dict]:
    """supervisor.jsonl 1줄 -> frame(dir/mtype/mode/t/signed). dir∉{up,down} 이면 None."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or obj.get("dir") not in _VALID_DIR:
        return None
    frame = redact(obj)
    return {
        "schema": frame.get("schema", "dah.supervisor.frame/1"),
        "t": frame.get("t"),
        "dir": frame.get("dir"),
        "mtype": frame.get("mtype", ""),
        "mode": frame.get("mode"),
        "mode_name": mode_name(frame.get("mode")),
        "signed": frame.get("signed"),
        "src_ip": frame.get("src_ip", ""),
    }


def load_comms_stream(path: "str | Path | None") -> list[dict]:
    """supervisor.jsonl 프레임들. 부재 -> []."""
    if path is None:
        return []
    p = Path(path)
    if not p.exists():
        return []
    frames: list[dict] = []
    for ln in p.read_text(encoding="utf-8").splitlines():
        fr = parse_frame_line(ln)
        if fr is not None:
            frames.append(fr)
    return frames


def frames_from_evaluation(ev: dict) -> list[dict]:
    """스트림 부재 시 재구성: ground_truth.mode_timeline->down, uplink_cmds->up, t 정렬.

    ※ evaluation 의 t 는 감독 캡처 상대시각. down=autopilot HEARTBEAT(관측 mode),
      up=업링크 DO_SET_MODE(target mode). signed 는 프레임별 미기록 -> None(정직).
      signing_observed(링크 전역)은 별도 감독패널에 표기.
    """
    gt = (ev or {}).get("ground_truth") or {}
    frames: list[dict] = []
    for pair in gt.get("mode_timeline") or []:
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        t, mode = pair[0], pair[1]
        frames.append({
            "schema": "dah.supervisor.frame/1", "t": t, "dir": "down",
            "mtype": "HEARTBEAT", "mode": mode, "mode_name": mode_name(mode),
            "signed": None, "src_ip": "",
        })
    for pair in gt.get("uplink_cmds") or []:
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        t, mode = pair[0], pair[1]
        frames.append({
            "schema": "dah.supervisor.frame/1", "t": t, "dir": "up",
            "mtype": "COMMAND_LONG(DO_SET_MODE)", "mode": mode, "mode_name": mode_name(mode),
            "signed": None, "src_ip": "",
        })
    frames.sort(key=lambda f: (f.get("t") is None, f.get("t") or 0.0))
    return frames


# ═══════════════════════════════════════════════════════════════════════════
# 통신 — 공격측 INJECT 주입 로그 레인 (동작 로그에서 추출)
# ═══════════════════════════════════════════════════════════════════════════


def inject_rows_from_action(steps: list[dict]) -> list[dict]:
    """tool_id∈INJECT_TOOL_IDS 스텝 -> 주입로그 레인 rows(source='attacker-inject').

    ※ StepRecord 엔 timestamp 없음 -> step 인덱스 순서만. 감독 wire 시각(t)과 절대정렬 불가.
      'accepted' 는 공격 agent 자기-ACK(verdict==OK)일 뿐 ground-truth 아님(감독패널 참조).
    """
    rows: list[dict] = []
    for st in steps:
        tid = st.get("tool_id")
        if tid not in INJECT_TOOL_IDS:
            continue
        verdict = st.get("verdict", "")
        rows.append({
            "source": "attacker-inject",
            "step": st.get("step"),
            "tool_id": tid,
            "layer": layer_of(tid),
            "mode": (st.get("params") or {}).get("mode"),
            "params": st.get("params") or {},
            "verdict": verdict,
            "accepted": verdict == "OK",
            "blocked_by": st.get("blocked_by"),
        })
    return rows


def comms_view(
    eval_obj: Optional[dict],
    stream_frames: list[dict],
    action_steps: list[dict],
) -> dict:
    """통신 패널 뷰. 스트림 우선, 부재 시 evaluation 재구성, 둘 다 없으면 none."""
    if stream_frames:
        source, wire = "stream", stream_frames
    elif eval_obj is not None:
        recon = frames_from_evaluation(eval_obj)
        source, wire = ("reconstructed" if recon else "none"), recon
    else:
        source, wire = "none", []
    return {
        "source": source,
        "wire": wire,
        "injections": inject_rows_from_action(action_steps),
    }


# ═══════════════════════════════════════════════════════════════════════════
# 스냅샷 조립 + 배너(agent≠truth)
# ═══════════════════════════════════════════════════════════════════════════


def _autonomy_agree(eval_obj: Optional[dict]) -> Optional[bool]:
    if not eval_obj:
        return None
    acc = ((eval_obj.get("verdict") or {}).get("autonomy_accuracy")) or {}
    return acc.get("agree")


def build_snapshot(
    action_path: "str | Path",
    eval_path: "str | Path",
    comms_path: "str | Path | None",
) -> dict:
    """3소스 로드 -> 뷰어 스냅샷.

    banner.mismatch = autonomy_accuracy.agree is False (agent 자기판정 ≠ 감독 ground-truth).
      agree==None(감독 claim 부재) 또는 True 이면 mismatch=False.
    """
    action = load_action_log(action_path)
    eval_obj = load_evaluation(eval_path)
    frames = load_comms_stream(comms_path)
    comms = comms_view(eval_obj, frames, action["steps"])

    agree = _autonomy_agree(eval_obj)
    mismatch = agree is False
    if agree is False:
        note = "공격 agent 자기-ACK 판정과 감독 ground-truth 가 불일치(agree=False)."
    elif agree is True:
        note = "공격 agent 자기-ACK 판정과 감독 ground-truth 가 일치(agree=True)."
    elif eval_obj is None:
        note = "감독 evaluation 미탑재 — 동작 로그만 표시(통신은 재구성 불가)."
    else:
        note = "감독 autonomy_accuracy 미확정(agent claim 부재 또는 pending)."
    if comms["source"] == "reconstructed":
        note += " 통신 wire 는 evaluation 에서 재구성(per-frame 스트림 부재)."

    return {
        "action": action,
        "comms": comms,
        "supervisor": {"evaluation": eval_obj},
        "banner": {"mismatch": mismatch, "note": note},
    }


# ═══════════════════════════════════════════════════════════════════════════
# 증분 tail (SSE 폴링용) — 오프셋 기반, CRLF/utf-8, truncate 재동기
# ═══════════════════════════════════════════════════════════════════════════


def tail_lines(path: "str | Path", offset: int) -> "tuple[list[str], int]":
    """오프셋(바이트) 이후 **완결된** JSONL 줄만 반환, (new_lines, new_offset).

    파일 truncate/rotate(size<offset) -> 오프셋 0 리셋 재동기. 미완결 마지막 줄은
    다음 폴링까지 보류(offset 을 그 앞으로 되돌림) -> 부분줄 파싱실패 레이스 제거.
    """
    p = Path(path)
    if not p.exists():
        return [], offset
    try:
        size = p.stat().st_size
    except OSError:
        return [], offset
    if size < offset:  # truncate/rotate 감지 -> 재동기
        offset = 0
    if size == offset:
        return [], offset
    try:
        with p.open("rb") as f:
            f.seek(offset)
            data = f.read()
            new_offset = f.tell()
    except OSError:
        return [], offset
    text = data.decode("utf-8", errors="replace")
    if not text.endswith("\n"):
        idx = text.rfind("\n")
        if idx == -1:
            return [], offset  # 완결 줄 없음 — 다음 폴링 대기
        partial = text[idx + 1:]
        new_offset -= len(partial.encode("utf-8"))
        text = text[: idx + 1]
    lines = [ln for ln in text.split("\n") if ln.strip()]
    return lines, new_offset


def file_mtime(path: "str | Path") -> Optional[float]:
    p = Path(path)
    try:
        return p.stat().st_mtime
    except OSError:
        return None


__all__ = [
    "INJECT_TOOL_IDS", "RECON_TOOL_IDS", "COLLECT_TOOL_IDS", "COPTER_MODE",
    "layer_of", "kind_of", "mode_name", "redact",
    "parse_action_line", "load_action_log", "load_evaluation",
    "parse_frame_line", "load_comms_stream", "frames_from_evaluation",
    "inject_rows_from_action", "comms_view", "build_snapshot",
    "tail_lines", "file_mtime",
]
