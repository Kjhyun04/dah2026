"""supervisor — Independent Verifier(감독): 14555 ARIA 복호 tap -> ground-truth 독립 판정.

doc17 정합. **완전 수동**(패킷 송신 0)·**소유자 특권**(키=env). gcs_proxy netns 공유 사이드카에서
`--cap-add NET_RAW`로 14555 UDP를 raw 캡처(AF_PACKET·무의존, PoC 검증) -> C2Cipher 복호 ->
pymavlink 파싱 -> 판정. **완전분리(grep0):** 이 패키지를 공격 agent(core)가 절대 import/read 안 함.
산출(evaluation.json·supervisor.jsonl)은 사용자/viewer 전용 — agent out.log 와 별개 sink.

파이프라인(단일 프로세스):
  sniff_14555 -> C2Cipher.unwrap -> MAVLink parse -> GroundTruth(mode timeline·signing·uplink cmds)
  -> judge(goal 도달·autonomy_accuracy) -> emit.
작성 2026-07-06.
"""
from __future__ import annotations

import json
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from supervisor.aria import C2Cipher


# ═══════════════════════════════════════════════════════════════════════════
# 1. 수동 캡처 (AF_PACKET raw · 무의존 · 송신 0) — PoC 검증
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class Datagram:
    ts: float
    src_ip: str
    sport: int
    dport: int
    payload: bytes


# 커널 BPF: Ethernet "udp port 14555"(0x38DB) — 커널이 비대상 패킷을 enqueue 전 폐기
# -> 공유 netns 에서 비-C2 트래픽의 clone/queue 비용 ~0(비간섭 footprint 상한, adversary 무증폭).
_BPF_UDP14555 = [
    (0x28, 0, 0, 0x0000000C), (0x15, 0, 10, 0x00000800), (0x30, 0, 0, 0x00000017),
    (0x15, 0, 8, 0x00000011), (0x28, 0, 0, 0x00000014), (0x45, 6, 0, 0x00001FFF),
    (0xB1, 0, 0, 0x0000000E), (0x48, 0, 0, 0x0000000E), (0x15, 2, 0, 0x000038DB),
    (0x48, 0, 0, 0x00000010), (0x15, 0, 1, 0x000038DB), (0x06, 0, 0, 0x00040000),
    (0x06, 0, 0, 0x00000000),
]
_RCVBUF_CAP = 4 * 1024 * 1024  # 수신버퍼 상한(커널메모리 footprint 캡·초과분 커널이 드롭=best-effort)


def _attach_bpf(s: socket.socket):
    """SO_ATTACH_FILTER(가능 시). 실패해도 유저스페이스 포트필터가 방어(defense-in-depth).

    반환한 buffer 는 **호출자가 소켓 수명 동안 참조 유지**해야 한다(GC 시 필터 무효화 방지).
    """
    import ctypes
    prog = b"".join(struct.pack("HBBI", *ins) for ins in _BPF_UDP14555)
    buf = ctypes.create_string_buffer(prog)
    fprog = struct.pack("Hxxxxxx" + "P", len(_BPF_UDP14555), ctypes.addressof(buf))
    try:
        s.setsockopt(socket.SOL_SOCKET, 26, fprog)  # SO_ATTACH_FILTER=26
        return buf
    except OSError:
        return None  # 필터 미부착 -> 유저스페이스 필터로 계속(캡처는 유지)


def sniff_udp14555(*, duration_s: float, max_pkts: int = 100000):
    """gcs_proxy netns 안에서 14555 UDP 를 수동 캡처(bind 안 함·송신 0). Datagram yield.

    14555 를 bind 하지 않는다(프록시 소유). AF_PACKET raw 로 wire 만 읽는다(read-only).
    비간섭: 커널 BPF(udp 14555)로 비대상 폐기 + SO_RCVBUF 상한 -> footprint 캡(adversary 무증폭).
    정확성: IP total_length/UDP length 로 payload 경계 정확 산정 + fragment(MF/offset) 스킵.
    """
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_CAP)
    except OSError:
        pass
    _bpf_keep = _attach_bpf(s)  # noqa: F841 — 소켓 수명 동안 필터 buffer 참조 유지(GC 방지)
    s.settimeout(2.0)
    end = time.time() + duration_s
    n = 0
    try:
        while time.time() < end and n < max_pkts:
            try:
                raw, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            if len(raw) < 42 or struct.unpack("!H", raw[12:14])[0] != 0x0800:
                continue
            ip = raw[14:]
            if len(ip) < 20:
                continue
            ihl = (ip[0] & 0x0F) * 4
            if ip[9] != 17 or ihl < 20:  # UDP
                continue
            frag = struct.unpack("!H", ip[6:8])[0]
            if (frag & 0x2000) or (frag & 0x1FFF):  # MF set or offset!=0 -> 조각(폐기)
                continue
            total_len = struct.unpack("!H", ip[2:4])[0]
            udp = ip[ihl:]
            if len(udp) < 8:
                continue
            sport, dport, udp_len = struct.unpack("!HHH", udp[:6])
            if 14555 not in (sport, dport):
                continue
            # payload 경계: UDP length(헤더8 제외) ∧ IP total_length ∧ 실제 캡처 길이 최소값.
            plen = max(0, min(udp_len - 8, total_len - ihl - 8, len(udp) - 8))
            src = ".".join(map(str, ip[12:16]))
            n += 1
            yield Datagram(time.time(), src, sport, dport, udp[8:8 + plen])
    finally:
        s.close()


# ═══════════════════════════════════════════════════════════════════════════
# 2. 파싱 -> ground-truth 이벤트 (pymavlink)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class MavEvent:
    t: float
    src_ip: str
    mtype: str
    custom_mode: Optional[int] = None   # HEARTBEAT(autopilot)
    target_mode: Optional[int] = None   # 업링크 DO_SET_MODE
    signed: Optional[bool] = None


class Parser:
    """복호 평문 1프레임 -> MavEvent. autopilot HEARTBEAT(comp==1)만 mode ground-truth."""

    def __init__(self) -> None:
        from pymavlink import mavutil
        self._mav = mavutil.mavlink.MAVLink(None)
        self._mav.robust_parsing = True
        self._DO_SET_MODE = mavutil.mavlink.MAV_CMD_DO_SET_MODE

    @staticmethod
    def _safe_int(v) -> Optional[int]:
        """유한 int/float 만 int 로. NaN/inf/bool/그외 -> None (int(nan) ValueError 크래시 방지)."""
        import math
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)) and math.isfinite(v):
            return int(v)
        return None

    def feed(self, pt: bytes, dg: Datagram) -> list[MavEvent]:
        # 각 datagram = 완결 1프레임(프록시 1:1) -> 파서 버퍼 리셋(프레임간 오염 방지).
        try:
            self._mav.buf = bytearray()
            self._mav.buf_index = 0
        except Exception:
            pass
        out: list[MavEvent] = []
        try:
            msgs = self._mav.parse_buffer(pt) or []
        except Exception:
            return out  # 손상 프레임 1개가 전체 캡처·emit 파이프라인을 못 죽인다
        for m in msgs:
            try:
                t = m.get_type()
                signed = bool(getattr(m.get_header(), "incompat_flags", 0) & 0x01)  # IFLAG_SIGNED
                ev = MavEvent(dg.ts, dg.src_ip, t, signed=signed)
                if t == "HEARTBEAT" and m.get_srcComponent() == 1 and getattr(m, "type", 0) != 6:
                    ev.custom_mode = self._safe_int(getattr(m, "custom_mode", None))
                elif t == "COMMAND_LONG" and self._safe_int(getattr(m, "command", -1)) == self._DO_SET_MODE:
                    ev.target_mode = self._safe_int(getattr(m, "param2", None))
                elif t == "SET_MODE":
                    ev.target_mode = self._safe_int(getattr(m, "custom_mode", None))
                out.append(ev)
            except Exception:
                continue
        return out


# ═══════════════════════════════════════════════════════════════════════════
# 3. 판정 (ground-truth · 결정론 · autonomy_accuracy) — 완전분리
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class GroundTruth:
    mode_timeline: list[tuple[float, int]] = field(default_factory=list)
    modes_ever_reached: set[int] = field(default_factory=set)
    final_mode: Optional[int] = None
    uplink_cmds: list[tuple[float, int]] = field(default_factory=list)
    signing_observed: bool = False
    heartbeats: int = 0
    decrypted: int = 0


class Judge:
    """복호 관측 -> GroundTruth 축적 + goal 도달(§2) + autonomy_accuracy."""

    def __init__(self) -> None:
        self.gt = GroundTruth()

    def on_event(self, ev: MavEvent) -> None:
        if ev.signed:
            self.gt.signing_observed = True
        if ev.custom_mode is not None:  # autopilot HEARTBEAT (downlink ground-truth)
            self.gt.heartbeats += 1
            self.gt.final_mode = ev.custom_mode
            self.gt.modes_ever_reached.add(ev.custom_mode)
            if not self.gt.mode_timeline or self.gt.mode_timeline[-1][1] != ev.custom_mode:
                self.gt.mode_timeline.append((ev.t, ev.custom_mode))
        if ev.target_mode is not None:  # 업링크 명령(공격/GCS)
            self.gt.uplink_cmds.append((ev.t, ev.target_mode))

    def goal_truth(self, goal: dict) -> dict:
        """goal.type 별 ground-truth 도달(§2). target=최종상태 아니라 **도달여부**(transient 포함).

        정직 스코프: mode 관측은 다운링크 HEARTBEAT(~1Hz) 표본이라 하트비트 간격 내 도달·원복
          (serial5762 transient)을 놓칠 수 있음(sampling 필드로 명시). signing_bypass 는 '링크에
          서명 강제됨(관측) AND target 도달' 을 뜻하며, 공격자가 서명을 우회했다는 attribution 증명이
          아니다(off-14555 경로 업링크는 안 보임). c2_disrupt 는 복호가 실동작(decrypted>0)일 때만 인정.
        """
        gtype = goal.get("type")
        target = goal.get("target", {}).get("mode")
        target = int(target) if target is not None else None
        reached = target is not None and target in self.gt.modes_ever_reached
        reverted = reached and self.gt.final_mode != target
        uplink_to_target = target is not None and any(tm == target for _, tm in self.gt.uplink_cmds)
        v = {"type": gtype, "target_mode": target,
             "sampling": "heartbeat-rate-limited(~1Hz downlink) — transient 놓칠 수 있음"}
        if gtype in ("mode_set", "signing_bypass"):
            ok = reached
            if gtype == "signing_bypass":
                ok = ok and self.gt.signing_observed  # = 서명강제 관측 AND 도달(attribution 아님)
            v["truth_verdict"] = "success" if ok else "pending"
            v["reached_target"] = reached
            v["reverted"] = reverted                       # 도달했으나 원복(serial5762 자가 revert)
            v["uplink_to_target_on_14555"] = uplink_to_target
            v["signing_enforced_on_link"] = self.gt.signing_observed
            if not reached and self.gt.heartbeats > 0:
                v["note"] = "target 미관측 — heartbeat 표본율 한계로 transient 놓쳤을 가능성"
        elif gtype == "c2_disrupt":
            if self.gt.decrypted == 0:
                v["truth_verdict"] = "no_visibility"       # 캡처/키 문제 vs 실제 두절 구분(위양성 방지)
            else:
                v["truth_verdict"] = "success" if self.gt.heartbeats == 0 else "pending"
        else:
            v["truth_verdict"] = "inconclusive"            # exfil 등은 패킷에 안 나옴(정직)
        return v

    def autonomy_accuracy(self, agent_claim: Optional[dict], truth: dict) -> dict:
        """공격 agent 자기-ACK(agent_claim) <-> 감독 ground-truth 대조(단방향 채점 입력).

        agent_claim = out.log 의 campaign_result(공개·읽기전용). agent 흐름엔 안 돌아감(grep0).
        """
        if agent_claim is None:
            return {"agent_reached": None, "truth_reached": truth.get("truth_verdict") == "success", "agree": None}
        agent_reached = bool(agent_claim.get("goal_reached"))
        truth_reached = truth.get("truth_verdict") == "success"
        return {"agent_reached": agent_reached, "truth_reached": truth_reached,
                "agree": agent_reached == truth_reached}


# ═══════════════════════════════════════════════════════════════════════════
# 4. emit — 사용자/viewer 전용 sink (agent out.log 와 별개·grep0)
# ═══════════════════════════════════════════════════════════════════════════


def read_agent_claim(out_log: Optional[str]) -> Optional[dict]:
    """agent 공개 out.log(JSONL)의 campaign_result 1줄 read-only 회수(단방향 채점 입력)."""
    if not out_log or not Path(out_log).exists():
        return None
    claim = None
    for ln in Path(out_log).read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            d = json.loads(ln)
        except Exception:
            continue
        if d.get("type") == "campaign_result":
            claim = d
    return claim


def build_evaluation(judge: Judge, goal: dict, agent_claim: Optional[dict]) -> dict:
    truth = judge.goal_truth(goal)
    acc = judge.autonomy_accuracy(agent_claim, truth)
    gt = judge.gt
    return {
        "schema": "dah.supervisor.evaluation/1",
        "goal": goal,
        "ground_truth": {
            "signing_observed": gt.signing_observed,
            "mode_timeline": gt.mode_timeline,
            "modes_ever_reached": sorted(gt.modes_ever_reached),
            "final_mode": gt.final_mode,
            "uplink_cmds": gt.uplink_cmds,
            "heartbeats": gt.heartbeats,
            "decrypted_frames": gt.decrypted,
        },
        "verdict": {**truth, "autonomy_accuracy": acc},
    }


def emit(evaluation: dict, *, eval_path: str, agent_out_log: Optional[str]) -> None:
    """evaluation.json 기록. agent out.log 와 **다른 경로** 강제(완전분리·sink 분리).

    무조건 raise(assert 아님) — `python -O`/PYTHONOPTIMIZE 에서도 가드 유효. agent_out_log 미지정 시엔
    비교 대상이 없으므로, 호출자(runner)가 항상 agent out.log 를 넘겨 이 가드가 스킵되지 않게 한다.
    """
    p = Path(eval_path).resolve()
    if agent_out_log and p == Path(agent_out_log).resolve():
        raise RuntimeError("supervisor sink == agent out.log (완전분리 위반)")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(evaluation, ensure_ascii=False, indent=2), encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# 5. runner — 캡처->판정->emit (수동·소유자 특권)
# ═══════════════════════════════════════════════════════════════════════════


def run(
    *,
    key: bytes,
    goal: dict,
    duration_s: float = 12.0,
    eval_path: str = "evaluation.json",
    agent_out_log: Optional[str] = None,
) -> dict:
    """감독 1회 실행: duration_s 동안 14555 복호 관측 -> evaluation 산출·기록. 반환=evaluation."""
    import contextlib
    cipher = C2Cipher(key)
    parser = Parser()
    judge = Judge()
    gen = sniff_udp14555(duration_s=duration_s)
    with contextlib.closing(gen):  # 소비자 예외 시에도 소켓 close 결정론 보장
        for dg in gen:
            try:
                pt = cipher.unwrap(dg.payload)
                if pt is None:
                    continue
                judge.gt.decrypted += 1
                for ev in parser.feed(pt, dg):
                    judge.on_event(ev)
            except Exception:
                continue  # 어떤 프레임도 캡처·emit 파이프라인을 못 죽인다
    agent_claim = read_agent_claim(agent_out_log)
    evaluation = build_evaluation(judge, goal, agent_claim)
    emit(evaluation, eval_path=eval_path, agent_out_log=agent_out_log)
    return evaluation


__all__ = [
    "Datagram", "sniff_udp14555", "MavEvent", "Parser",
    "GroundTruth", "Judge", "read_agent_claim", "build_evaluation", "emit", "run",
]
