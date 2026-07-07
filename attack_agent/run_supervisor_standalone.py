#!/usr/bin/env python3
"""run_supervisor_standalone.py — A(감독 분리) ops 글루.

core/agent 로직 변경 0. 기존 supervisor.run() 과 run_live_gate5._goal_payload 만 호출해
gcs_proxy netns 별도 프로세스로 감독(ground-truth)을 독립 실행한다.
캠페인(run_live_gate5.py --skip-supervisor, 호스트 netns)과 동시 구동 → agent≠truth 검증.

사용:
  sudo nsenter -t <gcs_pid> -n env ARIA_KEY=... \
    .venv/bin/python run_supervisor_standalone.py <goal.yaml> <duration_s>
"""
import sys

sys.path.insert(0, ".")
from supervisor.aria import load_key  # noqa: E402
from supervisor.supervisor import run as srun  # noqa: E402
from run_live_gate5 import _goal_payload  # noqa: E402

goal_path = sys.argv[1] if len(sys.argv) > 1 else "goals/goal.land.yaml"
duration = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0

ev = srun(
    key=load_key("ARIA_KEY"),
    goal=_goal_payload(goal_path),
    duration_s=duration,
    eval_path="evaluation_live.json",
    agent_out_log="run_live.jsonl",
)

v = ev.get("verdict") or {}
gt = ev.get("ground_truth") or {}
print(
    "SUP_DONE truth_verdict=%s reached_target=%s final_mode=%s "
    "modes_ever=%s heartbeats=%s frames=%s"
    % (
        v.get("truth_verdict"),
        v.get("reached_target"),
        gt.get("final_mode"),
        gt.get("modes_ever_reached"),
        gt.get("heartbeats"),
        gt.get("decrypted_frames"),
    )
)
