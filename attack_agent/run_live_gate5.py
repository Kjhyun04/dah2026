"""run_live_gate5.py - P5/P6 live campaign + supervisor capture runner.

Runs one live LLM campaign and (optionally) concurrent supervisor ground-truth
capture, then writes:
  - run_live.jsonl (agent output)
  - evaluation_live.json (supervisor verdict)
  - supervisor_live.jsonl (viewer comms frames reconstructed from evaluation)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core import driver as D  # noqa: E402
from core.common.config import load_config, load_goal_spec  # noqa: E402
from supervisor.aria import load_key  # noqa: E402
from supervisor.supervisor import run as supervisor_run  # noqa: E402
from viewer.ingest import frames_from_evaluation, load_evaluation  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="P5/P6 gate-5 live runner: campaign + supervisor outputs."
    )
    p.add_argument("--config", default="configs/config.live.yaml")
    p.add_argument("--goal", default="goals/goal.p4.yaml")
    p.add_argument("--backend", default="local", choices=["local", "ssh", "mock"])
    p.add_argument("--run-out", default="run_live.jsonl")
    p.add_argument("--eval-out", default="evaluation_live.json")
    p.add_argument("--comms-out", default="supervisor_live.jsonl")
    p.add_argument("--supervisor-duration", type=float, default=90.0)
    p.add_argument("--supervisor-lead", type=float, default=2.0)
    p.add_argument("--skip-supervisor", action="store_true")
    p.add_argument("--no-backup", action="store_true")
    return p.parse_args()


def _backup_outputs(paths: list[Path]) -> None:
    existing = [p for p in paths if p.exists()]
    if not existing:
        return
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = _ROOT / "runs" / f"archive_{stamp}"
    dst.mkdir(parents=True, exist_ok=True)
    for p in existing:
        shutil.copy2(p, dst / p.name)


def _cleanup_outputs(paths: list[Path]) -> None:
    for p in paths:
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def _goal_payload(goal_path: str) -> dict[str, Any]:
    spec = load_goal_spec(goal_path)
    g = spec.to_goal()
    return {"type": g.type, "target": dict(g.target)}


def _write_comms_from_eval(eval_path: Path, comms_path: Path) -> int:
    ev = load_evaluation(eval_path)
    frames = frames_from_evaluation(ev or {})
    comms_path.parent.mkdir(parents=True, exist_ok=True)
    with comms_path.open("w", encoding="utf-8") as f:
        for fr in frames:
            f.write(json.dumps(fr, ensure_ascii=False) + "\n")
    return len(frames)


def _run_supervisor_blocking(
    *, goal_path: str, eval_out: Path, run_out: Path, aria_env: str, duration_s: float
) -> dict[str, Any]:
    key = load_key(aria_env)
    goal = _goal_payload(goal_path)
    return supervisor_run(
        key=key,
        goal=goal,
        duration_s=duration_s,
        eval_path=str(eval_out),
        agent_out_log=str(run_out),
    )


async def _run_campaign(
    *, config_path: str, goal_path: str, backend: str, run_out: Path
) -> dict[str, Any]:
    cfg = load_config(config_path)
    gspec = load_goal_spec(goal_path)
    goal = gspec.to_goal()
    defense_seed = gspec.defense if gspec.defense in ("on", "off") else None
    drv = D.build_driver(
        cfg,
        goal,
        backend_kind=backend,
        recon_only=False,
        no_llm=False,
        defense=defense_seed,
    )
    result = await drv.run()
    D.write_jsonl(result, run_out)
    return {
        "goal_reached": bool(result.goal_reached),
        "steps": len(result.chain),
        "defenses_bypassed": list(result.defenses_bypassed),
        "win_causes": list(result.win_causes),
    }


async def main() -> int:
    args = _parse_args()
    run_out = (_ROOT / args.run_out).resolve()
    eval_out = (_ROOT / args.eval_out).resolve()
    comms_out = (_ROOT / args.comms_out).resolve()
    targets = [run_out, eval_out, comms_out]

    if not args.no_backup:
        _backup_outputs(targets)
    _cleanup_outputs(targets)

    cfg = load_config(args.config)
    missing_env: list[str] = []
    if not os.environ.get(cfg.llm.api_key_env):
        missing_env.append(cfg.llm.api_key_env)
    if not args.skip_supervisor and cfg.supervisor.enabled:
        if not os.environ.get(cfg.supervisor.aria_key_env):
            missing_env.append(cfg.supervisor.aria_key_env)
    if missing_env:
        names = ", ".join(sorted(set(missing_env)))
        raise RuntimeError(
            f"required env not exported: {names} "
            f"(run with `source ~/.bashrc; export {names}` or equivalent)"
        )

    sup_task: asyncio.Task | None = None
    if not args.skip_supervisor and cfg.supervisor.enabled:
        sup_task = asyncio.create_task(
            asyncio.to_thread(
                _run_supervisor_blocking,
                goal_path=args.goal,
                eval_out=eval_out,
                run_out=run_out,
                aria_env=cfg.supervisor.aria_key_env,
                duration_s=float(args.supervisor_duration),
            )
        )
        await asyncio.sleep(max(0.0, float(args.supervisor_lead)))

    camp = await _run_campaign(
        config_path=args.config,
        goal_path=args.goal,
        backend=args.backend,
        run_out=run_out,
    )

    sup_summary: dict[str, Any] | None = None
    if sup_task is not None:
        sup_eval = await sup_task
        verdict = (sup_eval.get("verdict") or {}).get("truth_verdict")
        gt = sup_eval.get("ground_truth") or {}
        sup_summary = {
            "truth_verdict": verdict,
            "heartbeats": gt.get("heartbeats"),
            "decrypted_frames": gt.get("decrypted_frames"),
        }

    frames = 0
    if eval_out.exists():
        frames = _write_comms_from_eval(eval_out, comms_out)

    print("RUN:", run_out)
    print("EVAL:", eval_out if eval_out.exists() else "not-generated")
    print("COMMS:", comms_out if comms_out.exists() else "not-generated", f"(frames={frames})")
    print("CAMPAIGN:", json.dumps(camp, ensure_ascii=False))
    if sup_summary is not None:
        print("SUPERVISOR:", json.dumps(sup_summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
