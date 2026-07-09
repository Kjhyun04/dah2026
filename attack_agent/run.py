"""run.py — 엔트리포인트 CLI (10 §1 · 13 §6). config+goal -> recon-only 폐루프 -> JSONL.

사용:
  python run.py --config config.yaml --goal goal.yaml [--recon-only] [--backend mock|local|ssh]
  python run.py --config config.yaml --goal-expr "mode_set mode=4 defense=on"
                [--no-llm] [--out run.jsonl]

완전 오프라인 기본: --backend mock + --no-llm(seed-only) -> docker/테스트베드 무접속으로
  부트스트랩 폐루프(config->WorldState->backend->runner_factory->recon 시드->CampaignResult)를
  로컬 검증한다. local/ssh 백엔드·live LLM 은 사람 런북(gate-1) 전용(여기서 강제하지 않음).
recon-only(기본 on): 노출/실행 tool 이 RECON 계층뿐 -> 주입(INJECT) tool 미실행.
작성 2026-07-06.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

try:  # Windows 콘솔(cp949) 유니코드 출력 보호.
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

# run.py 는 repo 루트 -> core 패키지가 sys.path 에 있도록 보장(직접 실행 대비).
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.common.config import GoalSpec, load_config, load_goal_spec, parse_goal_expr  # noqa: E402
from core.driver import build_driver, campaign_to_jsonl, write_jsonl  # noqa: E402


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="attack_agent",
        description="DAH 2026 공격계획 에이전트 — recon-only run-driver (오프라인 기본).",
    )
    p.add_argument("--config", required=True, help="config.yaml 경로(10 §2).")
    p.add_argument("--goal", default=None, help="goal.yaml 경로(10 §2-C).")
    p.add_argument(
        "--goal-expr",
        default=None,
        help="CLI 목표 문자열(예: 'mode_set mode=4 defense=on success=ack scope=A,C').",
    )
    p.add_argument(
        "--backend",
        choices=["mock", "local", "ssh"],
        default=None,
        help="실행 백엔드(미지정: no-llm=mock, 아니면 config.exec.mode 파생).",
    )
    p.add_argument(
        "--recon-only",
        dest="recon_only",
        action="store_true",
        default=True,
        help="RECON 계층만 노출·실행(주입 tool 미실행). 기본 on.",
    )
    p.add_argument(
        "--full",
        dest="recon_only",
        action="store_false",
        help="recon-only 해제(전 계층 노출) — 런북 전용.",
    )
    p.add_argument(
        "--no-llm",
        dest="no_llm",
        action="store_true",
        default=True,
        help="LLM 루프 생략(recon 시드-only 결정론). 오프라인 기본 on.",
    )
    p.add_argument(
        "--llm",
        dest="no_llm",
        action="store_false",
        help="LLM ReAct 루프 활성(replay/live) — 런북 전용.",
    )
    p.add_argument("--out", default=None, help="JSONL 산출 경로(미지정: config.out.log).")
    p.add_argument("--docker-bin", default="docker", help="docker CLI(하드코딩 0).")
    return p.parse_args(argv)


async def _run(ns: argparse.Namespace) -> int:
    if not ns.goal and not ns.goal_expr:
        raise ValueError("either --goal or --goal-expr is required")
    if ns.goal and ns.goal_expr:
        raise ValueError("use only one of --goal or --goal-expr")

    cfg = load_config(ns.config)
    if ns.goal:
        gspec = load_goal_spec(ns.goal)
    else:
        gspec = GoalSpec.model_validate(parse_goal_expr(ns.goal_expr))
    goal = gspec.to_goal()
    defense_seed = gspec.defense if gspec.defense in ("on", "off") else None
    driver = build_driver(
        cfg,
        goal,
        backend_kind=ns.backend,
        docker_bin=ns.docker_bin,
        recon_only=ns.recon_only,
        no_llm=ns.no_llm,
        defense=defense_seed,
    )
    result = await driver.run()

    out_path = ns.out or cfg.out.log
    written = write_jsonl(result, out_path)
    # stdout 요약(심사 가독) + 파일 경로.
    sys.stdout.write(campaign_to_jsonl(result))
    sys.stdout.write(f"# JSONL written: {written}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ns = _parse_args(argv)
    return asyncio.run(_run(ns))


if __name__ == "__main__":
    raise SystemExit(main())
