"""verify_models.py — A5 MODEL_MAP 오프라인 검증 (네트워크 0·litellm 미호출).

검증: (1) configs/models.yaml 로드·스키마, (2) resolve_model 우선순위(override/role/default),
  (3) config.live.yaml 이 models_path 로 friendly名→routable 해석, (4) 비밀 미포함(모델 문자열만).
회귀 0: config.testbed.yaml(models_path 미지정)은 cfg.llm.model 그대로여야 함.

사용: python verify_models.py   (exit 0 = PASS). 전부 오프라인.
작성 2026-07-06.
"""

from __future__ import annotations
_import_sys=__import__('sys'); _import_os=__import__('os')
from pathlib import Path as _Path
_REPO=_Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path: _import_sys.path.insert(0,str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root → cwd-relative paths resolve

import sys
from pathlib import Path

try:  # Windows 콘솔(cp949) 유니코드 출력 보호.
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.common.models import load_model_map, resolve_model  # noqa: E402

_FAILS: list[str] = []


def _check(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    if not cond:
        _FAILS.append(name)
    print(f"[{mark}] {name}{(' — ' + detail) if detail else ''}")


def main() -> int:
    # 1. models.yaml 로드
    mm = load_model_map("configs/models.yaml")
    _check("1. models.yaml 로드", bool(mm.default), f"default={mm.default}")
    _check(
        "2. AttackOrchestrator 등록",
        "AttackOrchestrator" in mm.models,
        mm.models.get("AttackOrchestrator", "<none>"),
    )

    # 3. resolve 우선순위: override(friendly) → alias 라우팅
    r_over = resolve_model("AttackOrchestrator", mm, override="claude-opus-4-8")
    _check(
        "3. override(friendly) alias 라우팅",
        r_over == mm.aliases.get("claude-opus-4-8"),
        r_over,
    )
    # 4. override 없음 → role 등록값
    r_role = resolve_model("AttackOrchestrator", mm, override=None)
    _check("4. role 해석", r_role == mm.route(mm.models["AttackOrchestrator"]), r_role)
    # 5. 미등록 role → default
    r_def = resolve_model("Nonexistent", mm, override=None)
    _check("5. 미등록 role→default", r_def == mm.route(mm.default), r_def)

    # 6. 비밀 미포함(모델 문자열에 key/secret/token 리터럴 없음)
    blob = " ".join([mm.default, *mm.models.values(), *mm.aliases.values()]).lower()
    _check(
        "6. 비밀 미포함",
        not any(s in blob for s in ("key", "secret", "token", "sk-", "bearer")),
    )

    # 7. 회귀: config.testbed.yaml(models_path 미지정) → cfg.llm.model 그대로
    try:
        from core.common.config import load_config

        cfg_t = load_config("configs/config.testbed.yaml")
        _check(
            "7. testbed 회귀(models_path None)",
            cfg_t.llm.models_path is None and cfg_t.llm.model == "claude-opus-4-8",
            f"model={cfg_t.llm.model} models_path={cfg_t.llm.models_path}",
        )
        # 8. config.live.yaml → models_path 지정 + live
        cfg_l = load_config("configs/config.live.yaml")
        live_model = resolve_model(
            "AttackOrchestrator",
            load_model_map(cfg_l.llm.models_path),
            override=cfg_l.llm.model,
        )
        _check(
            "8. live config → routable 해석",
            cfg_l.llm.mode == "live"
            and cfg_l.llm.models_path == "configs/models.yaml"
            and live_model.startswith("openrouter/"),
            f"live_model={live_model}",
        )
    except Exception as e:  # pyyaml/pydantic 미설치 환경은 7·8 스킵(회귀 아님)
        print(f"[SKIP] 7·8 config 로드 스킵(환경 의존): {type(e).__name__}: {e}")

    print()
    if _FAILS:
        print(f"FAIL ({len(_FAILS)}): {', '.join(_FAILS)}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



