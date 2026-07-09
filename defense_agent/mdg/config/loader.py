"""Config 로더. 정규 *.yaml 파일(pyyaml)을 우선한다. pyyaml 이 없으면 defaults.py 의
Python 네이티브 상수로 폴백하여 결정론 파이프라인과 테스트가 추가 의존성 없이 동작한다.

Q-D-4 문서 전용 — 이 로더를 통해 실제로 live-read 되는 키는 무엇인가:
결정론 SCORING 파이프라인은 thresholds() 를 거쳐 스코어링 보정값을 다시 읽지 않는다.
defaults.py 상수를 직접 import 한다(설계상, 결정론 경로를 YAML 표면에서 떼어놓기 위함):
scoring.py 는 D.SEVERITY_FACTOR/BAND_MAP/TRUST_BANDS/IMPACT_BANDS/LOW_CONFIDENCE_THRESHOLD/
IMPACT_BAND_ORDER 를, compute_trust.py 는 D.METRICS/D.DOMAINS 를, correlate.py 는
D.CORRELATION_RULES 를, intent_ledger.py 는 D.SEQ_WINDOW 를, ingest/verify.py 는 D.TS_SKEW_S 를,
driver.py 는 D.DRIVER_BUDGETS 를, bundle.py 는 D.DEBOUNCE_*/DEESCALATION_* 를 읽는다. 따라서
thresholds() 페이로드 안의
severity_factor/band_map/metrics/trust_bands/impact_bands/low_confidence_threshold/
seq_window/ts_skew_s/correlation_rules/driver 키(및 thresholds.yaml 의 대응 scoring 섹션)는
스코어링 관점에서 DEAD 이다 — 이들을 편집해도 스코어링이 재보정되지 않는다.
이 로더를 통해 실제로 live-consume 되는 키:
  - thresholds(): rtt_baseline_ms/rtt_mdev_ms (recon.py), evidence_ttl_s (evidence.py),
    llm_response_max_bytes (llm/client.py)
  - mission_profile(): config_version 및 mission 스칼라(아래)
  - recovery_priors(), models(), input_spec(): recovery/llm/recon 에서 소비
이를 "고치려고" 로더를 스코어링 경로에 배선하지 마라 — 그러면 보정값이 YAML 표면으로 옮겨가
결정론 경로가 바뀐다(불변식1.).
"""
from __future__ import annotations

import os
from functools import lru_cache

from . import defaults as D

_CFG_DIR = os.path.dirname(os.path.abspath(__file__))


def _try_yaml(name: str) -> dict | None:
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    path = os.path.join(_CFG_DIR, name)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@lru_cache(maxsize=1)
def thresholds() -> dict:
    y = _try_yaml("thresholds.yaml")
    if y:
        return y
    # Q-D-4 주의: 이 pyyaml-부재 폴백은 의도적으로 thresholds.yaml 의 SUBSET(비-미러)이다 —
    # evidence_ttl_s, llm_response_max_bytes, debounce, deescalation 같은 키를 생략한다.
    # 이 생략은 구조적으로 HARMLESS 하다: 모든 소비자는 .get(key, <default>) 로 읽거나
    # 키가 없으면 defaults.py 상수로 폴백한다(evidence.evidence_ttl_s -> D.TIME_WINDOWS; llm.client
    # llm_response_max_bytes -> _DEFAULT_MAX_BYTES; recon rtt_* -> 리터럴 기본값). 따라서
    # 비-미러는 어떤 scoring/routing 스칼라도 바꾸지 않는다. "미러를 고치려고" 여기에 숫자 키를
    # 추가하지 마라 — 그러면 폴백 경로에 값이 도입되어 보정 변경이 된다.
    return {
        "severity_factor": D.SEVERITY_FACTOR,
        "band_map": D.BAND_MAP,
        "metrics": D.METRICS,
        "trust_bands": {k: list(v) for k, v in D.TRUST_BANDS.items()},
        "impact_bands": {k: list(v) for k, v in D.IMPACT_BANDS.items()},
        "low_confidence_threshold": D.LOW_CONFIDENCE_THRESHOLD,
        "seq_window": D.SEQ_WINDOW,
        "ts_skew_s": D.TS_SKEW_S,
        "rtt_baseline_ms": D.RTT_BASELINE_MS,
        "rtt_mdev_ms": D.RTT_MDEV_MS,
        "rtt_k": D.RTT_K,
        "correlation_rules": D.CORRELATION_RULES,
        "driver": D.DRIVER_BUDGETS,
    }


@lru_cache(maxsize=1)
def demo_mode() -> dict:
    """Phase 2 (PS-7/B3) demo-mode 완화 노브. thresholds.yaml demo_mode 블록 ->
    defaults 폴백. 반환값은 operator_auto(sandbox demo) 에서만 적용된다;
    production(operator_auto off)은 절대 참조하지 않으므로 엄격 태세는 영향받지 않는다."""
    thr = thresholds()
    dm = thr.get("demo_mode") if isinstance(thr, dict) else None
    if isinstance(dm, dict):
        return {
            "provenance_relaxed": bool(dm.get("provenance_relaxed", D.DEMO_PROVENANCE_RELAXED)),
            "debounce_ticks": int(dm.get("debounce_ticks", D.DEMO_DEBOUNCE_TICKS)),
        }
    return {"provenance_relaxed": D.DEMO_PROVENANCE_RELAXED,
            "debounce_ticks": D.DEMO_DEBOUNCE_TICKS}


@lru_cache(maxsize=1)
def mission_profile() -> dict:
    return _try_yaml("mission_profile.yaml") or D.MISSION_PROFILE


# Q-D-4 문서 전용: 이 accessor + defaults.CHANNEL_QUALITY + channel_quality.yaml
# (channel_quality/tool_channel/decay)은 mdg 내부에 live 소비자가 없다(grep 확인:
# channel_quality() 는 호출되지 않고 CHANNEL_QUALITY 는 읽히지 않는다). 증거별 confidence 는
# ingest 페이로드에서 온다 — collector/ingest.py 가 SensorEv.confidence 를
# p.get('confidence', 0.9) 로 설정하고, compute_trust.py 는 그 증거별 값에서 avg_q 를 유도한다,
# 절대 이 채널 prior 로부터가 아니다. 그것이 "compute_confidence의
# avg_quality" 를 공급한다는 YAML 헤더 주장은 부정확하다. 무해한 orphan 으로 보존(repo 관례: SEQ_SKEW_S,
# score_weights); 스코어링 효과를 기대하고 이 prior 를 삭제하거나 재조정하지 마라.
@lru_cache(maxsize=1)
def channel_quality() -> dict:
    y = _try_yaml("channel_quality.yaml")
    if y:
        return y
    return {"channel_quality": D.CHANNEL_QUALITY}


@lru_cache(maxsize=1)
def recovery_priors() -> dict:
    y = _try_yaml("recovery_priors.yaml")
    if y:
        return y
    return {"recovery_priors": D.RECOVERY_PRIORS,
            "success_prob_feasible_min": D.RECOVERY_FEASIBLE_MIN,
            "default_enforce_at": D.RECOVERY_DEFAULT_ENFORCE_AT}


def _apply_model_env(cfg: dict) -> dict:
    """.env 오버레이로 supervisor 가 models.yaml 을 편집하지 않고 model slug + key-env 를 설정한다.
    전부 선택적; 미설정 => yaml 불변. dict 에는 env NAME 만 들어간다 — key VALUE 는 절대 아니다
    (PS-3: 값은 나중에 client.resolve_api_key 가 os.environ 에서 해석한다).
      MDG_LLM_API_KEY     — key VALUE(provider 무관). 존재하면 api_key_env 를
                            자기 자신으로 가리켜 has_api_key()/client 가 찾는다.
      MDG_LLM_API_KEY_ENV — api_key_env NAME 오버라이드(provider 관례 키); 우선한다.
      MDG_ORIENT_MODEL / MDG_DECIDE_MODEL       — 역할별 primary slug (openrouter/…, anthropic/…, openai/…, gemini/…).
      MDG_ORIENT_FALLBACK / MDG_DECIDE_FALLBACK — 콤마 리스트; '' 는 비운다(provider 전환 시 동일 provider slug).
    """
    if not isinstance(cfg, dict):
        return cfg
    name = os.environ.get("MDG_LLM_API_KEY_ENV")
    if name:
        cfg["api_key_env"] = name
    elif os.environ.get("MDG_LLM_API_KEY"):
        cfg["api_key_env"] = "MDG_LLM_API_KEY"
    roles = cfg.get("roles")
    if isinstance(roles, dict):
        for role, mkey, fkey in (("orient", "MDG_ORIENT_MODEL", "MDG_ORIENT_FALLBACK"),
                                 ("decide", "MDG_DECIDE_MODEL", "MDG_DECIDE_FALLBACK")):
            rc = roles.get(role)
            if not isinstance(rc, dict):
                continue
            m = os.environ.get(mkey)
            if m and m.strip():
                rc["model"] = m.strip()
            fb = os.environ.get(fkey)
            if fb is not None:
                rc["fallback"] = [s.strip() for s in fb.split(",") if s.strip()]
    return cfg


@lru_cache(maxsize=1)
def models() -> dict:
    return _apply_model_env(_try_yaml("models.yaml") or {"roles": {}, "timeout_s": 5})


@lru_cache(maxsize=1)
def input_spec() -> dict:
    """DefInputSpec 소스 (P2). YAML 오버라이드 -> defaults.INPUT_SPEC 폴백."""
    return _try_yaml("input_spec.yaml") or D.INPUT_SPEC


def config_version() -> str:
    return str(mission_profile().get("config_version", D.MISSION_PROFILE["config_version"]))
