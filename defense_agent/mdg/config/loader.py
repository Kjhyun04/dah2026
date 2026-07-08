"""Config loader. Prefers the canonical *.yaml files (pyyaml). Falls back to the
Python-native constants in ``defaults.py`` when pyyaml is unavailable so the
deterministic pipeline and tests run with zero extra deps.

Q-D-4 DOCUMENTATION-ONLY — which keys are ACTUALLY live-read via this loader:
The deterministic SCORING pipeline does NOT read scoring calibration back through
``thresholds()``. It imports the ``defaults.py`` constants DIRECTLY (by design, to
keep the determinism path off the YAML surface): scoring.py reads
D.SEVERITY_FACTOR/BAND_MAP/TRUST_BANDS/IMPACT_BANDS/LOW_CONFIDENCE_THRESHOLD/
IMPACT_BAND_ORDER; compute_trust.py D.METRICS/D.DOMAINS; correlate.py
D.CORRELATION_RULES; intent_ledger.py D.SEQ_WINDOW; ingest/verify.py D.TS_SKEW_S;
driver.py D.DRIVER_BUDGETS; bundle.py D.DEBOUNCE_*/DEESCALATION_*. Therefore the
``severity_factor/band_map/metrics/trust_bands/impact_bands/low_confidence_threshold/
seq_window/ts_skew_s/correlation_rules/driver`` keys in the ``thresholds()`` payload
(and the matching scoring section of thresholds.yaml) are DEAD for scoring — editing
them does NOT recalibrate scoring.
The keys that ARE live-consumed via this loader:
  - thresholds(): rtt_baseline_ms/rtt_mdev_ms (recon.py), evidence_ttl_s (evidence.py),
    llm_response_max_bytes (llm/client.py)
  - mission_profile(): config_version and mission scalars (below)
  - recovery_priors(), models(), input_spec(): consumed by recovery/llm/recon
Do NOT wire the loader into the scoring path to "fix" this — that would move calibration
onto the YAML surface and change the determinism path (불변식①).
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
    # Q-D-4 NOTE: this pyyaml-absent fallback is INTENTIONALLY a SUBSET (non-mirrored) of
    # thresholds.yaml — it omits keys such as ``evidence_ttl_s``, ``llm_response_max_bytes``,
    # ``debounce`` and ``deescalation``. That omission is HARMLESS by construction: every
    # consumer reads via ``.get(key, <default>)`` or falls back to a ``defaults.py`` constant
    # when the key is absent (evidence.evidence_ttl_s -> D.TIME_WINDOWS; llm.client
    # llm_response_max_bytes -> _DEFAULT_MAX_BYTES; recon rtt_* -> literal defaults). So the
    # non-mirror changes no scoring/routing scalar. Do NOT add numeric keys here to "fix" the
    # mirror — that would introduce a value on the fallback path and is a calibration change.
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
def mission_profile() -> dict:
    return _try_yaml("mission_profile.yaml") or D.MISSION_PROFILE


# Q-D-4 DOCUMENTATION-ONLY: this accessor + defaults.CHANNEL_QUALITY + channel_quality.yaml
# (channel_quality/tool_channel/decay) have NO live consumer within mdg (grep-confirmed:
# channel_quality() is never called, CHANNEL_QUALITY is never read). Per-evidence confidence
# comes from the ingest payload — collector/ingest.py sets SensorEv.confidence from
# p.get('confidence', 0.9), and compute_trust.py derives avg_q from those per-evidence values,
# NEVER from these channel priors. The YAML header claiming it feeds "compute_confidence의
# avg_quality" is inaccurate. Kept as a harmless orphan (repo convention: SEQ_SKEW_S,
# score_weights); do NOT delete or retune these priors expecting a scoring effect.
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


@lru_cache(maxsize=1)
def models() -> dict:
    return _try_yaml("models.yaml") or {"roles": {}, "timeout_s": 5}


@lru_cache(maxsize=1)
def input_spec() -> dict:
    """DefInputSpec source (P2). YAML override -> defaults.INPUT_SPEC fallback."""
    return _try_yaml("input_spec.yaml") or D.INPUT_SPEC


def config_version() -> str:
    return str(mission_profile().get("config_version", D.MISSION_PROFILE["config_version"]))
