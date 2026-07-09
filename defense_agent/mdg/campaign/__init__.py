"""P6 E2E campaign package — 6-attack replay harness + honesty layer + report artifacts.

  e2e.py       — replay -> detect -> respond -> verify harness (DRY; live = operator-go 유보)
  honest.py    — disclosed limitations (V4/mission-weight/unverified/blast-radius)
  artifacts.py — timeline · decisions · verifier_truth · CampaignResult -> 6-chapter report
  RUNBOOK.md   — live-execution procedure (safety · reversibility · restore)
"""
from __future__ import annotations
