"""V1 Trust & Transparency: a pure, read-only projection of the evidence engine.

Converts the deterministic ``ScoreResult`` + collected evidence into the
user-facing trust report contract:

    score -> risk_level -> confidence -> verified -> not_determined -> breakdown

Design rules enforced here:

- It NEVER feeds data back into ``app.services.scoring.evaluate_evidence``.
  Explanations and the summary are derived *after* the score is computed and
  are display-only. This enforces the invariant that AI/prose explanations
  cannot modify the deterministic score, confidence, or evidence.
- "Not determined" means *unknown*: a planned evidence category with no
  collected item is listed as not-measured, never as a positive or negative
  signal. Unknown != Safe/Dangerous.
- It adds no collectors and never redesigns the scoring engine. The per-signal
  ``applied_effect`` and per-category caps are computed with the SAME formula
  the engine uses, so the report exposes what actually happened to the score.

Scoring math exposed here (mirrors ``app.services.scoring``):

    raw_effect       = the signed effect recorded by the collector
    confidence       = the collector/engine confidence for that signal
    applied_effect   = clamp(raw_effect * confidence, +/- MAX_SIGNAL_EFFECT)
    raw category sum = sum of applied_effect for the category
    applied category = clamp(raw category sum, +/- category cap)
    final score      = clamp(BASE_SCORE + sum of applied categories, 0..100)
"""

from typing import Any, Dict, List

from app.models.evidence import EvidenceItem, ScoreResult
from app.services.scoring import (
    BASE_SCORE,
    CATEGORY_CAPS,
    MAX_SIGNAL_EFFECT,
    PLANNED_CATEGORIES,
    summarize,
)


def _applied_effect(item: EvidenceItem) -> float:
    """The per-signal effect the engine actually applies (effect * confidence,
    clamped to +/- MAX_SIGNAL_EFFECT). Identical to the engine's formula."""
    return max(
        -MAX_SIGNAL_EFFECT,
        min(MAX_SIGNAL_EFFECT, item.effect * item.confidence),
    )


def _category_detail(category: str, items: List[EvidenceItem]) -> Dict[str, Any]:
    """Per-category cap reconciliation: raw sum vs applied (capped) value."""
    cap = CATEGORY_CAPS.get(category)
    applied = [_applied_effect(i) for i in items if i.category == category]
    raw_sum = round(sum(applied), 2)
    if cap is None:
        return {
            "raw_sum": raw_sum,
            "cap": None,
            "applied": raw_sum,
            "capped": False,
        }
    capped = abs(sum(applied)) > cap
    applied_contribution = round(max(-cap, min(cap, sum(applied))), 2)
    return {
        "raw_sum": raw_sum,
        "cap": cap,
        "applied": applied_contribution,
        "capped": capped,
    }


def _reconciliation(result: ScoreResult) -> Dict[str, Any]:
    """Expose the arithmetic that produced the final score."""
    contributions = dict(result.category_contributions)
    sum_contributions = round(sum(contributions.values()), 2)
    reconciled = round(BASE_SCORE + sum_contributions, 2)
    return {
        "base": BASE_SCORE,
        "contributions": contributions,
        "sum_of_contributions": sum_contributions,
        "reconciled_score": reconciled,
        "final_score": result.score,
        "exact": reconciled == result.score,
        "clamped": result.score in (0.0, 100.0) and reconciled != result.score,
    }


def build_transparency(
    result: ScoreResult, items: List[EvidenceItem]
) -> Dict[str, Any]:
    """Project a ScoreResult + collected evidence into the V1 transparency report.

    ``items`` is the raw evidence collected this scan (unfiltered). ``result``
    is the deterministic engine output. Every field is derived from these two
    values; nothing here can mutate them.
    """
    verified = [
        {
            "id": item.id,
            "category": item.category,
            "signal": item.signal,
            "source": item.source,
            "raw_effect": item.effect,
            "effect": item.effect,
            "confidence": item.confidence,
            "applied_effect": round(_applied_effect(item), 2),
            "explanation": item.explanation,
        }
        for item in items
    ]

    measured = {item.category for item in items}
    not_determined = [
        category for category in PLANNED_CATEGORIES if category not in measured
    ]

    categories = sorted(measured & set(CATEGORY_CAPS))
    breakdown_detail = {
        category: _category_detail(category, items) for category in categories
    }

    return {
        "score": result.score,
        "risk_level": result.risk_level,
        "category": result.category,
        "confidence": result.confidence,
        "verified": verified,
        "not_determined": not_determined,
        "breakdown": dict(result.category_contributions),
        "breakdown_detail": breakdown_detail,
        "reconciliation": _reconciliation(result),
        "summary": summarize(result),
    }
