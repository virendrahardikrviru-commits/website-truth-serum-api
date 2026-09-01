"""Deterministic, evidence-based trust scoring engine (Phase 2a).

The engine starts from a neutral anchor of 50 and applies only real,
explicitly supplied :class:`EvidenceItem` deltas.

Design rules enforced here:

- Never infer facts from domain names (no patterns, no known-domain lists).
- Missing data / unavailable providers produce no item and therefore no
  penalty (they only lower confidence).
- Per-signal effect is capped at ``MAX_SIGNAL_EFFECT``.
- Per-category net effect is capped at ``CATEGORY_CAPS`` so no single
  category can dominate.
- Final score is clamped to 0-100.
- Confidence is computed separately from the score.

In Phase 2a the only active category is ``domain`` (RDAP). Future categories
are listed in ``PLANNED_CATEGORIES`` purely so that confidence reflects how
little of the eventual evidence surface has been measured, but their weights
are NOT active until their collectors exist.
"""

from typing import Dict, List

from app.models.evidence import EvidenceItem, ScoreResult

BASE_SCORE = 50.0
MAX_SIGNAL_EFFECT = 10.0

# Categories with an active, conservative score influence. A category only
# becomes active when its collector actually exists and is trusted.
CATEGORY_CAPS: Dict[str, float] = {
    "domain": 10.0,
    "ssl": 10.0,
    "http": 5.0,
    "security_headers": 5.0,
}

# The full planned evidence surface. Used as the confidence denominator so
# that measuring only one dimension never produces high confidence.
PLANNED_CATEGORIES: tuple = (
    "domain", "ssl", "http", "security_headers", "content", "legal",
    "contact", "intel", "tech", "performance", "reputation",
)


def _band(score: float):
    if score >= 75.0:
        return "trusted", "low"
    if score >= 50.0:
        return "moderate", "moderate"
    if score >= 26.0:
        return "untrustworthy", "elevated"
    return "untrustworthy", "high"


def evaluate_evidence(items: List[EvidenceItem]) -> ScoreResult:
    """Compute a deterministic trust score + confidence from evidence items."""
    if not items:
        return ScoreResult(
            score=BASE_SCORE,
            confidence=0.0,
            category="moderate",
            risk_level="moderate",
            positive_signals=[],
            negative_signals=[],
            applied_evidence=[],
            category_contributions={},
            notes=["No usable evidence was available."],
        )

    grouped: Dict[str, List[EvidenceItem]] = {}
    for item in items:
        grouped.setdefault(item.category, []).append(item)

    total_delta = 0.0
    contributions: Dict[str, float] = {}
    positive: List[str] = []
    negative: List[str] = []
    applied: List[EvidenceItem] = []
    notes: List[str] = []
    conflict = False
    usable_categories: set = set()

    for category, category_items in grouped.items():
        cap = CATEGORY_CAPS.get(category)
        if cap is None:
            notes.append(
                f"Category '{category}' has no active influence; its evidence was not applied."
            )
            continue
        usable_categories.add(category)

        cat_positives = [i for i in category_items if i.effect > 0]
        cat_negatives = [i for i in category_items if i.effect < 0]
        if cat_positives and cat_negatives:
            conflict = True

        category_delta = 0.0
        for item in category_items:
            # Scale by signal confidence, then cap the per-signal effect.
            effect = max(
                -MAX_SIGNAL_EFFECT,
                min(MAX_SIGNAL_EFFECT, item.effect * item.confidence),
            )
            category_delta += effect
            applied.append(item)
            if effect > 0:
                positive.append(item.explanation or f"{item.category}:{item.signal}")
            elif effect < 0:
                negative.append(item.explanation or f"{item.category}:{item.signal}")

        raw_category_delta = category_delta
        category_delta = max(-cap, min(cap, category_delta))
        if category_delta != raw_category_delta:
            notes.append(
                f"Category '{category}' hit its influence cap; "
                f"net effect capped at {cap:g}."
            )
        contributions[category] = round(category_delta, 2)
        total_delta += category_delta

    score = round(max(0.0, min(100.0, BASE_SCORE + total_delta)), 2)

    # Confidence is independent of the score.
    coverage = len(usable_categories) / len(PLANNED_CATEGORIES)
    if usable_categories:
        confidence = 0.35 + 0.65 * coverage
        if conflict:
            confidence *= 0.7
            notes.append(
                "Conflicting evidence detected within a category; confidence reduced."
            )
        confidence = round(min(1.0, confidence), 2)
    else:
        confidence = 0.0

    category, risk_level = _band(score)

    return ScoreResult(
        score=score,
        confidence=confidence,
        category=category,
        risk_level=risk_level,
        positive_signals=positive,
        negative_signals=negative,
        applied_evidence=applied,
        category_contributions=contributions,
        notes=notes,
    )


def summarize(result: ScoreResult) -> str:
    """Deterministic human-readable summary (LLM explanation is a later phase)."""
    if result.confidence == 0.0:
        return (
            "Insufficient evidence is available to assess this website; "
            "additional signals are required."
        )

    if result.score >= 75.0:
        lead = "Multiple positive trust signals were observed."
    elif result.score >= 50.0:
        lead = "Limited or mixed signals; no strong risk indicators were observed."
    else:
        lead = "Several risk indicators were observed."

    parts = [lead]
    if result.positive_signals:
        parts.append("Positive evidence: " + "; ".join(result.positive_signals))
    if result.negative_signals:
        parts.append("Negative evidence: " + "; ".join(result.negative_signals))
    if result.notes:
        parts.append("Notes: " + " ".join(result.notes))
    return " ".join(parts)
