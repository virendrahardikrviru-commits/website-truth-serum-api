import inspect

import pytest

from app.models.evidence import EvidenceItem
from app.services.evidence import rdap_evidence_items
from app.services.scoring import (
    BASE_SCORE,
    CATEGORY_CAPS,
    MAX_SIGNAL_EFFECT,
    evaluate_evidence,
    summarize,
)


def age_item(effect=0.0, age=500, age_id="RDAP_001"):
    return EvidenceItem(
        id=age_id,
        category="domain",
        signal="domain_age",
        value=age,
        effect=effect,
        confidence=1.0,
        source="rdap",
        explanation="Domain age signal.",
    )


def hold_item(effect=-5.0, states=None):
    return EvidenceItem(
        id="RDAP_002",
        category="domain",
        signal="domain_status",
        value=states or ["clienthold"],
        effect=effect,
        confidence=1.0,
        source="rdap",
        explanation="Hold state signal.",
    )


# ---------- Neutral / boundaries ----------

def test_no_evidence_neutral_score_and_zero_confidence():
    result = evaluate_evidence([])
    assert result.score == 50.0
    assert result.confidence == 0.0
    assert result.category == "moderate"
    assert "No usable evidence" in result.notes[0]
    assert "Insufficient evidence" in summarize(result)


def test_final_score_clamped_within_0_100(monkeypatch):
    caps = dict(CATEGORY_CAPS)
    caps["ssl"] = 50.0
    monkeypatch.setattr("app.services.scoring.CATEGORY_CAPS", caps)
    # Per-signal cap is ±10, so several signals are needed to hit the extremes.
    pos_items = [
        EvidenceItem(id=f"SSL_{i}", category="ssl", signal="x", effect=100.0,
                     confidence=1.0, source="ssl")
        for i in range(5)
    ]
    assert evaluate_evidence(pos_items).score == 100.0
    neg_items = [
        EvidenceItem(id=f"SSL_{i}", category="ssl", signal="x", effect=-100.0,
                     confidence=1.0, source="ssl")
        for i in range(5)
    ]
    assert evaluate_evidence(neg_items).score == 0.0


def test_per_signal_cap():
    result = evaluate_evidence([age_item(effect=50.0)])
    assert result.score == BASE_SCORE + MAX_SIGNAL_EFFECT
    result = evaluate_evidence([age_item(effect=-50.0)])
    assert result.score == BASE_SCORE - MAX_SIGNAL_EFFECT


def test_domain_category_cap():
    # Two +8 signals must not exceed the ±10 domain cap.
    result = evaluate_evidence([age_item(effect=8.0), age_item(effect=8.0)])
    assert result.category_contributions["domain"] == 10.0
    assert result.score == 60.0
    result = evaluate_evidence([hold_item(-8.0), hold_item(-8.0)])
    assert result.score == 40.0


# ---------- RDAP age rules ----------

def test_old_domain_is_55():
    result = evaluate_evidence([age_item(5.0, 4000)])
    assert result.score == 55.0
    assert result.confidence > 0.0


def test_young_domain_is_45():
    result = evaluate_evidence([age_item(-5.0, 10)])
    assert result.score == 45.0
    assert result.category == "untrustworthy"
    assert result.risk_level == "elevated"


def test_middle_aged_domain_is_50_with_usable_evidence():
    result = evaluate_evidence([age_item(0.0, 500)])
    assert result.score == 50.0
    assert result.confidence > 0.0  # usable but neutral -> not zero confidence


def test_hold_status_is_minus_5():
    result = evaluate_evidence([hold_item(-5.0)])
    assert result.score == 45.0


def test_old_plus_hold_is_bounded():
    result = evaluate_evidence([age_item(5.0, 4000), hold_item(-5.0)])
    assert result.score == 50.0  # +5 - 5 = 0, within caps


# ---------- RDAP adapter ----------

def test_rdap_missing_age_and_status_emit_no_items():
    assert rdap_evidence_items({"source": "rdap", "domain_age_days": None, "status": []}) == []


def test_rdap_unavailable_emits_no_items():
    assert rdap_evidence_items({"source": "rdap_unavailable"}) == []
    assert rdap_evidence_items(None) == []


def test_multiple_hold_statuses_do_not_stack():
    rdap = {
        "source": "rdap",
        "domain_age_days": 500,
        "status": ["clientHold", "serverHold", "redemptionPeriod", "pendingDelete"],
    }
    items = rdap_evidence_items(rdap)
    status_items = [i for i in items if i.signal == "domain_status"]
    assert len(status_items) == 1
    assert status_items[0].effect == -5.0
    result = evaluate_evidence(items)
    assert result.score == 45.0  # single -5, not stacked


def test_old_rdap_via_adapter_is_55():
    rdap = {"source": "rdap", "domain_age_days": 4000, "status": []}
    items = rdap_evidence_items(rdap)
    assert len(items) == 1
    assert items[0].effect == 5.0
    assert evaluate_evidence(items).score == 55.0


def test_missing_age_through_adapter_no_penalty():
    rdap = {"source": "rdap", "domain_age_days": None, "status": ["clientHold"]}
    items = rdap_evidence_items(rdap)
    assert [i.signal for i in items] == ["domain_status"]
    assert evaluate_evidence(items).score == 45.0  # hold only, no age penalty


# ---------- Confidence is separate from score ----------

def test_confidence_independent_of_score():
    old = evaluate_evidence([age_item(5.0, 4000)])    # score 55
    young = evaluate_evidence([age_item(-5.0, 10)])   # score 45
    assert old.score == 55.0
    assert young.score == 45.0
    # Same single category => same confidence despite different scores.
    assert old.confidence == pytest.approx(0.41)
    assert young.confidence == old.confidence


def test_confidence_never_zero_when_evidence_usable():
    result = evaluate_evidence([age_item(0.0, 500)])
    assert result.confidence > 0.0
    assert result.score == 50.0  # score neutral but confidence present


# ---------- No domain-name pattern influence ----------

def test_engine_has_no_domain_input():
    signature = inspect.signature(evaluate_evidence)
    assert "domain" not in signature.parameters


def test_domain_string_does_not_affect_score():
    base = [
        EvidenceItem(id="RDAP_001", category="domain", signal="domain_age",
                     value=4000, effect=5.0, confidence=1.0, source="rdap"),
    ]
    result = evaluate_evidence(base)
    # Explanation/ids are free text; results must be identical.
    renamed = [
        EvidenceItem(id="RDAP_001", category="domain", signal="domain_age",
                     value=4000, effect=5.0, confidence=1.0, source="rdap",
                     explanation="google is trusted"),
    ]
    assert evaluate_evidence(renamed).score == result.score
    assert evaluate_evidence(renamed).confidence == result.confidence


# ---------- Category mapping ----------

def test_category_mapping_bands():
    assert evaluate_evidence([age_item(5.0, 4000)]).category == "moderate"  # 55
    assert evaluate_evidence([age_item(-5.0, 10)]).category == "untrustworthy"  # 45

    caps = dict(CATEGORY_CAPS)
    caps["ssl"] = 50.0
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("app.services.scoring.CATEGORY_CAPS", caps)
        high = evaluate_evidence(
            [
                EvidenceItem(id=f"SSL_{i}", category="ssl", signal="x", effect=15.0,
                             confidence=1.0, source="ssl")
                for i in range(3)
            ]
        )
    assert high.score == 80.0
    assert high.category == "trusted"
    assert high.risk_level == "low"
