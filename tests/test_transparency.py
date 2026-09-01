"""Evidence transparency: verifies the auditable shape and invariants of the
evidence-mode `/api/analyze/` response.

All external calls (page fetch, RDAP, TLS, HTTP) are mocked. The evidence
engine itself is exercised through the real endpoint assembly.
"""

import os
from unittest import mock

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.evidence import EvidenceItem
from app.services.evidence import rdap_evidence_items
from app.services.rate_limit import SlidingWindowRateLimiter
from app.services.scoring import PLANNED_CATEGORIES, evaluate_evidence
from app.services.transparency import build_transparency

client = TestClient(app)

NEUTRAL_RDAP = {
    "domain": "example.com",
    "registered": None,
    "expires": None,
    "updated": None,
    "registrar": None,
    "nameservers": [],
    "domain_age_days": None,
    "status": [],
    "source": "rdap_unavailable",
    "notes": ["RDAP request timed out."],
}

OLD_RDAP = {
    "domain": "example.com",
    "registered": "1995-08-14",
    "expires": "2027-08-13",
    "updated": "2023-07-20",
    "registrar": "GoDaddy.com, LLC",
    "nameservers": ["ns1.example.com"],
    "domain_age_days": 4000,
    "status": ["ok"],
    "source": "rdap",
    "notes": [],
}


@pytest.fixture(autouse=True)
def _no_network():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, text="<html><title>Test</title></html>")
    )

    with mock.patch("app.routers.analyze._page_fetch_transport", transport), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[],
    ), mock.patch(
        "app.routers.analyze.analyze_http_response",
        return_value=[],
    ), mock.patch(
        "app.routers.analyze.analyze_headers_response",
        return_value=[],
    ), mock.patch(
        "app.routers.analyze.analyze_page_content",
        return_value=[],
    ), mock.patch(
        "app.routers.analyze.scan_rate_limiter",
        SlidingWindowRateLimiter(max_requests=10**6, window_seconds=3600),
    ), mock.patch.dict(os.environ, {"SCORING_MODE": "legacy"}):
        yield


def _tls_item():
    return EvidenceItem(
        id="TLS_001", category="ssl", signal="ssl_valid",
        value={"tls_version": "TLSv1.3"}, effect=8.0,
        confidence=1.0, source="tls",
        explanation="Valid TLS certificate; connection negotiated TLSv1.3.",
    )


def _http_item():
    return EvidenceItem(
        id="HTTP_HTTPS", category="http", signal="https_ok",
        value={"status_code": 200}, effect=2.0,
        confidence=1.0, source="http",
        explanation="HTTPS endpoint responded successfully.",
    )


def _analyze(rdap=NEUTRAL_RDAP, tls=None, http=None, headers=None, url="https://example.com/"):
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=rdap,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=tls if tls is not None else [],
    ), mock.patch(
        "app.routers.analyze.analyze_http_response",
        return_value=http if http is not None else [],
    ), mock.patch(
        "app.routers.analyze.analyze_headers_response",
        return_value=headers if headers is not None else [],
    ):
        return client.post("/api/analyze/", json={"url": url})


def _evidence_response():
    resp = _analyze(rdap=OLD_RDAP, tls=[_tls_item()], http=[_http_item()])
    assert resp.status_code == 200
    return resp.json()


def test_evidence_mode_exposes_all_review_fields():
    data = _evidence_response()
    for field in (
        "trust_score", "confidence", "risk_level", "evidence",
        "category_contributions", "red_flags", "green_flags", "notes",
    ):
        assert field in data, field
    assert isinstance(data["notes"], list)
    assert data["risk_level"] == "moderate"


def test_evidence_items_identify_full_facts():
    data = _evidence_response()
    required_keys = {
        "id", "category", "signal", "value", "effect", "confidence",
        "source", "explanation",
    }
    assert len(data["evidence"]) == 3
    for item in data["evidence"]:
        assert required_keys <= set(item.keys()), item

    rdap_item = next(i for i in data["evidence"] if i["signal"] == "domain_age")
    assert rdap_item["id"] == "RDAP_001"
    assert rdap_item["category"] == "domain"
    assert rdap_item["value"] == 4000
    assert rdap_item["effect"] == 5.0
    assert rdap_item["source"] == "rdap"
    assert isinstance(rdap_item["explanation"], str) and rdap_item["explanation"]


def test_score_reconciles_with_category_contributions():
    data = _evidence_response()
    expected = round(50.0 + sum(data["category_contributions"].values()), 2)
    assert data["trust_score"] == expected
    assert data["category_contributions"] == {"domain": 5.0, "ssl": 8.0, "http": 2.0}
    assert data["trust_score"] == 65.0


def test_confidence_within_0_1():
    data = _evidence_response()
    assert 0.0 <= data["confidence"] <= 1.0
    assert data["confidence"] == pytest.approx(0.53)


def test_unavailable_evidence_is_neutral_not_negative():
    data = _analyze().json()  # default: rdap unavailable, tls/http empty
    assert data["trust_score"] == 50.0
    assert data["confidence"] == 0.0
    assert data["evidence"] == []
    assert data["red_flags"] == []  # unavailability must not create negatives
    assert data["green_flags"] == []
    assert any("No usable evidence" in n for n in data["notes"])


def test_no_fabricated_fields_in_evidence_mode():
    data = _evidence_response()
    assert data["ai_probability"] is None
    assert data["ssl_valid"] is None
    # Every evidence item maps to a genuinely collected signal.
    signals = {i["signal"] for i in data["evidence"]}
    assert signals == {"domain_age", "ssl_valid", "https_ok"}


def test_category_cap_is_transparent():
    # Two TLS signals (16 combined) must be capped at 10 and explained in notes.
    tls = [
        EvidenceItem(id="TLS_001", category="ssl", signal="ssl_valid",
                     value="TLSv1.3", effect=8.0, confidence=1.0, source="tls"),
        EvidenceItem(id="TLS_002", category="ssl", signal="ssl_pinning",
                     value=True, effect=8.0, confidence=1.0, source="tls"),
    ]
    data = _analyze(rdap=OLD_RDAP, tls=tls).json()
    assert data["category_contributions"]["ssl"] == 10.0  # capped, not 16
    assert data["trust_score"] == round(
        50.0 + sum(data["category_contributions"].values()), 2
    )
    assert any("cap" in n and "ssl" in n for n in data["notes"])


def test_legacy_mode_response_unchanged():
    # SCORING_MODE unset -> legacy: no transparency fields populated.
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ):
        resp = client.post("/api/analyze/", json={"url": "https://example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 65
    assert data["confidence"] is None
    assert data["evidence"] is None
    assert data["category_contributions"] is None
    assert data["notes"] is None
    assert data["transparency"] is None
    assert data["ai_probability"] == 40.0
    assert data["ssl_valid"] is True


# ============================================
# V1 Trust & Transparency report
# ============================================

def test_transparency_block_exposes_v1_flow():
    data = _evidence_response()
    t = data["transparency"]
    assert t is not None
    for field in (
        "score", "risk_level", "category", "confidence",
        "verified", "not_determined", "breakdown", "summary",
    ):
        assert field in t, field
    # The projection mirrors the deterministic top-level fields.
    assert t["score"] == data["trust_score"]
    assert t["risk_level"] == data["risk_level"]
    assert t["confidence"] == data["confidence"]
    assert t["breakdown"] == data["category_contributions"]
    assert t["summary"] == data["summary"]


def test_transparency_verified_matches_evidence():
    data = _evidence_response()
    t = data["transparency"]
    assert len(t["verified"]) == len(data["evidence"])
    required_keys = {
        "id", "category", "signal", "source", "effect", "confidence", "explanation",
    }
    for item in t["verified"]:
        assert required_keys <= set(item.keys()), item


def test_transparency_not_determined_is_unknown_not_negative():
    data = _evidence_response()  # domain + ssl + http measured
    t = data["transparency"]
    measured = {v["category"] for v in t["verified"]}
    for category in t["not_determined"]:
        assert category in PLANNED_CATEGORIES
        assert category not in measured
        # Unknown dimensions never influence the score or flags.
        assert category not in data["category_contributions"]
    assert set(t["not_determined"]) == set(PLANNED_CATEGORIES) - measured


def test_transparency_unknown_evidence_is_neutral():
    data = _analyze().json()  # rdap unavailable; no collector produced items
    t = data["transparency"]
    assert t["verified"] == []
    assert t["not_determined"] == list(PLANNED_CATEGORIES)
    assert t["confidence"] == 0.0
    assert t["score"] == 50.0
    assert "Insufficient evidence" in t["summary"]
    # Unknown must not be labeled safe OR dangerous.
    assert data["red_flags"] == []
    assert data["green_flags"] == []
    assert data["category_contributions"] == {}


def test_transparency_ai_explanation_cannot_modify_deterministic_output():
    # Invariant: prose/explanation is derived AFTER scoring. Rewriting it must
    # not change score, confidence, evidence, or the category breakdown.
    items = rdap_evidence_items(OLD_RDAP) + [_tls_item(), _http_item()]
    result = evaluate_evidence(items)
    report_before = build_transparency(result, items)

    for item in items:
        item.explanation = "An AI rewrote this explanation."
    result_after = evaluate_evidence(items)
    report_after = build_transparency(result_after, items)

    assert result_after.score == result.score
    assert result_after.confidence == result.confidence
    assert result_after.applied_evidence == result.applied_evidence
    assert report_after["score"] == report_before["score"]
    assert report_after["confidence"] == report_before["confidence"]
    assert report_after["breakdown"] == report_before["breakdown"]
    assert report_after["risk_level"] == report_before["risk_level"]
    # Only the display prose may differ.
    assert report_after["verified"] != report_before["verified"]


# ============================================
# V1-H1: transparent scoring math
# ============================================

def _rep_item(effect=-10.0, confidence=0.6):
    return EvidenceItem(
        id="REP_MALWARE", category="reputation", signal="malware_hit",
        value={"threat": "malware", "reported_by": ["urlhaus"]},
        effect=effect, confidence=confidence, source="reputation",
        explanation="malware confirmed by 1 provider(s): urlhaus.",
    )


def test_transparency_reports_raw_confidence_applied():
    items = [_rep_item()]  # effect -10, confidence 0.6
    result = evaluate_evidence(items)
    report = build_transparency(result, items)

    verified = report["verified"][0]
    assert verified["raw_effect"] == -10.0
    assert verified["effect"] == -10.0
    assert verified["confidence"] == 0.6
    assert verified["applied_effect"] == -6.0  # -10 * 0.6
    # The contribution reflects the applied effect, not the raw effect.
    assert report["breakdown"]["reputation"] == -6.0


def test_transparency_category_cap_reconciliation():
    tls = [
        EvidenceItem(id="TLS_001", category="ssl", signal="ssl_valid",
                     value=True, effect=8.0, confidence=1.0, source="tls"),
        EvidenceItem(id="TLS_002", category="ssl", signal="ssl_pinning",
                     value=True, effect=8.0, confidence=1.0, source="tls"),
    ]
    items = rdap_evidence_items(OLD_RDAP) + tls  # domain +5, ssl raw 16
    result = evaluate_evidence(items)
    report = build_transparency(result, items)

    detail = report["breakdown_detail"]["ssl"]
    assert detail["raw_sum"] == 16.0
    assert detail["cap"] == 10.0
    assert detail["capped"] is True
    assert detail["applied"] == 10.0
    assert report["breakdown"]["ssl"] == 10.0
    # Cap is explained in the engine notes too.
    assert any("cap" in n and "ssl" in n for n in result.notes)


def test_transparency_reconciliation_matches_score():
    data = _evidence_response()  # domain 5, ssl 8, http 2 -> 65
    rec = data["transparency"]["reconciliation"]
    assert rec["base"] == 50.0
    assert rec["sum_of_contributions"] == 15.0
    assert rec["reconciled_score"] == 65.0
    assert rec["final_score"] == data["trust_score"] == 65.0
    assert rec["exact"] is True
    assert rec["clamped"] is False


def test_transparency_unknown_reconciliation_is_exact():
    data = _analyze().json()
    rec = data["transparency"]["reconciliation"]
    assert rec["contributions"] == {}
    assert rec["sum_of_contributions"] == 0.0
    assert rec["reconciled_score"] == 50.0
    assert rec["final_score"] == 50.0
    assert rec["exact"] is True
