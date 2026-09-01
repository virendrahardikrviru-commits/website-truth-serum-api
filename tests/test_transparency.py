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

    def fake_async_client(*args, **kwargs):
        return httpx.AsyncClient(transport=transport, **kwargs)

    with mock.patch(
        "app.routers.analyze.httpx.AsyncClient", side_effect=fake_async_client
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[],
    ), mock.patch(
        "app.routers.analyze.collect_http",
        new_callable=mock.AsyncMock,
        return_value=[],
    ):
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


def _analyze(rdap=NEUTRAL_RDAP, tls=None, http=None, url="https://example.com/"):
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=rdap,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=tls if tls is not None else [],
    ), mock.patch(
        "app.routers.analyze.collect_http",
        new_callable=mock.AsyncMock,
        return_value=http if http is not None else [],
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
    assert data["ai_probability"] == 40.0
    assert data["ssl_valid"] is True
