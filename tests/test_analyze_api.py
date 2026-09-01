from datetime import date
import os
from unittest import mock

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.evidence import EvidenceItem

client = TestClient(app)

# Neutral default so no test accidentally hits the real RDAP network.
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


@pytest.fixture(autouse=True)
def _no_network():
    """Fake the page fetch and default the RDAP lookup to a neutral result."""
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
    ), mock.patch(
        "app.routers.analyze.collect_security_headers",
        new_callable=mock.AsyncMock,
        return_value=[],
    ):
        yield


def _rdap(age_days=None, status=None, source="rdap"):
    return {
        "domain": "example.com",
        "registered": "1995-08-14" if age_days else None,
        "expires": "2027-08-13",
        "updated": "2023-07-20",
        "registrar": "GoDaddy.com, LLC",
        "nameservers": ["ns1.example.com"],
        "domain_age_days": age_days,
        "status": status or [],
        "source": source,
        "notes": [],
    }


def _analyze(url="https://example.com/"):
    return client.post("/api/analyze/", json={"url": url})


# ---------- Normal domain with successful RDAP ----------

def test_analyze_normal_domain_with_rdap():
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=_rdap(age_days=(date.today() - date(1995, 8, 14)).days, status=["ok"]),
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["domain_intel"]["source"] == "rdap"
    assert data["domain_intel"]["domain_age_days"] > 0
    assert data["domain_intel"]["registrar"] == "GoDaddy.com, LLC"
    assert data["domain_intel"]["nameservers"] == ["ns1.example.com"]


# ---------- Old domain ----------

def test_analyze_old_domain_small_boost():
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=_rdap(age_days=12000, status=["ok"]),
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    # example.com is "moderate" (score 65); old age adds a bounded +5.
    assert data["trust_score"] == 70
    assert any("well-established" in f.lower() for f in data["green_flags"])
    assert data["domain_age"] == "32 years, 10 months"


# ---------- Very young domain ----------

def test_analyze_young_domain_small_penalty():
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=_rdap(age_days=10, status=["ok"]),
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 60
    assert any("recently" in f.lower() for f in data["red_flags"])
    assert data["domain_age"] == "10 days"


# ---------- Hold / suspension status ----------

def test_analyze_hold_status_negative():
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=_rdap(age_days=500, status=["clientHold"]),
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 60
    assert any("suspension" in f.lower() for f in data["red_flags"])


# ---------- Missing RDAP fields (neutral) ----------

def test_analyze_missing_rdap_fields_neutral():
    missing = {
        "domain": "example.com",
        "registered": None,
        "expires": None,
        "updated": None,
        "registrar": None,
        "nameservers": [],
        "domain_age_days": None,
        "status": [],
        "source": "rdap",
        "notes": ["RDAP did not provide a registration date."],
    }
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=missing,
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 65  # unchanged from baseline
    assert data["domain_age"] == "3 years"  # safe fallback preserved
    assert data["domain_intel"]["source"] == "rdap"
    assert data["domain_intel"]["domain_age_days"] is None


# ---------- RDAP unavailable (no score change) ----------

def test_analyze_rdap_unavailable_keeps_score():
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 65
    assert data["domain_age"] == "3 years"
    assert data["domain_intel"]["source"] == "rdap_unavailable"


# ---------- RDAP failure must not break /api/analyze ----------

def test_analyze_succeeds_when_rdap_raises():
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        side_effect=RuntimeError("boom"),
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 65
    assert data["domain_age"] == "3 years"
    assert data["domain_intel"] is None


# ---------- Existing behavior intact ----------

def test_analyze_trusted_domain_existing_behavior():
    # github.com matches the existing trusted pattern (score 95 baseline).
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ):
        resp = _analyze("https://github.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 95
    assert data["category"] == "trusted"
    assert data["domain_intel"]["source"] == "rdap_unavailable"


def test_analyze_invalid_url_rejected():
    resp = client.post("/api/analyze/", json={"url": "not-a-url"})
    assert resp.status_code == 422


# ---------- Evidence mode (SCORING_MODE=evidence) ----------

@pytest.fixture()
def evidence_mode():
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}):
        yield


def test_evidence_mode_old_domain_not_100(evidence_mode):
    # github.com with only RDAP old-age evidence must NOT reach 100.
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=_rdap(age_days=6902, status=["ok"]),
    ):
        resp = _analyze("https://github.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 55
    assert data["category"] == "moderate"
    assert data["domain_age"] == "18 years, 11 months"
    assert data["ai_probability"] is None
    assert data["ssl_valid"] is None
    assert data["confidence"] == 0.41
    assert data["domain_intel"]["source"] == "rdap"
    assert len(data["evidence"]) == 1
    assert data["evidence"][0]["signal"] == "domain_age"


def test_evidence_mode_young_domain(evidence_mode):
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=_rdap(age_days=10, status=["ok"]),
    ):
        resp = _analyze("https://newtest.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 45
    assert data["category"] == "untrustworthy"
    assert data["risk_level"] == "elevated"
    assert data["red_flags"] == ["Domain age is 10 days."]
    assert data["domain_age"] == "10 days"


def test_evidence_mode_rdap_unavailable_neutral(evidence_mode):
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ):
        resp = _analyze("https://example.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 50
    assert data["confidence"] == 0.0
    assert data["evidence"] == []
    assert data["ai_probability"] is None
    assert "Insufficient evidence" in data["summary"]


def test_evidence_mode_rdap_failure_neutral(evidence_mode):
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        side_effect=RuntimeError("boom"),
    ):
        resp = _analyze("https://example.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 50
    assert data["confidence"] == 0.0
    assert data["domain_intel"] is None


def test_evidence_mode_hold_status(evidence_mode):
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=_rdap(age_days=500, status=["clientHold"]),
    ):
        resp = _analyze("https://example.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 45
    assert any("suspension" in f.lower() for f in data["red_flags"])


def test_default_mode_is_legacy():
    # With SCORING_MODE unset, legacy Phase-1 behavior must be preserved.
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ):
        resp = _analyze("https://example.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 65  # legacy pattern baseline
    assert data["ai_probability"] == 40.0
    assert data["confidence"] is None
    assert data["ssl_valid"] is True


# ---------- Evidence mode: TLS + HTTP collectors ----------

def _tls_item(effect, signal="ssl_valid"):
    return EvidenceItem(
        id="TLS_001" if effect > 0 else "TLS_ERR",
        category="ssl",
        signal=signal,
        effect=effect,
        confidence=1.0,
        source="tls",
        explanation=(
            None
            if effect > 0
            else "TLS certificate verification failed during the connection handshake."
        ),
    )


def _http_item(effect, signal="https_ok"):
    return EvidenceItem(
        id="HTTP_HTTPS",
        category="http",
        signal=signal,
        effect=effect,
        confidence=1.0,
        source="http",
    )


def test_evidence_mode_tls_valid(evidence_mode):
    with mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[_tls_item(8.0)],
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 58  # 50 + 8
    assert data["category_contributions"]["ssl"] == 8.0
    assert any(e["signal"] == "ssl_valid" for e in data["evidence"])


def test_evidence_mode_tls_failure(evidence_mode):
    with mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[_tls_item(-10.0, signal="ssl_error")],
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 40  # 50 - 10
    assert any("TLS" in f for f in data["red_flags"])


def test_evidence_mode_http_https(evidence_mode):
    with mock.patch(
        "app.routers.analyze.collect_http",
        new_callable=mock.AsyncMock,
        return_value=[_http_item(2.0)],
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 52  # 50 + 2
    assert data["category_contributions"]["http"] == 2.0


def test_evidence_mode_combined_rdap_tls_http(evidence_mode):
    with mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=_rdap(age_days=4000, status=["ok"]),
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[_tls_item(8.0)],
    ), mock.patch(
        "app.routers.analyze.collect_http",
        new_callable=mock.AsyncMock,
        return_value=[_http_item(2.0)],
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 65  # 50 + 5 (domain) + 8 (ssl) + 2 (http)
    assert data["category_contributions"] == {"domain": 5.0, "ssl": 8.0, "http": 2.0}
    assert data["confidence"] == 0.53  # 3 of 11 planned categories usable
    assert len(data["evidence"]) == 3


def test_evidence_mode_collectors_never_crash_analyze(evidence_mode):
    with mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        side_effect=RuntimeError("tls boom"),
    ), mock.patch(
        "app.routers.analyze.collect_http",
        new_callable=mock.AsyncMock,
        side_effect=RuntimeError("http boom"),
    ), mock.patch(
        "app.routers.analyze.collect_security_headers",
        new_callable=mock.AsyncMock,
        side_effect=RuntimeError("headers boom"),
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 50  # collectors unavailable -> neutral
    assert data["confidence"] == 0.0
    assert data["evidence"] == []


def test_evidence_mode_security_headers(evidence_mode):
    with mock.patch(
        "app.routers.analyze.collect_security_headers",
        new_callable=mock.AsyncMock,
        return_value=[
            EvidenceItem(
                id="HDR_HSTS", category="security_headers", signal="hsts",
                value="max-age=31536000", effect=1.0, confidence=1.0,
                source="security_headers",
                explanation="Strict-Transport-Security is enabled with a long max-age.",
            ),
            EvidenceItem(
                id="HDR_CSP", category="security_headers", signal="csp",
                value="default-src 'self'", effect=1.0, confidence=1.0,
                source="security_headers",
                explanation="Content-Security-Policy is present.",
            ),
        ],
    ):
        resp = _analyze()

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 52  # 50 + 2 (headers)
    assert data["category_contributions"]["security_headers"] == 2.0
    signals = {e["signal"] for e in data["evidence"]}
    assert {"hsts", "csp"} <= signals
