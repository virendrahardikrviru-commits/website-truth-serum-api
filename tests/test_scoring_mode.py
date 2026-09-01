"""V1-H3 — SCORING_MODE configuration policy.

Evidence is the production default; legacy is explicit rollback; invalid
values fail closed (never silently fall back to legacy).
"""

import httpx
import pytest
from fastapi.testclient import TestClient
from unittest import mock

from app.main import app
from app.routers.analyze import get_scoring_mode
from app.services.rate_limit import SlidingWindowRateLimiter

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
    "notes": [],
}


def test_scoring_mode_defaults_to_evidence(monkeypatch):
    monkeypatch.delenv("SCORING_MODE", raising=False)
    assert get_scoring_mode() == "evidence"


def test_scoring_mode_evidence_explicit(monkeypatch):
    monkeypatch.setenv("SCORING_MODE", "evidence")
    assert get_scoring_mode() == "evidence"


def test_scoring_mode_legacy_explicit(monkeypatch):
    monkeypatch.setenv("SCORING_MODE", "legacy")
    assert get_scoring_mode() == "legacy"


def test_scoring_mode_case_insensitive(monkeypatch):
    monkeypatch.setenv("SCORING_MODE", "EVIDENCE")
    assert get_scoring_mode() == "evidence"


def test_scoring_mode_invalid_fails_closed(monkeypatch):
    monkeypatch.setenv("SCORING_MODE", "banana")
    with pytest.raises(RuntimeError):
        get_scoring_mode()


def _network_mocks(transport):
    import contextlib

    stack = contextlib.ExitStack()
    stack.enter_context(mock.patch("app.routers.analyze._page_fetch_transport", transport))
    stack.enter_context(
        mock.patch(
            "app.routers.analyze.rdap_lookup",
            new_callable=mock.AsyncMock,
            return_value=NEUTRAL_RDAP,
        )
    )
    stack.enter_context(
        mock.patch("app.routers.analyze.collect_tls", new_callable=mock.AsyncMock, return_value=[])
    )
    stack.enter_context(mock.patch("app.routers.analyze.analyze_http_response", return_value=[]))
    stack.enter_context(mock.patch("app.routers.analyze.analyze_headers_response", return_value=[]))
    stack.enter_context(mock.patch("app.routers.analyze.analyze_page_content", return_value=[]))
    stack.enter_context(
        mock.patch(
            "app.routers.analyze.scan_rate_limiter",
            SlidingWindowRateLimiter(max_requests=10**6, window_seconds=3600),
        )
    )
    return stack


def test_evidence_is_default_at_endpoint(monkeypatch):
    monkeypatch.delenv("SCORING_MODE", raising=False)
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="<html></html>"))
    with _network_mocks(transport):
        resp = client.post("/api/analyze/", json={"url": "https://example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["confidence"] == 0.0
    assert data["evidence"] == []
    assert data["transparency"] is not None  # evidence-mode-only field present


def test_legacy_is_explicit_rollback(monkeypatch):
    monkeypatch.setenv("SCORING_MODE", "legacy")
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="<html></html>"))
    with _network_mocks(transport):
        resp = client.post("/api/analyze/", json={"url": "https://example.com/"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 65  # legacy pattern baseline unchanged
    assert data["confidence"] is None
    assert data["evidence"] is None
    assert data["transparency"] is None


def test_invalid_mode_fails_closed_at_endpoint(monkeypatch):
    monkeypatch.setenv("SCORING_MODE", "banana")
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="<html></html>"))
    # raise_server_exceptions=False so the 500 (not the exception) is returned.
    non_raising = TestClient(app, raise_server_exceptions=False)
    with _network_mocks(transport):
        resp = non_raising.post("/api/analyze/", json={"url": "https://example.com/"})

    assert resp.status_code == 500  # fail closed; never silently legacy


def test_reputation_still_disabled_by_default(monkeypatch):
    monkeypatch.setenv("SCORING_MODE", "evidence")
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="<html></html>"))
    with _network_mocks(transport), mock.patch(
        "app.routers.analyze.collect_reputation", new_callable=mock.AsyncMock
    ) as rep_mock:
        client.post("/api/analyze/", json={"url": "https://example.com/"})

    rep_mock.assert_not_called()  # REPUTATION_ENABLED unset -> never invoked
