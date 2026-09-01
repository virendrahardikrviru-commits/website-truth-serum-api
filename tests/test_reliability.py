"""Phase 2c-10 — Reliability & observability tests.

Deterministic tests (no live network) for: overall evidence deadline, partial
evidence retention, concurrent scans, collector/thread timeout behavior,
structured logging, single-fetch consolidation, SSRF/size preservation,
reputation cache bounds/concurrency, failure classification and legacy
regression.
"""

import asyncio
import concurrent.futures
import contextlib
import json
import logging
import os
import time
from unittest import mock

import httpx
import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport

from app.main import app
from app.models.evidence import EvidenceItem
from app.routers import analyze as analyze_module
from app.services.collectors import reputation as rep
from app.services.collectors.reputation import ProviderReport

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


@pytest.fixture(autouse=True)
def _env_reset():
    rep._CACHE.clear()
    saved = {
        key: os.environ.pop(key, None)
        for key in ("SCORING_MODE", "REPUTATION_ENABLED", "URLHAUS_API_KEY", "SPAMHAUS_DQS_KEY")
    }
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    rep._CACHE.clear()


def _post(url):
    return client.post("/api/analyze/", json={"url": url})


def _evidence_mocks(deadline=5.0, transport=None, tls=None, rdap=None, content=None):
    """Enter evidence-mode orchestration mocks with neutral defaults."""
    if transport is None:
        transport = httpx.MockTransport(
            lambda r: httpx.Response(200, text="<html><title>R</title></html>")
        )
    real_client_cls = httpx.AsyncClient  # captured before patching
    tls_mock = tls if tls is not None else mock.AsyncMock(return_value=[])
    exit_stack = contextlib.ExitStack()
    exit_stack.enter_context(mock.patch.object(analyze_module, "SCAN_DEADLINE_SECONDS", deadline))
    exit_stack.enter_context(mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}))
    exit_stack.enter_context(
        mock.patch(
            "app.routers.analyze.httpx.AsyncClient",
            side_effect=lambda *a, **k: real_client_cls(transport=transport, **k),
        )
    )
    exit_stack.enter_context(
        mock.patch(
            "app.routers.analyze.rdap_lookup",
            new_callable=mock.AsyncMock,
            return_value=rdap or NEUTRAL_RDAP,
        )
    )
    exit_stack.enter_context(mock.patch("app.routers.analyze.collect_tls", new=tls_mock))
    exit_stack.enter_context(mock.patch("app.routers.analyze.analyze_http_response", return_value=[]))
    exit_stack.enter_context(mock.patch("app.routers.analyze.analyze_headers_response", return_value=[]))
    exit_stack.enter_context(
        mock.patch(
            "app.routers.analyze.analyze_page_content",
            return_value=content if content is not None else [],
        )
    )
    return exit_stack


# ---------- Overall deadline ----------

def test_evidence_deadline_bounds_scan_and_drops_slow_collector():
    async def slow_tls(domain):
        await asyncio.sleep(30)
        return []

    with _evidence_mocks(deadline=0.5, tls=slow_tls):
        start = time.monotonic()
        resp = _post("https://example.com/")
        elapsed = time.monotonic() - start

    assert resp.status_code == 200
    assert elapsed < 5  # bounded well under the 30s slow collector
    data = resp.json()
    assert data["trust_score"] == 50
    assert "ssl" not in data["category_contributions"]  # slow collector -> unavailable


def test_partial_evidence_retained_after_deadline():
    async def slow_tls(domain):
        await asyncio.sleep(30)
        return []

    content_item = EvidenceItem(
        id="CONTENT_TITLE", category="content", signal="title_present",
        value="R", effect=1.0, confidence=1.0, source="content",
        explanation="The page has a title.",
    )
    with _evidence_mocks(deadline=0.5, tls=slow_tls, content=[content_item]):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["category_contributions"].get("content") == 1.0  # completed evidence kept
    assert "ssl" not in data["category_contributions"]  # unfinished collector dropped


def test_concurrent_scans_are_independent():
    transport = httpx.MockTransport(
        lambda r: httpx.Response(200, text="<html><title>R</title></html>")
    )
    real_client_cls = httpx.AsyncClient  # captured before patching

    async def run_scan(i):
        async with real_client_cls(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            return await c.post("/api/analyze/", json={"url": "https://example.com/"})

    async def run_all():
        return await asyncio.gather(*[run_scan(i) for i in range(8)])

    with _evidence_mocks(deadline=5.0, transport=transport):
        responses = asyncio.run(run_all())

    for resp in responses:
        assert resp.status_code == 200
        assert resp.json()["trust_score"] == 50


# ---------- Collector / thread timeouts ----------

def test_reputation_dns_timeout_is_neutral(monkeypatch):
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["SPAMHAUS_DQS_KEY"] = "test-key"
    monkeypatch.setattr(rep, "REPUTATION_TIMEOUT", 0.2)

    def slow_resolve(host):
        time.sleep(1.0)
        return []

    with mock.patch.object(rep, "_dbl_resolve", side_effect=slow_resolve):
        start = time.monotonic()
        items = asyncio.run(rep.collect_reputation("example.com"))
        elapsed = time.monotonic() - start

    assert items == []  # timeout -> neutral
    assert elapsed < 0.9  # bounded by REPUTATION_TIMEOUT, not the thread sleep


def test_slow_tls_thread_does_not_block_scan():
    transport = httpx.MockTransport(
        lambda r: httpx.Response(200, text="<html><title>R</title></html>")
    )

    def slow_sync(domain):
        time.sleep(1.5)
        return []

    with _evidence_mocks(deadline=0.5, transport=transport), mock.patch(
        "app.services.collectors.ssl._collect_tls_sync", side_effect=slow_sync
    ):
        start = time.monotonic()
        resp = _post("https://example.com/")
        elapsed = time.monotonic() - start

    assert resp.status_code == 200
    assert elapsed < 1.2  # bounded by the deadline despite the hanging TLS thread
    assert "ssl" not in resp.json()["category_contributions"]


# ---------- Single fetch consolidation ----------

def test_single_page_fetch_in_evidence_mode():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(
            200, text="<html><title>R</title></html>",
            headers={
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
            },
        )

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient  # captured before patching
    # http/headers/content are NOT mocked -> they derive from the reused response.
    with mock.patch.object(analyze_module, "SCAN_DEADLINE_SECONDS", 5.0), mock.patch.dict(
        os.environ, {"SCORING_MODE": "evidence"}
    ), mock.patch(
        "app.routers.analyze.httpx.AsyncClient",
        side_effect=lambda *a, **k: real_client_cls(transport=transport, **k),
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock, return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock, return_value=[],
    ):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    assert calls["n"] == 1  # exactly one page GET; http/headers derived, not re-fetched
    data = resp.json()
    assert data["category_contributions"]["http"] == 2.0  # https_ok
    assert data["category_contributions"]["security_headers"] == 2.0  # HSTS + nosniff


def test_http_upgrade_from_reused_response():
    def handler(req):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com/"})
        return httpx.Response(200, text="<html>ok</html>")

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient  # captured before patching
    with mock.patch.object(analyze_module, "SCAN_DEADLINE_SECONDS", 5.0), mock.patch.dict(
        os.environ, {"SCORING_MODE": "evidence"}
    ), mock.patch(
        "app.routers.analyze.httpx.AsyncClient",
        side_effect=lambda *a, **k: real_client_cls(transport=transport, **k),
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock, return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock, return_value=[],
    ):
        resp = _post("http://example.com/")

    assert resp.status_code == 200
    assert resp.json()["category_contributions"]["http"] == 4.0  # https_ok + upgrade


def test_ssrf_redirect_still_blocked_after_consolidation():
    def handler(req):
        if req.url.host == "example.com":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"})
        return httpx.Response(200, text="internal")

    transport = httpx.MockTransport(handler)
    with mock.patch.object(analyze_module, "SCAN_DEADLINE_SECONDS", 5.0), mock.patch.dict(
        os.environ, {"SCORING_MODE": "evidence"}
    ), mock.patch(
        "app.routers.analyze.httpx.AsyncClient",
        side_effect=lambda *a, **k: httpx.AsyncClient(transport=transport, **k),
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock, return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock, return_value=[],
    ):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    data = resp.json()
    assert "http" not in data["category_contributions"]  # blocked -> no response
    assert "security_headers" not in data["category_contributions"]
    assert data["trust_score"] == 50


# ---------- Structured observability ----------

def _log_records(caplog):
    return [
        json.loads(r.getMessage())
        for r in caplog.records
        if r.name == "wts.evidence"
    ]


def test_structured_logging_fields(caplog):
    with caplog.at_level(logging.INFO, logger="wts.evidence"), _evidence_mocks():
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    records = _log_records(caplog)
    collectors = [r for r in records if r["event"] == "collector"]
    results = [r for r in records if r["event"] == "scan_result"]
    assert collectors
    for ev in collectors:
        assert {"scan_id", "domain", "mode", "collector", "duration_ms",
                "outcome", "evidence_count"} <= set(ev)
        assert ev["domain"] == "example.com"
        assert ev["mode"] == "evidence"
        assert ev["outcome"] in ("success", "unavailable", "timeout", "rate_limited",
                                 "unauthorized", "invalid", "error")
    assert results
    assert {"score", "category", "confidence", "duration_ms"} <= set(results[0])


def test_no_sensitive_data_in_logs(caplog):
    with caplog.at_level(logging.INFO, logger="wts.evidence"), _evidence_mocks():
        resp = _post("https://example.com/?q=supersecretpass123")

    assert resp.status_code == 200
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "supersecretpass123" not in log_text


def test_failure_outcome_classification(caplog):
    with caplog.at_level(logging.INFO, logger="wts.evidence"), _evidence_mocks():
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    outcomes = {
        r["collector"]: r["outcome"]
        for r in _log_records(caplog)
        if r["event"] == "collector"
    }
    assert outcomes.get("tls") == "unavailable"
    assert outcomes.get("http") == "unavailable"
    assert outcomes.get("security_headers") == "unavailable"
    assert outcomes.get("content") == "unavailable"


def test_reputation_rate_limited_logged_as_warning(caplog):
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"

    async def fake_reputation(domain, client=None, outcomes=None):
        if outcomes is not None:
            outcomes["urlhaus"] = "rate_limited"
        return []

    with caplog.at_level(logging.WARNING, logger="wts.evidence"), _evidence_mocks(
        deadline=5.0
    ), mock.patch("app.routers.analyze.collect_reputation", new=fake_reputation):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    warnings = [
        r for r in _log_records(caplog)
        if r["event"] == "collector" and r["collector"] == "reputation:urlhaus"
    ]
    assert warnings and warnings[0]["outcome"] == "rate_limited"


def test_legacy_scan_emits_no_structured_logs(caplog):
    transport = httpx.MockTransport(
        lambda r: httpx.Response(200, text="<html></html>")
    )
    with caplog.at_level(logging.INFO, logger="wts.evidence"), mock.patch(
        "app.routers.analyze.httpx.AsyncClient",
        side_effect=lambda *a, **k: httpx.AsyncClient(transport=transport, **k),
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock, return_value=NEUTRAL_RDAP,
    ):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    assert resp.json()["trust_score"] == 65  # legacy baseline unchanged
    assert _log_records(caplog) == []  # no evidence-mode structured logs in legacy


# ---------- Reputation cache ----------

def test_reputation_cache_hard_bound():
    for i in range(rep.CACHE_MAX_ENTRIES + 10):
        rep._CACHE[f"k{i}"] = (time.time() - 0.1, ProviderReport(
            provider="p", threats=(), listed=False, raw={}))
    rep._cache_set("trigger", ProviderReport(provider="p", threats=(), listed=False, raw={}))
    assert len(rep._CACHE) <= rep.CACHE_MAX_ENTRIES
    assert "trigger" in rep._CACHE  # newest entry retained


def test_reputation_cache_concurrent_access():
    async def worker(i):
        for j in range(50):
            key = f"k{(i + j) % 20}"
            rep._cache_set(key, ProviderReport(provider="p", threats=(), listed=False, raw={}))
            rep._cache_get(key)

    async def run_all():
        await asyncio.gather(*[worker(i) for i in range(8)])

    asyncio.run(run_all())
    assert len(rep._CACHE) <= rep.CACHE_MAX_ENTRIES
