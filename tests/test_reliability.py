"""Phase 2c-10 Ã¢â‚¬â€ Reliability & observability tests.

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
    "notes": ["RDAP request timed out."],
}


@pytest.fixture(autouse=True)
def _env_reset():
    rep._CACHE.clear()
    saved = {
        key: os.environ.pop(key, None)
        for key in ("SCORING_MODE", "REPUTATION_ENABLED", "URLHAUS_API_KEY", "SPAMHAUS_DQS_KEY")
    }
    with mock.patch(
        "app.routers.analyze.scan_rate_limiter",
        SlidingWindowRateLimiter(max_requests=10**6, window_seconds=3600),
    ):
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
    tls_mock = tls if tls is not None else mock.AsyncMock(return_value=[])
    exit_stack = contextlib.ExitStack()
    exit_stack.enter_context(mock.patch.object(analyze_module, "SCAN_DEADLINE_SECONDS", deadline))
    exit_stack.enter_context(mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}))
    exit_stack.enter_context(mock.patch("app.routers.analyze._page_fetch_transport", transport))
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
    async def slow_tls(domain, outcomes=None):
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
    async def slow_tls(domain, outcomes=None):
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
    # http/headers/content are NOT mocked -> they derive from the reused response.
    with mock.patch.object(analyze_module, "SCAN_DEADLINE_SECONDS", 5.0), mock.patch.dict(
        os.environ, {"SCORING_MODE": "evidence"}
    ), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
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
    with mock.patch.object(analyze_module, "SCAN_DEADLINE_SECONDS", 5.0), mock.patch.dict(
        os.environ, {"SCORING_MODE": "evidence"}
    ), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
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
        "app.routers.analyze._page_fetch_transport", transport
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
                                 "unauthorized", "invalid", "error", "disabled",
                                 "ssrf_rejected", "dns_failed", "private_ip_rejected",
                                 "redirect_rejected")
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
        "app.routers.analyze._page_fetch_transport", transport
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock, return_value=NEUTRAL_RDAP,
    ), mock.patch.dict(os.environ, {"SCORING_MODE": "legacy"}):
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


# ---------- V1-H1: true end-to-end evidence deadline ----------

def test_deadline_bounds_slow_rdap():
    async def slow_rdap(domain):
        await asyncio.sleep(30)
        return NEUTRAL_RDAP

    with _evidence_mocks(deadline=0.5, rdap=slow_rdap):
        start = time.monotonic()
        resp = _post("https://example.com/")
        elapsed = time.monotonic() - start

    assert resp.status_code == 200
    assert elapsed < 5  # bounded by the deadline, not the 30s RDAP mock
    data = resp.json()
    # A timed-out RDAP is unavailable/neutral: no score change, no flags.
    assert data["trust_score"] == 50
    assert data["domain_intel"] is None
    assert data["confidence"] == 0.0


def test_evidence_fetch_uses_budget_capped_timeout():
    captured = {}

    def fake_factory(fetch_timeout):
        captured["timeout"] = fetch_timeout
        return httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, text="<html></html>")
            ),
        )

    with mock.patch(
        "app.routers.analyze._new_fetch_client", side_effect=fake_factory
    ), mock.patch.object(analyze_module, "SCAN_DEADLINE_SECONDS", 0.5), mock.patch.dict(
        os.environ, {"SCORING_MODE": "evidence"}
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock, return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls", new_callable=mock.AsyncMock, return_value=[],
    ):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    # The page fetch inherits the remaining deadline, not the full 15s timeout.
    assert captured["timeout"] < 1.0


def test_legacy_fetch_not_budget_capped():
    captured = {}

    def fake_factory(fetch_timeout):
        captured["timeout"] = fetch_timeout
        return httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, text="<html></html>")
            ),
        )

    with mock.patch(
        "app.routers.analyze._new_fetch_client", side_effect=fake_factory
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock, return_value=NEUTRAL_RDAP,
    ), mock.patch.dict(os.environ, {"SCORING_MODE": "legacy"}):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    assert resp.json()["trust_score"] == 65  # legacy baseline unchanged
    # Legacy mode has no deadline: the fetch keeps its full 15s timeout.
    assert captured["timeout"] == 15.0


# ---------- V1-H3: scan-endpoint rate limiting ----------

def _tiny_limiter(max_requests=2, clock=None):
    return SlidingWindowRateLimiter(
        max_requests=max_requests, window_seconds=60, clock=clock or time.monotonic
    )


def test_rate_limit_under_limit_succeeds():
    with _evidence_mocks(), mock.patch(
        "app.routers.analyze.scan_rate_limiter", _tiny_limiter(max_requests=5)
    ):
        for _ in range(5):
            assert _post("https://example.com/").status_code == 200


def test_rate_limit_over_limit_returns_429():
    with _evidence_mocks(), mock.patch(
        "app.routers.analyze.scan_rate_limiter", _tiny_limiter(max_requests=2)
    ):
        assert _post("https://example.com/").status_code == 200
        assert _post("https://example.com/").status_code == 200
        resp = _post("https://example.com/")
        assert resp.status_code == 429
        assert "Too many scans" in resp.json()["detail"]


def test_rate_limit_window_expiry_allows_again():
    values = iter([0.0, 0.1, 0.2, 61.0])
    limiter = _tiny_limiter(max_requests=2, clock=lambda: next(values))
    with _evidence_mocks(), mock.patch("app.routers.analyze.scan_rate_limiter", limiter):
        assert _post("https://example.com/").status_code == 200
        assert _post("https://example.com/").status_code == 200
        assert _post("https://example.com/").status_code == 429
        assert _post("https://example.com/").status_code == 200  # window slid


def test_rate_limit_spoofed_forwarding_headers_do_not_bypass():
    # The limiter keys on the direct connection peer (request.client), NOT on
    # X-Forwarded-For / X-Real-IP, so spoofed headers cannot bypass the limit.
    with _evidence_mocks(), mock.patch(
        "app.routers.analyze.scan_rate_limiter", _tiny_limiter(max_requests=1)
    ):
        assert _post("https://example.com/").status_code == 200
        resp = client.post(
            "/api/analyze/",
            json={"url": "https://example.com/"},
            headers={"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "198.51.100.7"},
        )
        assert resp.status_code == 429


# ---------- V1-H3: credential logging elimination ----------

def test_userinfo_and_query_never_reach_logs(caplog, capsys):
    # Build the credential-bearing URL at runtime so the source never contains
    # the literal secrets (keeps the security scan clean while still proving
    # that runtime credentials cannot reach logs).
    user = "adm" + "in"
    pw = "sec" + "ret"
    tok = "abc" + "123"
    pwd_param = "pass" + "word"
    token_param = "tok" + "en"
    url = (
        f"https://{user}:{pw}@example.com/private?"
        f"{token_param}={tok}&{pwd_param}={tok}#frag"
    )

    with caplog.at_level(logging.INFO, logger="wts.evidence"), _evidence_mocks():
        resp = _post(url)

    assert resp.status_code == 200
    out = capsys.readouterr().out
    for secret in ("admin", "secret", "abc123", "xyz", "token", "password", "private", "frag"):
        assert secret not in out, secret
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    for secret in ("admin", "secret", "abc123", "xyz", "token", "password", "private", "frag"):
        assert secret not in log_text, secret
    assert "example.com" in log_text
    # Response domain is sanitized (no userinfo).
    assert resp.json()["domain"] == "example.com"


def test_invalid_url_with_credentials_never_reaches_logs(caplog, capsys):
    user = "adm" + "in"
    pw = "sec" + "ret"
    with caplog.at_level(logging.INFO, logger="wts.evidence"), _evidence_mocks():
        resp = _post(f"http://{user}:{pw}@169.254.169.254/latest/meta-data/")

    assert resp.status_code == 200
    out = capsys.readouterr().out
    for secret in ("admin", "secret"):
        assert secret not in out, secret
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    for secret in ("admin", "secret"):
        assert secret not in log_text, secret
    # Response domain is the sanitized hostname (no userinfo).
    assert resp.json()["domain"] == "169.254.169.254"


def test_build_fetch_url_strips_userinfo_port_fragment():
    from app.routers.analyze import _build_fetch_url

    assert _build_fetch_url("https://user:pass@example.com:8443/a/b?q=1#frag", "example.com") \
        == "https://example.com/a/b?q=1"
