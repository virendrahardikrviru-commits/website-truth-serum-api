"""Phase 2c-8 — SSRF and resource-boundary hardening tests.

Verifies the page-fetch SSRF gate, redirect-target guard, response-size cap,
and collector-level guards. No live network is used.
"""

import asyncio
import os
from unittest import mock

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers.analyze import MAX_PAGE_BYTES, _cap_page_html, _guard_public_redirects

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


def _post(url):
    return client.post("/api/analyze/", json={"url": url})


# ---------- Page-fetch SSRF gate ----------

def test_page_fetch_skipped_for_loopback():
    with mock.patch(
        "app.routers.analyze.httpx.AsyncClient", new_callable=mock.AsyncMock
    ) as http_mock:
        resp = _post("http://localhost:8080/")

    assert resp.status_code == 200  # analysis still succeeds
    http_mock.assert_not_called()  # no network request was attempted


def test_page_fetch_skipped_for_ip_literal():
    with mock.patch(
        "app.routers.analyze.httpx.AsyncClient", new_callable=mock.AsyncMock
    ) as http_mock:
        resp = _post("http://169.254.169.254/latest/meta-data/")

    assert resp.status_code == 200
    http_mock.assert_not_called()


def test_page_fetch_skipped_for_private_range():
    with mock.patch(
        "app.routers.analyze.httpx.AsyncClient", new_callable=mock.AsyncMock
    ) as http_mock:
        resp = _post("http://10.0.0.5/admin")

    assert resp.status_code == 200
    http_mock.assert_not_called()


def test_page_fetch_runs_for_public_host():
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, text="<html><title>x</title></html>")
    )
    with mock.patch(
        "app.routers.analyze.httpx.AsyncClient",
        side_effect=lambda *a, **k: httpx.AsyncClient(transport=transport, **k),
    ):
        resp = _post("https://example.com/")

    assert resp.status_code == 200


# ---------- Redirect-target guard ----------

def test_redirect_guard_blocks_non_public_targets():
    for url in (
        "http://169.254.169.254/",
        "http://127.0.0.1:8080/",
        "http://10.1.2.3/",
        "http://192.168.1.1/",
        "http://[::1]/",
        "http://localhost/",
    ):
        with pytest.raises(ValueError):
            asyncio.run(_guard_public_redirects(httpx.Request("GET", url)))

    for url in ("https://example.com/", "https://github.com/some/path"):
        asyncio.run(_guard_public_redirects(httpx.Request("GET", url)))  # must not raise


def test_redirect_to_non_public_host_blocked_at_endpoint():
    captured = {}

    def spy(html):
        captured["html"] = html
        return []

    def handler(req):
        if req.url.host == "example.com":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"})
        return httpx.Response(200, text="<html>internal</html>")

    transport = httpx.MockTransport(handler)
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze.httpx.AsyncClient",
        side_effect=lambda *a, **k: httpx.AsyncClient(transport=transport, **k),
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
    ), mock.patch("app.routers.analyze.analyze_page_content", side_effect=spy):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    assert captured["html"] is None  # internal redirect target was blocked
    assert resp.json()["trust_score"] == 50  # no content evidence


# ---------- Response-size bound ----------

def test_page_body_size_capped():
    payload = f"<html><body>{'a' * (MAX_PAGE_BYTES + 5000)}</body></html>"
    captured = {}

    def spy(html):
        captured["html"] = html
        return []

    transport = httpx.MockTransport(lambda req: httpx.Response(200, text=payload))
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze.httpx.AsyncClient",
        side_effect=lambda *a, **k: httpx.AsyncClient(transport=transport, **k),
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
    ), mock.patch("app.routers.analyze.analyze_page_content", side_effect=spy):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    # Content-Length exceeds the bound -> oversized download aborted before
    # buffering, so the content collector receives no page body.
    assert captured["html"] is None


def test_cap_page_html_truncates():
    raw = "x" * (MAX_PAGE_BYTES + 1000)
    capped = _cap_page_html(raw)
    assert len(capped) == MAX_PAGE_BYTES
    assert _cap_page_html(None) is None
    assert _cap_page_html("short") == "short"


# ---------- Collector-level guards (self-created clients) ----------

def test_collect_http_rejects_non_public_target():
    from app.services.collectors.http_behavior import collect_http

    assert asyncio.run(collect_http("http://169.254.169.254/")) == []
    assert asyncio.run(collect_http("http://localhost:8080/")) == []
    assert asyncio.run(collect_http("http://192.168.1.10/")) == []


def test_collect_security_headers_rejects_non_public_target():
    from app.services.collectors.security_headers import collect_security_headers

    assert asyncio.run(collect_security_headers("http://127.0.0.1/")) == []
    assert asyncio.run(collect_security_headers("http://10.0.0.1/")) == []
