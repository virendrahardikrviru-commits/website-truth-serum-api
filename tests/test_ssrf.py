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
from app.services.rate_limit import SlidingWindowRateLimiter

client = TestClient(app)


@pytest.fixture(autouse=True)
def _permissive_rate_limit():
    with mock.patch(
        "app.routers.analyze.scan_rate_limiter",
        SlidingWindowRateLimiter(max_requests=10**6, window_seconds=3600),
    ):
        yield


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
        "app.routers.analyze._new_fetch_client", new_callable=mock.AsyncMock
    ) as http_mock:
        resp = _post("http://localhost:8080/")

    assert resp.status_code == 200  # analysis still succeeds
    http_mock.assert_not_called()  # no network request was attempted


def test_page_fetch_skipped_for_ip_literal():
    with mock.patch(
        "app.routers.analyze._new_fetch_client", new_callable=mock.AsyncMock
    ) as http_mock:
        resp = _post("http://169.254.169.254/latest/meta-data/")

    assert resp.status_code == 200
    http_mock.assert_not_called()


def test_page_fetch_skipped_for_private_range():
    with mock.patch(
        "app.routers.analyze._new_fetch_client", new_callable=mock.AsyncMock
    ) as http_mock:
        resp = _post("http://10.0.0.5/admin")

    assert resp.status_code == 200
    http_mock.assert_not_called()


def test_page_fetch_runs_for_public_host():
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, text="<html><title>x</title></html>")
    )
    with mock.patch("app.routers.analyze._page_fetch_transport", transport):
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

    def spy(html, scheme=None):
        captured["html"] = html
        return []

    def handler(req):
        if req.url.host == "example.com":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"})
        return httpx.Response(200, text="<html>internal</html>")

    transport = httpx.MockTransport(handler)
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
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

    def spy(html, scheme=None):
        captured["html"] = html
        return []

    transport = httpx.MockTransport(lambda req: httpx.Response(200, text=payload))
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
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


# ---------- V1-H1: bounded streaming body read ----------

from app.routers.analyze import _read_bounded_body


class ChunkStream(httpx.AsyncByteStream):
    """Async body that yields data in a controllable number of chunks."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk


def _stream_response(chunks, headers=None):
    return httpx.Response(
        200,
        headers=headers or {},
        stream=ChunkStream(chunks),
        request=httpx.Request("GET", "https://example.com/"),
    )


def test_read_bounded_body_stream_truncates_at_limit():
    chunk = b"a" * (MAX_PAGE_BYTES // 2)
    resp = _stream_response([chunk, chunk, chunk])  # 1.5x the limit
    html = asyncio.run(_read_bounded_body(resp))
    assert html is not None
    assert len(html) == MAX_PAGE_BYTES  # truncated at the byte bound


def test_read_bounded_body_exact_limit():
    chunk = b"b" * MAX_PAGE_BYTES
    resp = _stream_response([chunk])
    html = asyncio.run(_read_bounded_body(resp))
    assert len(html) == MAX_PAGE_BYTES


def test_read_bounded_body_below_limit():
    resp = _stream_response([b"<html><title>small</title></html>"])
    html = asyncio.run(_read_bounded_body(resp))
    assert html == "<html><title>small</title></html>"


def test_read_bounded_body_content_length_aborts():
    resp = _stream_response(
        [b"x" * 100],
        headers={"content-length": str(MAX_PAGE_BYTES + 1)},
    )
    assert asyncio.run(_read_bounded_body(resp)) is None


def test_read_bounded_body_none_response_content():
    # A body that yields no bytes produces empty (not None) text; oversized
    # bodies with an honest Content-Length produce None.
    resp = _stream_response([])
    assert asyncio.run(_read_bounded_body(resp)) == ""


def test_oversized_streamed_body_stays_bounded_end_to_end():
    # Endpoint-level: a streamed body without a Content-Length header must not
    # be fully buffered; the content collector receives the bounded text only.
    captured = {}

    def spy(html, scheme=None):
        captured["html"] = html
        return []

    handler = lambda req: httpx.Response(
        200,
        stream=ChunkStream([b"x" * (MAX_PAGE_BYTES // 2)] * 3),
    )
    transport = httpx.MockTransport(handler)
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
    ), mock.patch(
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
    ), mock.patch("app.routers.analyze.analyze_page_content", side_effect=spy):
        resp = _post("https://example.com/")

    assert resp.status_code == 200
    assert captured["html"] is not None
    assert len(captured["html"]) == MAX_PAGE_BYTES  # bounded, not 1.5x


# ================================================================
# V1-H3 — DNS-resolution SSRF (hostname resolving to internal IP)
# ================================================================

from app.services.network_security import (  # noqa: E402
    NonPublicDestinationError,
    PinnedAsyncHTTPTransport,
)


def _patched_resolve(host, port, rejected=()):
    # Simulates the pinned backend: rejected hosts fail closed, everything else
    # resolves to a validated public IP (no live DNS in tests).
    if host in rejected:
        raise NonPublicDestinationError(host, reason="private_ip_rejected")
    return "8.8.8.8"


def test_dns_ssrf_initial_host_resolving_private_blocked(caplog):
    # A public-looking hostname resolving to an internal address must be
    # rejected at connect time (before any connection is made) and scored as
    # unavailable/neutral.
    import logging

    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze._page_fetch_transport", PinnedAsyncHTTPTransport()
    ), mock.patch(
        "app.services.network_security.resolve_and_pin",
        side_effect=NonPublicDestinationError("evil.example", reason="private_ip_rejected"),
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[],
    ), mock.patch("app.routers.analyze.analyze_http_response", return_value=[]), mock.patch(
        "app.routers.analyze.analyze_headers_response", return_value=[]
    ), mock.patch("app.routers.analyze.analyze_page_content", return_value=[]), caplog.at_level(
        logging.WARNING, logger="wts.evidence"
    ):
        resp = _post("https://evil.example/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 50  # no evidence, neutral — never a penalty
    assert data["confidence"] == 0.0
    assert data["evidence"] == []
    assert any(r["event"] == "collector" and r["outcome"] == "private_ip_rejected"
               for r in _json_logs(caplog))


def _json_logs(caplog):
    import json as _json

    return [
        _json.loads(r.getMessage())
        for r in caplog.records
        if r.name == "wts.evidence"
    ]


class ResolvingRedirectTransport(httpx.AsyncBaseTransport):
    """Test transport that mirrors the pinned backend's contract: every hop
    (initial request AND redirect target) is resolved + validated before the
    MockTransport serves the response."""

    def __init__(self, handler, rejected=()):
        self._inner = httpx.MockTransport(handler)
        self._rejected = rejected

    async def handle_async_request(self, request):
        _patched_resolve(request.url.host, request.url.port or 443, rejected=self._rejected)
        return await self._inner.handle_async_request(request)


def test_redirect_to_hostname_resolving_private_blocked():
    # public.example 302 -> private.example (would resolve to 169.254.169.254).
    def handler(req):
        if req.url.host == "public.example":
            return httpx.Response(302, headers={"location": "https://private.example/"})
        return httpx.Response(200, text="internal")

    transport = ResolvingRedirectTransport(handler, rejected=("private.example",))
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[],
    ), mock.patch("app.routers.analyze.analyze_http_response", return_value=[]), mock.patch(
        "app.routers.analyze.analyze_headers_response", return_value=[]
    ), mock.patch("app.routers.analyze.analyze_page_content", return_value=[]):
        resp = _post("https://public.example/")

    assert resp.status_code == 200
    data = resp.json()
    assert data["trust_score"] == 50  # redirect hop rejected -> no evidence
    assert data["evidence"] == []


def test_redirect_to_hostname_resolving_private_ipv6_blocked():
    # Redirect to a hostname resolving to an internal IPv6 (link-local/ULA).
    def handler(req):
        if req.url.host == "public.example":
            return httpx.Response(302, headers={"location": "https://six.example/"})
        return httpx.Response(200, text="internal")

    transport = ResolvingRedirectTransport(handler, rejected=("six.example",))
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[],
    ), mock.patch("app.routers.analyze.analyze_http_response", return_value=[]), mock.patch(
        "app.routers.analyze.analyze_headers_response", return_value=[]
    ), mock.patch("app.routers.analyze.analyze_page_content", return_value=[]):
        resp = _post("https://public.example/")

    assert resp.status_code == 200
    assert resp.json()["trust_score"] == 50


def test_redirect_to_hostname_resolving_10_0_0_1_blocked():
    # public.example 302 -> evil.example (would resolve to 10.0.0.1).
    def handler(req):
        if req.url.host == "public.example":
            return httpx.Response(302, headers={"location": "https://evil.example/"})
        return httpx.Response(200, text="internal")

    transport = ResolvingRedirectTransport(handler, rejected=("evil.example",))
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[],
    ), mock.patch("app.routers.analyze.analyze_http_response", return_value=[]), mock.patch(
        "app.routers.analyze.analyze_headers_response", return_value=[]
    ), mock.patch("app.routers.analyze.analyze_page_content", return_value=[]):
        resp = _post("https://public.example/")

    assert resp.status_code == 200
    assert resp.json()["trust_score"] == 50


def test_redirect_to_public_hostname_still_works():
    # A redirect to another public hostname must resolve+validate and proceed.
    def handler(req):
        if req.url.host == "public.example":
            return httpx.Response(302, headers={"location": "https://other.example/"})
        return httpx.Response(200, text="<html><title>ok</title></html>")

    transport = ResolvingRedirectTransport(handler, rejected=("evil.example", "private.example"))
    with mock.patch.dict(os.environ, {"SCORING_MODE": "evidence"}), mock.patch(
        "app.routers.analyze._page_fetch_transport", transport
    ), mock.patch(
        "app.routers.analyze.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=NEUTRAL_RDAP,
    ), mock.patch(
        "app.routers.analyze.collect_tls",
        new_callable=mock.AsyncMock,
        return_value=[],
    ), mock.patch(
        "app.routers.analyze.analyze_headers_response", return_value=[]
    ), mock.patch("app.routers.analyze.analyze_page_content", return_value=[]):
        resp = _post("https://public.example/")

    assert resp.status_code == 200
    # Redirect followed to other.example -> HTTPS evidence present.
    assert resp.json()["category_contributions"].get("http") == 2.0
