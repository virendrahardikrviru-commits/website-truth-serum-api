import asyncio
import socket
import ssl
from unittest import mock

import httpx

from app.models.evidence import EvidenceItem
from app.services.collectors.http_behavior import collect_http
from app.services.collectors.ssl import collect_tls
from app.services.evidence import rdap_evidence_items
from app.services.scoring import evaluate_evidence


# ---------- TLS collector ----------

class FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeTLS(FakeConn):
    def version(self):
        return "TLSv1.3"

    def getpeercert(self):
        return {
            "subject": ((("organizationName", "Example Org"),),),
            "notAfter": "Sep  1 12:00:00 2026 GMT",
        }


def _patch_tls(monkeypatch, wrap_error=None, connect_error=None):
    def fake_connect(addr, timeout):
        if connect_error:
            raise connect_error
        return FakeConn()

    ctx = mock.Mock()
    if wrap_error:
        ctx.wrap_socket.side_effect = wrap_error
    else:
        ctx.wrap_socket.return_value = FakeTLS()
    monkeypatch.setattr(
        "app.services.collectors.ssl.socket.create_connection", fake_connect
    )
    monkeypatch.setattr(
        "app.services.collectors.ssl.ssl.create_default_context", lambda: ctx
    )
    return ctx


def test_tls_valid(monkeypatch):
    _patch_tls(monkeypatch)
    items = asyncio.run(collect_tls("example.com"))
    assert len(items) == 1
    item = items[0]
    assert item.category == "ssl"
    assert item.signal == "ssl_valid"
    assert item.effect == 8.0
    assert item.source == "tls"
    assert item.value["tls_version"] == "TLSv1.3"


def test_tls_cert_verification_failure(monkeypatch):
    _patch_tls(
        monkeypatch,
        wrap_error=ssl.SSLCertVerificationError("certificate verify failed"),
    )
    items = asyncio.run(collect_tls("example.com"))
    assert len(items) == 1
    assert items[0].signal == "ssl_error"
    assert items[0].effect == -10.0


def test_tls_handshake_failure(monkeypatch):
    _patch_tls(monkeypatch, wrap_error=ssl.SSLError("handshake failure"))
    items = asyncio.run(collect_tls("example.com"))
    assert len(items) == 1
    assert items[0].effect == -10.0


def test_tls_timeout_unavailable_no_penalty(monkeypatch):
    _patch_tls(monkeypatch, wrap_error=socket.timeout("timed out"))
    items = asyncio.run(collect_tls("example.com"))
    assert items == []


def test_tls_network_failure_unavailable_no_penalty(monkeypatch):
    _patch_tls(monkeypatch, connect_error=ConnectionRefusedError("refused"))
    items = asyncio.run(collect_tls("example.com"))
    assert items == []


# ---------- HTTP behavior collector ----------

def _run_http(url, handler, max_redirects=5):
    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, follow_redirects=True, max_redirects=max_redirects,
            timeout=5.0,
        ) as client:
            return await collect_http(url, client=client)

    return asyncio.run(_run())


def test_http_https_success():
    items = _run_http(
        "https://example.com/", lambda req: httpx.Response(200, text="ok")
    )
    assert len(items) == 1
    assert items[0].signal == "https_ok"
    assert items[0].effect == 2.0
    assert items[0].category == "http"
    assert items[0].value["status_code"] == 200


def test_http_http_to_https_redirect():
    def handler(req):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com/"})
        return httpx.Response(200, text="ok")

    items = _run_http("http://example.com/", handler)
    signals = sorted(i.signal for i in items)
    assert signals == ["http_to_https", "https_ok"]
    assert sum(i.effect for i in items) == 4.0


def test_http_redirect_loop_negative():
    def handler(req):
        return httpx.Response(302, headers={"location": str(req.url)})

    items = _run_http("https://example.com/", handler)
    assert len(items) == 1
    assert items[0].signal == "redirect_loop"
    assert items[0].effect == -3.0


def test_http_timeout_unavailable_no_penalty():
    def handler(req):
        raise httpx.ReadTimeout("timed out", request=req)

    items = _run_http("https://example.com/", handler)
    assert items == []


def test_http_network_failure_unavailable_no_penalty():
    def handler(req):
        raise httpx.ConnectError("refused", request=req)

    items = _run_http("https://example.com/", handler)
    assert items == []


def test_http_plain_http_not_penalized():
    items = _run_http(
        "http://example.com/", lambda req: httpx.Response(200, text="ok")
    )
    assert items == []


# ---------- Evidence assembly: RDAP + TLS + HTTP -> engine ----------

def test_evidence_assembly_rdap_tls_http():
    rdap = rdap_evidence_items({"source": "rdap", "domain_age_days": 4000, "status": []})
    tls = [
        EvidenceItem(id="TLS_001", category="ssl", signal="ssl_valid", value="TLSv1.3",
                     effect=8.0, confidence=1.0, source="tls"),
    ]
    http = [
        EvidenceItem(id="HTTP_HTTPS", category="http", signal="https_ok",
                     effect=2.0, confidence=1.0, source="http"),
    ]
    result = evaluate_evidence(rdap + tls + http)
    assert result.score == 65.0  # 50 + 5 (domain) + 8 (ssl) + 2 (http)
    assert result.category_contributions == {"domain": 5.0, "ssl": 8.0, "http": 2.0}
    assert len(result.applied_evidence) == 3
    assert result.confidence > 0.5


def test_evidence_assembly_collector_failures_are_neutral():
    # TLS and HTTP unavailable -> only RDAP evidence applies, no penalty.
    rdap = rdap_evidence_items({"source": "rdap", "domain_age_days": 500, "status": []})
    result = evaluate_evidence(rdap)
    assert result.score == 50.0
    assert result.category_contributions == {"domain": 0.0}
