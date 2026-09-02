import asyncio
import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest import mock

import httpx

from app.models.evidence import EvidenceItem
from app.services.collectors.http_behavior import collect_http
from app.services.collectors.ssl import days_until_expiry, collect_tls
from app.services.evidence import rdap_evidence_items
from app.services.scoring import evaluate_evidence


# ---------- TLS collector ----------

class FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _asctime_not_after(dt: datetime) -> str:
    """Format a UTC datetime as OpenSSL's asctime notAfter string."""
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S %Y')} GMT"


# Far-future so tests never depend on the real wall clock.
_DEFAULT_NOT_AFTER = "Jan  1 12:00:00 2099 GMT"


class FakeTLS(FakeConn):
    def __init__(self, not_after: str = _DEFAULT_NOT_AFTER):
        self._not_after = not_after

    def version(self):
        return "TLSv1.3"

    def getpeercert(self):
        return {
            "subject": ((("organizationName", "Example Org"),),),
            "notAfter": self._not_after,
        }


def _patch_tls(monkeypatch, wrap_error=None, connect_error=None, not_after=_DEFAULT_NOT_AFTER):
    def fake_connect(addr, timeout):
        if connect_error:
            raise connect_error
        return FakeConn()

    ctx = mock.Mock()
    if wrap_error:
        ctx.wrap_socket.side_effect = wrap_error
    else:
        ctx.wrap_socket.return_value = FakeTLS(not_after=not_after)
    monkeypatch.setattr(
        "app.services.collectors.ssl.resolve_and_pin", lambda host, port: "1.1.1.1"
    )
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
    assert item.effect == 6.0
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


# ---------- V1.2: SSL expiry ----------

_FIXED_NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_days_until_expiry_parses_asctime_string():
    cert = {"notAfter": _asctime_not_after(_FIXED_NOW + timedelta(days=20))}
    assert days_until_expiry(cert, now=_FIXED_NOW) == 20.0


def test_days_until_expiry_missing_not_after_is_neutral():
    assert days_until_expiry({}, now=_FIXED_NOW) is None
    assert days_until_expiry({"notAfter": None}, now=_FIXED_NOW) is None
    assert days_until_expiry({"notAfter": ""}, now=_FIXED_NOW) is None


def test_days_until_expiry_malformed_not_after_is_neutral():
    assert days_until_expiry({"notAfter": "not-a-date"}, now=_FIXED_NOW) is None


def test_tls_expiry_within_30_days_emits_negative(monkeypatch):
    not_after = _asctime_not_after(_FIXED_NOW + timedelta(days=20))
    _patch_tls(monkeypatch, not_after=not_after)
    monkeypatch.setattr(
        "app.services.collectors.ssl._now_utc", lambda: _FIXED_NOW
    )
    items = asyncio.run(collect_tls("example.com"))
    signals = [i.signal for i in items]
    assert signals == ["ssl_valid", "ssl_expiry"]
    expiry = next(i for i in items if i.signal == "ssl_expiry")
    assert expiry.effect == -2.0
    assert expiry.confidence == 1.0


def test_tls_expiry_outside_30_days_no_item(monkeypatch):
    not_after = _asctime_not_after(_FIXED_NOW + timedelta(days=31))
    _patch_tls(monkeypatch, not_after=not_after)
    monkeypatch.setattr(
        "app.services.collectors.ssl._now_utc", lambda: _FIXED_NOW
    )
    items = asyncio.run(collect_tls("example.com"))
    assert [i.signal for i in items] == ["ssl_valid"]


def test_tls_expiry_exactly_30_days_emits(monkeypatch):
    not_after = _asctime_not_after(_FIXED_NOW + timedelta(days=30))
    _patch_tls(monkeypatch, not_after=not_after)
    monkeypatch.setattr(
        "app.services.collectors.ssl._now_utc", lambda: _FIXED_NOW
    )
    items = asyncio.run(collect_tls("example.com"))
    assert [i.signal for i in items] == ["ssl_valid", "ssl_expiry"]


def test_tls_expiry_missing_not_after_neutral(monkeypatch):
    class NoExpiryTLS(FakeTLS):
        def getpeercert(self):
            return {"subject": ((("organizationName", "Example Org"),),)}

    ctx = mock.Mock()
    ctx.wrap_socket.return_value = NoExpiryTLS()
    monkeypatch.setattr(
        "app.services.collectors.ssl.resolve_and_pin", lambda host, port: "1.1.1.1"
    )
    monkeypatch.setattr(
        "app.services.collectors.ssl.socket.create_connection",
        lambda addr, timeout: FakeConn(),
    )
    monkeypatch.setattr(
        "app.services.collectors.ssl.ssl.create_default_context", lambda: ctx
    )
    monkeypatch.setattr(
        "app.services.collectors.ssl._now_utc", lambda: _FIXED_NOW
    )
    items = asyncio.run(collect_tls("example.com"))
    assert [i.signal for i in items] == ["ssl_valid"]


def test_tls_expiry_malformed_not_after_neutral(monkeypatch):
    _patch_tls(monkeypatch, not_after="garbage-not-after")
    monkeypatch.setattr(
        "app.services.collectors.ssl._now_utc", lambda: _FIXED_NOW
    )
    items = asyncio.run(collect_tls("example.com"))
    assert [i.signal for i in items] == ["ssl_valid"]


# ---------- V1-H3: TLS SSRF / pinning ----------

def test_tls_non_public_resolution_rejected_neutral(monkeypatch):
    from app.services.network_security import NonPublicDestinationError

    monkeypatch.setattr(
        "app.services.collectors.ssl.resolve_and_pin",
        lambda host, port: (_ for _ in ()).throw(
            NonPublicDestinationError(host, reason="private_ip_rejected")
        ),
    )
    outcomes = {}
    items = asyncio.run(collect_tls("evil.example", outcomes=outcomes))
    assert items == []  # SSRF rejection -> unavailable/neutral, never a penalty
    assert outcomes.get("tls") == "private_ip_rejected"


def test_tls_dns_failure_rejected_neutral(monkeypatch):
    from app.services.network_security import NonPublicDestinationError

    monkeypatch.setattr(
        "app.services.collectors.ssl.resolve_and_pin",
        lambda host, port: (_ for _ in ()).throw(
            NonPublicDestinationError(host, reason="dns_failed")
        ),
    )
    outcomes = {}
    items = asyncio.run(collect_tls("doesnotexist.example", outcomes=outcomes))
    assert items == []
    assert outcomes.get("tls") == "dns_failed"


def test_tls_connects_to_validated_ip_with_sni(monkeypatch):
    # The socket destination must be the validated IP; the hostname is kept
    # only for SNI / certificate verification (server_hostname).
    import ssl as _ssl

    calls = {}

    class FakeConn2:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_connect(addr, timeout):
        calls["addr"] = addr
        return FakeConn2()

    ctx = mock.Mock()
    ctx.wrap_socket.return_value = FakeTLS()
    monkeypatch.setattr(
        "app.services.collectors.ssl.resolve_and_pin", lambda host, port: "1.1.1.1"
    )
    monkeypatch.setattr("app.services.collectors.ssl.socket.create_connection", fake_connect)
    monkeypatch.setattr(
        "app.services.collectors.ssl.ssl.create_default_context", lambda: ctx
    )

    items = asyncio.run(collect_tls("example.com"))
    assert calls["addr"] == ("1.1.1.1", 443)  # pinned validated IP is the target
    assert len(items) == 1 and items[0].signal == "ssl_valid"
    # SNI / cert verification still uses the logical hostname.
    assert ctx.wrap_socket.call_args.kwargs.get("server_hostname") == "example.com"


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


def test_http_https_3xx_success_is_reachable():
    # A 3xx without a Location header is a terminal response; it is still a
    # working HTTPS endpoint (200 <= status < 400).
    items = _run_http(
        "https://example.com/", lambda req: httpx.Response(304, text="")
    )
    assert len(items) == 1
    assert items[0].signal == "https_ok"
    assert items[0].effect == 2.0
    assert items[0].value["status_code"] == 304


def test_http_https_root_404_no_credit_entry_error():
    items = _run_http(
        "https://example.com/", lambda req: httpx.Response(404, text="nope")
    )
    signals = {i.signal: i.effect for i in items}
    assert "https_ok" not in signals
    assert signals.get("http_entry_error") == -2.0


def test_http_https_root_500_no_credit_entry_error():
    items = _run_http(
        "https://example.com/", lambda req: httpx.Response(500, text="boom")
    )
    signals = {i.signal: i.effect for i in items}
    assert "https_ok" not in signals
    assert signals.get("http_entry_error") == -2.0


def test_http_https_deep_path_404_neutral():
    # A 404 on a scanned deep path is the URL's fault, not the site's.
    items = _run_http(
        "https://example.com/some/deep/page",
        lambda req: httpx.Response(404, text="nope"),
    )
    assert items == []


def test_http_page_with_error_no_entry_error():
    # HTTP-only pages are never given the HTTPS entry-error penalty.
    items = _run_http(
        "http://example.com/", lambda req: httpx.Response(500, text="boom")
    )
    assert items == []


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
                     effect=6.0, confidence=1.0, source="tls"),
    ]
    http = [
        EvidenceItem(id="HTTP_HTTPS", category="http", signal="https_ok",
                     effect=2.0, confidence=1.0, source="http"),
    ]
    result = evaluate_evidence(rdap + tls + http)
    assert result.score == 63.0  # 50 + 5 (domain) + 6 (ssl) + 2 (http)
    assert result.category_contributions == {"domain": 5.0, "ssl": 6.0, "http": 2.0}
    assert len(result.applied_evidence) == 3
    assert result.confidence > 0.5


def test_evidence_assembly_collector_failures_are_neutral():
    # TLS and HTTP unavailable -> only RDAP evidence applies, no penalty.
    rdap = rdap_evidence_items({"source": "rdap", "domain_age_days": 500, "status": []})
    result = evaluate_evidence(rdap)
    assert result.score == 50.0
    assert result.category_contributions == {"domain": 0.0}
