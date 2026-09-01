import asyncio

import httpx

from app.models.evidence import EvidenceItem
from app.services.collectors.http_behavior import collect_http
from app.services.collectors.security_headers import _analyze_headers, collect_security_headers
from app.services.collectors.ssl import collect_tls
from app.services.evidence import rdap_evidence_items
from app.services.scoring import evaluate_evidence

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}


def _signals(items):
    return {i.signal: i.effect for i in items}


# ---------- Pure header analysis ----------

def test_all_recommended_headers_present():
    items = _analyze_headers(httpx.Headers(GOOD_HEADERS))
    effects = _signals(items)
    assert effects["hsts"] == 1.0
    assert effects["csp"] == 1.0
    assert effects["csp_frame_ancestors"] == 1.0
    assert effects["nosniff"] == 1.0
    assert effects["x_frame_options"] == 1.0
    assert effects["referrer_policy"] == 1.0
    assert effects["permissions_policy"] == 1.0
    for item in items:
        assert item.category == "security_headers"
        assert item.source == "security_headers"
        assert isinstance(item.explanation, str) and item.explanation


def test_individual_headers_missing_produce_no_evidence():
    items = _analyze_headers(httpx.Headers({}))
    assert items == []


def test_csp_frame_ancestors_alone_provides_framing_protection():
    items = _analyze_headers(
        httpx.Headers({"content-security-policy": "default-src 'self'; frame-ancestors 'none'"})
    )
    effects = _signals(items)
    # X-Frame-Options absent must not be penalized; CSP provides framing.
    assert "x_frame_options" not in effects
    assert effects["csp_frame_ancestors"] == 1.0


def test_xfo_valid_without_csp():
    items = _analyze_headers(httpx.Headers({"x-frame-options": "SAMEORIGIN"}))
    effects = _signals(items)
    assert effects["x_frame_options"] == 1.0
    assert "csp_frame_ancestors" not in effects


def test_invalid_or_misleading_header_values():
    items = _analyze_headers(
        httpx.Headers(
            {
                "strict-transport-security": "max-age=0",
                "x-content-type-options": "nosniff-extra",
                "x-frame-options": "FOOBAR",
                "referrer-policy": "not-a-real-policy",
            }
        )
    )
    effects = _signals(items)
    assert effects["hsts"] == -1.0
    assert effects["nosniff"] == -1.0
    assert effects["x_frame_options"] == -1.0
    assert effects["referrer_policy"] == -1.0


def test_referrer_policy_comma_separated_list_is_valid():
    # GitHub sends: origin-when-cross-origin, strict-origin-when-cross-origin
    items = _analyze_headers(
        httpx.Headers(
            {"referrer-policy": "origin-when-cross-origin, strict-origin-when-cross-origin"}
        )
    )
    effects = _signals(items)
    assert effects["referrer_policy"] == 1.0
    assert not any(i.effect < 0 for i in items)


def test_referrer_policy_all_invalid_entries_remain_invalid():
    items = _analyze_headers(
        httpx.Headers({"referrer-policy": "bogus-a, bogus-b"})
    )
    effects = _signals(items)
    assert effects["referrer_policy"] == -1.0


def test_weak_hsts_is_neutral_not_negative():
    items = _analyze_headers(httpx.Headers({"strict-transport-security": "max-age=600"}))
    effects = _signals(items)
    assert effects["hsts"] == 0.0


def test_normal_http_response_with_no_security_headers():
    items = _analyze_headers(httpx.Headers({"content-type": "text/html"}))
    assert items == []


# ---------- Collector via mocked transport ----------

def _run(url, handler, max_redirects=5):
    async def _run_inner():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, follow_redirects=True, max_redirects=max_redirects,
            timeout=5.0,
        ) as client:
            return await collect_security_headers(url, client=client)

    return asyncio.run(_run_inner())


def test_collector_reads_final_response_headers():
    items = _run(
        "https://example.com/",
        lambda req: httpx.Response(200, text="ok", headers=GOOD_HEADERS),
    )
    effects = _signals(items)
    assert effects["hsts"] == 1.0
    assert len(items) == 7


def test_collector_timeout_unavailable_no_penalty():
    def handler(req):
        raise httpx.ReadTimeout("timed out", request=req)

    assert _run("https://example.com/", handler) == []


def test_collector_network_failure_unavailable_no_penalty():
    def handler(req):
        raise httpx.ConnectError("refused", request=req)

    assert _run("https://example.com/", handler) == []


def test_collector_redirect_loop_unavailable_no_penalty():
    def handler(req):
        return httpx.Response(302, headers={"location": str(req.url)})

    assert _run("https://example.com/", handler) == []


# ---------- Category cap + assembly ----------

def test_security_headers_category_cap():
    # Seven +1 signals (7 raw) must be capped at the ±5 category cap.
    items = _analyze_headers(httpx.Headers(GOOD_HEADERS))
    result = evaluate_evidence(items)
    assert result.category_contributions["security_headers"] == 5.0
    assert result.score == 55.0
    assert any("cap" in n and "security_headers" in n for n in result.notes)


def test_security_headers_reconciles_under_cap():
    items = _analyze_headers(httpx.Headers(GOOD_HEADERS))
    result = evaluate_evidence(items)
    assert result.score == round(
        50.0 + sum(result.category_contributions.values()), 2
    )


def test_assembly_rdap_tls_http_security_headers():
    rdap = rdap_evidence_items({"source": "rdap", "domain_age_days": 4000, "status": []})
    tls = [
        EvidenceItem(id="TLS_001", category="ssl", signal="ssl_valid", value="TLSv1.3",
                     effect=8.0, confidence=1.0, source="tls"),
    ]
    http = [
        EvidenceItem(id="HTTP_HTTPS", category="http", signal="https_ok",
                     effect=2.0, confidence=1.0, source="http"),
    ]
    headers = _analyze_headers(httpx.Headers(GOOD_HEADERS))
    result = evaluate_evidence(rdap + tls + http + headers)
    # 50 + 5 (domain) + 8 (ssl) + 2 (http) + 5 (headers capped) = 70
    assert result.score == 70.0
    assert result.category_contributions == {
        "domain": 5.0, "ssl": 8.0, "http": 2.0, "security_headers": 5.0,
    }
    assert result.confidence > 0.5  # 4 of 11 planned categories usable
