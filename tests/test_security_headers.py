import asyncio
import json

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
    # 7 positive headers + 1 neutral framing audit (XFO + protective CSP).
    assert len(items) == 8
    assert effects["framing"] == 0.0


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
        EvidenceItem(id="TLS_001", category="ssl", signal="ssl_valid",
                     value="TLSv1.3", effect=6.0, confidence=1.0, source="tls"),
    ]
    http = [
        EvidenceItem(id="HTTP_HTTPS", category="http", signal="https_ok",
                     effect=2.0, confidence=1.0, source="http"),
    ]
    headers = _analyze_headers(httpx.Headers(GOOD_HEADERS))
    result = evaluate_evidence(rdap + tls + http + headers)
    # 50 + 5 (domain) + 6 (ssl) + 2 (http) + 5 (headers capped) = 68
    assert result.score == 68.0
    assert result.category_contributions == {
        "domain": 5.0, "ssl": 6.0, "http": 2.0, "security_headers": 5.0,
    }
    assert result.confidence > 0.5  # 4 of 11 planned categories usable


# ================================================================
# V1.3.1: COOP / CORP / COEP / CSP-Report-Only
# ================================================================

NEW_POSITIVE_HEADERS = {
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "content-security-policy-report-only": "default-src 'self'",
}


def test_v131_new_security_headers_positive():
    items = _analyze_headers(httpx.Headers(NEW_POSITIVE_HEADERS))
    effects = _signals(items)
    for signal in ("coop", "corp", "coep", "csp_report_only"):
        assert effects[signal] == 1.0
    for item in items:
        assert item.category == "security_headers"
        assert item.source == "security_headers"
    expected_values = {
        "coop": "same-origin",
        "corp": "same-origin",
        "coep": "require-corp",
        "csp_report_only": "default-src 'self'",
    }
    assert {i.signal: i.value for i in items} == expected_values


def test_v131_empty_new_headers_are_neutral_not_negative():
    empty = {name: "" for name in NEW_POSITIVE_HEADERS}
    items = _analyze_headers(httpx.Headers(empty))
    effects = _signals(items)
    for signal in ("coop", "corp", "coep", "csp_report_only"):
        assert effects.get(signal) == 0.0
    assert not any(i.effect < 0 for i in items)


def test_v131_absent_new_headers_produce_no_evidence():
    items = _analyze_headers(httpx.Headers({"content-type": "text/html"}))
    assert not ({"coop", "corp", "coep", "csp_report_only"} & {i.signal for i in items})


def test_v131_new_headers_respect_category_cap():
    headers = dict(GOOD_HEADERS)
    headers.update(NEW_POSITIVE_HEADERS)
    items = _analyze_headers(httpx.Headers(headers))
    result = evaluate_evidence(items)
    assert result.category_contributions["security_headers"] == 5.0
    assert any("cap" in n and "security_headers" in n for n in result.notes)


# ================================================================
# V1.3.1: Cookie security attributes (privacy + neutrality)
# ================================================================

# Neutral audits are only appended when the category is already measured by a
# security-header item, so the cookie tests pair Set-Cookie with HSTS.
COOKIE_COMPANION = {"strict-transport-security": "max-age=31536000"}


def _cookie_items(pairs, scheme="https"):
    headers = httpx.Headers(list(COOKIE_COMPANION.items()) + list(pairs))
    return [i for i in _analyze_headers(headers, scheme=scheme)
            if i.signal == "cookie_security"]


def test_v131_cookie_audit_records_only_safe_facts():
    items = _cookie_items(
        [("set-cookie", "session=abc123TOPSECRET; Path=/; Secure; HttpOnly; SameSite=Lax")]
    )
    assert len(items) == 1
    item = items[0]
    assert item.effect == 0.0
    assert item.value == {
        "cookie_count": 1,
        "secure_all": True,
        "httponly_all": True,
        "samesite_all": True,
        "samesite_values": ["lax"],
    }
    serialized = json.dumps([i.model_dump() for i in items])
    assert "abc123TOPSECRET" not in serialized
    assert "session" not in serialized


def test_v131_cookie_missing_attributes_are_neutral():
    items = _cookie_items([("set-cookie", "sid=xyz; Path=/")])
    assert len(items) == 1
    item = items[0]
    assert item.effect == 0.0  # never a penalty for a missing attribute
    assert item.value["secure_all"] is False
    assert item.value["httponly_all"] is False
    assert item.value["samesite_all"] is False


def test_v131_cookie_audit_only_on_https_scheme():
    headers = httpx.Headers(
        list(COOKIE_COMPANION.items()) + [("set-cookie", "sid=x; Secure")]
    )
    for scheme in ("http", None):
        signals = {i.signal for i in _analyze_headers(headers, scheme=scheme)}
        assert signals == {"hsts"}
    signals = {i.signal for i in _analyze_headers(headers, scheme="https")}
    assert signals == {"hsts", "cookie_security"}


def test_v131_multiple_cookies_aggregated():
    items = _cookie_items(
        [
            ("set-cookie", "a=1; Secure; HttpOnly"),
            ("set-cookie", "b=2; Path=/; SameSite=Strict"),
        ]
    )
    assert len(items) == 1
    value = items[0].value
    assert value["cookie_count"] == 2
    assert value["secure_all"] is False
    assert value["httponly_all"] is False
    assert value["samesite_all"] is False
    assert value["samesite_values"] == ["strict"]


def test_v131_cookie_only_response_produces_no_items():
    # With no security-header item present, the audit must not fire: it can
    # never be the sole evidence that marks security_headers as measured.
    headers = httpx.Headers({"set-cookie": "sid=abc; Secure; HttpOnly"})
    assert _analyze_headers(headers, scheme="https") == []
    result = evaluate_evidence(_analyze_headers(headers, scheme="https"))
    assert result.score == 50.0
    assert result.category_contributions == {}
    assert result.confidence == 0.0


def test_v131_evidence_engine_counts_effect_zero_items_as_measured():
    # Confidence-flow demonstration: the engine marks a capped category usable
    # for ANY item in it, including an effect-0 audit-only item (scoring.py
    # adds the category to usable_categories before applying effects). This is
    # why V1.3.1 gates neutral audits behind an already-measured category.
    audit_only = [
        EvidenceItem(
            id="HDR_COOKIE", category="security_headers", signal="cookie_security",
            value={"cookie_count": 1}, effect=0.0, confidence=1.0,
            source="security_headers",
        )
    ]
    result = evaluate_evidence(audit_only)
    assert result.category_contributions == {"security_headers": 0.0}
    assert result.confidence == 0.41  # 1 of 11 planned categories usable
    assert result.score == 50.0  # zero scoring effect


# ================================================================
# V1.3.1: Framing redundancy / consistency
# ================================================================

def test_v131_framing_redundant_audit_when_both_protective():
    headers = httpx.Headers(
        {
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
        }
    )
    items = _analyze_headers(headers)
    effects = _signals(items)
    assert effects["x_frame_options"] == 1.0
    assert effects["csp_frame_ancestors"] == 1.0
    audit = next(i for i in items if i.signal == "framing")
    assert audit.effect == 0.0


def test_v131_no_framing_audit_with_single_mechanism():
    xfo_only = _analyze_headers(httpx.Headers({"x-frame-options": "DENY"}))
    csp_only = _analyze_headers(
        httpx.Headers({"content-security-policy": "default-src 'self'; frame-ancestors 'self'"})
    )
    assert all(i.signal != "framing" for i in xfo_only + csp_only)


def test_csp_frame_ancestors_wildcard_preserves_v12_behavior():
    # V1.2 semantics: csp_frame_ancestors is +1 whenever frame-ancestors is
    # present, regardless of its value (allow-all included). Restored unchanged.
    headers = httpx.Headers(
        {"content-security-policy": "default-src 'self'; frame-ancestors *"}
    )
    items = _analyze_headers(headers)
    effects = _signals(items)
    assert effects["csp"] == 1.0
    assert effects["csp_frame_ancestors"] == 1.0  # V1.2 behavior preserved
    assert not any(i.signal == "framing" for i in items)  # no X-Frame-Options


def test_v131_framing_audit_is_presence_based():
    # The framing audit fires when XFO and CSP frame-ancestors are both present
    # (even allow-all); it does not reinterpret the CSP value.
    headers = httpx.Headers(
        {
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'; frame-ancestors *",
        }
    )
    items = _analyze_headers(headers)
    effects = _signals(items)
    assert effects["x_frame_options"] == 1.0
    assert effects["csp_frame_ancestors"] == 1.0  # V1.2 semantics intact
    audit = next(i for i in items if i.signal == "framing")
    assert audit.effect == 0.0
