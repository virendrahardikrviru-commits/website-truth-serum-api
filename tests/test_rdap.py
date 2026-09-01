import asyncio
from datetime import date

import httpx
import pytest

from app.services.rdap import (
    RDAP_BOOTSTRAP_URL,
    calculate_domain_age,
    normalize_domain,
    parse_rdap_response,
    rdap_lookup,
    reset_bootstrap_cache,
)

SAMPLE_BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["uk"], ["https://rdap.nominet.uk/uk/"]],
    ]
}

SAMPLE_RDAP = {
    "ldhName": "example.com",
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2023-07-20T04:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "handle": "292",
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "GoDaddy.com, LLC"]],
            ],
        }
    ],
    "nameservers": [
        {"ldhName": "ns1.example.com"},
        {"ldhName": "ns2.example.com"},
    ],
    "status": ["clientDeleteProhibited", "clientTransferProhibited"],
}


@pytest.fixture(autouse=True)
def _clear_bootstrap_cache():
    reset_bootstrap_cache()
    yield
    reset_bootstrap_cache()


def make_handler(
    bootstrap=None,
    rdap_payload=SAMPLE_RDAP,
    rdap_status=200,
    rdap_error=None,
    bootstrap_error=None,
):
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(RDAP_BOOTSTRAP_URL):
            if bootstrap_error:
                raise bootstrap_error
            return httpx.Response(200, json=bootstrap or SAMPLE_BOOTSTRAP)
        if rdap_error:
            raise rdap_error
        return httpx.Response(rdap_status, json=rdap_payload)

    return handler


async def _lookup_with(handler, domain):
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        return await rdap_lookup(domain, client=client)


def run_lookup(handler, domain):
    return asyncio.run(_lookup_with(handler, domain))


# ---------- Normalization ----------

def test_normalize_domain_accepts_forms():
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("https://example.com") == "example.com"
    assert normalize_domain("http://example.com/path") == "example.com"
    assert normalize_domain("EXAMPLE.com") == "example.com"
    assert normalize_domain("  example.com  ") == "example.com"
    assert normalize_domain("https://www.example.com:8443/x") == "www.example.com"


def test_normalize_domain_rejects_invalid():
    invalid = [
        None,
        "",
        "   ",
        "not a domain",
        "http://",
        "example",
        "example..com",
        "bad_domain.com",
        "192.168.1.1",
        "https://192.168.1.1/",
        "2001:db8::1",
        "exam ple.com",
    ]
    for value in invalid:
        assert normalize_domain(value) is None, f"expected None for {value!r}"


# ---------- Domain age ----------

def test_calculate_domain_age():
    created = date(2000, 1, 1)
    expected = (date.today() - created).days
    assert calculate_domain_age("2000-01-01") == expected
    assert calculate_domain_age("2000-01-01T04:00:00Z") == expected


def test_calculate_domain_age_missing_or_invalid():
    assert calculate_domain_age(None) is None
    assert calculate_domain_age("not-a-date") is None


def test_calculate_domain_age_future_clamped_to_zero():
    future = date.today().replace(year=date.today().year + 5)
    assert calculate_domain_age(future.isoformat()) == 0


# ---------- RDAP success ----------

def test_rdap_success():
    result = run_lookup(make_handler(), "example.com")
    assert result["source"] == "rdap"
    assert result["domain"] == "example.com"
    assert result["registered"] == "1995-08-14"
    assert result["expires"] == "2027-08-13"
    assert result["updated"] == "2023-07-20"
    assert result["registrar"] == "GoDaddy.com, LLC"
    assert result["nameservers"] == ["ns1.example.com", "ns2.example.com"]
    assert result["domain_age_days"] == (date.today() - date(1995, 8, 14)).days
    assert result["status"] == ["clientDeleteProhibited", "clientTransferProhibited"]
    assert result["notes"] == []


def test_rdap_success_verifies_bootstrap_discovery_used():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return make_handler()(request)

    result = run_lookup(handler, "example.com")
    assert result["source"] == "rdap"
    bootstrap_calls = [u for u in seen if u.startswith(RDAP_BOOTSTRAP_URL)]
    lookup_calls = [u for u in seen if not u.startswith(RDAP_BOOTSTRAP_URL)]
    assert bootstrap_calls, "bootstrap was not consulted"
    assert lookup_calls == ["https://rdap.verisign.com/com/v1/domain/example.com"]


# ---------- RDAP missing fields ----------

def test_rdap_missing_fields():
    minimal = {"ldhName": "example.com"}
    result = run_lookup(make_handler(rdap_payload=minimal), "example.com")
    assert result["source"] == "rdap"
    assert result["registered"] is None
    assert result["expires"] is None
    assert result["updated"] is None
    assert result["registrar"] is None
    assert result["nameservers"] == []
    assert result["domain_age_days"] is None
    assert result["status"] == []
    assert len(result["notes"]) == 5


# ---------- RDAP not found ----------

def test_rdap_not_found():
    result = run_lookup(make_handler(rdap_status=404), "example.com")
    assert result["source"] == "rdap_unavailable"
    assert result["registered"] is None
    assert result["domain_age_days"] is None
    assert any("not found" in note for note in result["notes"])


# ---------- RDAP timeout / network failure ----------

def test_rdap_timeout():
    result = run_lookup(
        make_handler(rdap_error=httpx.ReadTimeout("timed out")), "example.com"
    )
    assert result["source"] == "rdap_unavailable"
    assert any("timed out" in note for note in result["notes"])


def test_rdap_network_failure():
    result = run_lookup(
        make_handler(rdap_error=httpx.ConnectError("connection refused")),
        "example.com",
    )
    assert result["source"] == "rdap_unavailable"
    assert any("unreachable" in note for note in result["notes"])


def test_rdap_redirect_is_not_followed():
    # A redirecting RDAP server must be treated as unavailable, never followed
    # (V1-H3: unguarded redirects are disabled).
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(RDAP_BOOTSTRAP_URL):
            return httpx.Response(200, json=SAMPLE_BOOTSTRAP)
        return httpx.Response(302, headers={"location": "https://internal.example/evil"})

    result = run_lookup(handler, "example.com")
    assert result["source"] == "rdap_unavailable"
    assert any("HTTP 302" in note for note in result["notes"])


# ---------- RDAP malformed response ----------

def test_rdap_malformed_response():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(RDAP_BOOTSTRAP_URL):
            return httpx.Response(200, json=SAMPLE_BOOTSTRAP)
        return httpx.Response(200, text="<html>not json</html>")

    result = run_lookup(handler, "example.com")
    assert result["source"] == "rdap_unavailable"
    assert any("malformed" in note for note in result["notes"])


# ---------- Unsupported TLD ----------

def test_rdap_unsupported_tld():
    result = run_lookup(make_handler(), "example.xyz")
    assert result["source"] == "rdap_unavailable"
    assert any("top-level domain" in note for note in result["notes"])
    assert result["registered"] is None


# ---------- Bootstrap unavailable ----------

def test_rdap_bootstrap_unavailable():
    result = run_lookup(
        make_handler(bootstrap_error=httpx.ConnectError("no connection")),
        "example.com",
    )
    assert result["source"] == "rdap_unavailable"
    assert any("bootstrap" in note for note in result["notes"])


# ---------- Parse function directly ----------

def test_parse_rdap_response_missing_registration():
    data = {"ldhName": "example.com", "events": []}
    parsed = parse_rdap_response("example.com", data)
    assert parsed["registered"] is None
    assert parsed["domain_age_days"] is None
    assert parsed["source"] == "rdap"
    assert any("registration" in note for note in parsed["notes"])
