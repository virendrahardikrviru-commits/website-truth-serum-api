"""Security headers evidence collector (Phase 2c-1).

Observes HTTP security headers from a real response and converts them into
small, conservative EvidenceItems. Only actual observations produce items;
missing headers, timeouts, redirect loops and network failures produce no
evidence and zero score impact (a missing header never makes the site unsafe
on its own).

All effects are small (+/-1) so the whole category stays within its +/-5 cap,
and no single header exceeds the per-signal limit.

Additional observations (Phase V1.3.1), all derived from the same response
headers and requiring no extra request:

- ``coop`` / ``corp`` / ``coep`` / ``csp_report_only``: +1 when the header is
  present and non-empty (0 when present but empty). Absent is neutral.
- ``cookie_security``: a neutral (effect 0) audit appended only when an
  HTTPS-served response sets cookies AND the category is already measured by
  another security-header item from the same response, so an audit never
  independently marks the category usable. It records only safe
  boolean/attribute facts (Secure/HttpOnly/SameSite presence aggregated across
  cookies). Raw Set-Cookie values are never stored, returned or logged, and a
  missing attribute is never a penalty by itself.
- ``framing``: a neutral (effect 0) audit appended when X-Frame-Options
  (deny/sameorigin) and CSP ``frame-ancestors`` are both present. The
  ``csp_frame_ancestors`` signal keeps its V1.2 behavior unchanged (+1 whenever
  the directive is present).
"""

import re
from typing import Any, Dict, List, Optional

import httpx

from app.models.evidence import EvidenceItem
from app.services.rdap import is_public_hostname

HEADERS_TIMEOUT = 8.0
MAX_REDIRECTS = 5

_USER_AGENT = (
    "WebsiteTruthSerum/1.0 (http://websitetruthserum.com; info@websitetruthserum.com)"
)


async def _guard_redirect_targets(request: httpx.Request) -> None:
    """SSRF guard: abort requests whose target host is not a public hostname."""
    if not is_public_hostname(request.url.host):
        raise ValueError(f"blocked non-public host: {request.url.host}")

# 180 days; HSTS below this is considered weak, not dangerous.
HSTS_GOOD_MAX_AGE = 15552000

VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}

_ITEM_IDS = {
    "hsts": "HDR_HSTS",
    "csp": "HDR_CSP",
    "csp_frame_ancestors": "HDR_CSP_FA",
    "nosniff": "HDR_XCTO",
    "x_frame_options": "HDR_XFO",
    "referrer_policy": "HDR_REFERRER",
    "permissions_policy": "HDR_PERMISSIONS",
    "coop": "HDR_COOP",
    "corp": "HDR_CORP",
    "coep": "HDR_COEP",
    "csp_report_only": "HDR_CSPRO",
    "cookie_security": "HDR_COOKIE",
    "framing": "HDR_FRAMING",
}


def _item(signal: str, value: Optional[Any], effect: float, explanation: str) -> EvidenceItem:
    return EvidenceItem(
        id=_ITEM_IDS[signal],
        category="security_headers",
        signal=signal,
        value=value,
        effect=effect,
        confidence=1.0,
        source="security_headers",
        explanation=explanation,
    )


def _present(headers, name: str) -> Optional[str]:
    """Return the header value if the header is actually present, else None."""
    if name in headers:
        return headers.get(name, "").strip()
    return None


def _parse_max_age(value: str) -> Optional[int]:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


_ADDITIONAL_HEADERS = (
    ("cross-origin-opener-policy", "coop", "Cross-Origin-Opener-Policy"),
    ("cross-origin-resource-policy", "corp", "Cross-Origin-Resource-Policy"),
    ("cross-origin-embedder-policy", "coep", "Cross-Origin-Embedder-Policy"),
    ("content-security-policy-report-only", "csp_report_only",
     "Content-Security-Policy-Report-Only"),
)


def _set_cookie_values(headers) -> List[str]:
    """Return the individual Set-Cookie header values present on a response."""
    values: List[str] = []
    if hasattr(headers, "get_list"):
        values = headers.get_list("set-cookie")
    if not values:
        raw = headers.get("set-cookie")
        if raw:
            values = [raw]
    return values


def _cookie_attribute_facts(values: List[str]) -> Dict[str, Any]:
    """Aggregate cookie security attributes into safe boolean/attribute facts.

    Raw cookie names/values are never captured. ``secure_all`` / ``httponly_all``
    / ``samesite_all`` are true only when every cookie carries the attribute.
    ``samesite_values`` is the sorted set of observed SameSite policy values.
    """
    secure_all = True
    httponly_all = True
    samesite_all = True
    samesite_values: set = set()
    for value in values:
        parts = value.split(";")
        has_secure = False
        has_httponly = False
        has_samesite = False
        for part in parts[1:]:
            token = part.strip()
            lower = token.lower()
            if lower == "secure":
                has_secure = True
            elif lower == "httponly":
                has_httponly = True
            elif lower.startswith("samesite"):
                has_samesite = True
                if "=" in token:
                    policy = token.split("=", 1)[1].strip().lower()
                    if policy:
                        samesite_values.add(policy)
        secure_all = secure_all and has_secure
        httponly_all = httponly_all and has_httponly
        samesite_all = samesite_all and has_samesite
    return {
        "cookie_count": len(values),
        "secure_all": secure_all,
        "httponly_all": httponly_all,
        "samesite_all": samesite_all,
        "samesite_values": sorted(samesite_values),
    }


def _cookie_security_item(values: List[str]) -> Optional[EvidenceItem]:
    """Neutral (effect 0) audit of cookie attribute hygiene for an HTTPS page.

    Only safe facts are stored; missing attributes never produce a penalty.
    """
    if not values:
        return None
    facts = _cookie_attribute_facts(values)
    return EvidenceItem(
        id=_ITEM_IDS["cookie_security"],
        category="security_headers",
        signal="cookie_security",
        value=facts,
        effect=0.0,
        confidence=1.0,
        source="security_headers",
        explanation=(
            f"HTTPS response sets {facts['cookie_count']} cookie(s); "
            f"Secure set on all: {facts['secure_all']}; HttpOnly set on all: "
            f"{facts['httponly_all']}; SameSite set on all: {facts['samesite_all']}."
        ),
    )


def _analyze_headers(headers, scheme: Optional[str] = None) -> List[EvidenceItem]:
    """Convert observed response headers into EvidenceItems (pure function).

    ``scheme`` is the final page scheme observed by the fetch. It gates the
    neutral ``cookie_security`` audit: cookie attributes are only audited for
    HTTPS-served responses (on a plain-HTTP page the whole exchange is already
    insecure by transport and HTTP reachability is never penalized). Neutral
    audits (``cookie_security``, ``framing``) are only appended when the
    category is already measured by a security-header item, so they can never
    be the sole item that makes the category usable.
    """
    items: List[EvidenceItem] = []

    hsts = _present(headers, "strict-transport-security")
    if hsts is not None:
        max_age = _parse_max_age(hsts)
        if max_age == 0:
            items.append(_item(
                "hsts", hsts, -1.0,
                "Strict-Transport-Security is disabled (max-age=0).",
            ))
        elif max_age is not None and max_age >= HSTS_GOOD_MAX_AGE:
            items.append(_item(
                "hsts", hsts, 1.0,
                "Strict-Transport-Security is enabled with a long max-age.",
            ))
        elif max_age is not None:
            items.append(_item(
                "hsts", hsts, 0.0,
                "Strict-Transport-Security is present but with a short max-age.",
            ))
        else:
            items.append(_item(
                "hsts", hsts, 0.0,
                "Strict-Transport-Security is present but without a max-age.",
            ))

    csp = _present(headers, "content-security-policy")
    csp_frame_ancestors_present = False
    if csp is not None:
        if not csp:
            items.append(_item(
                "csp", csp, 0.0,
                "Content-Security-Policy header is present but empty.",
            ))
        else:
            items.append(_item(
                "csp", csp, 1.0,
                "Content-Security-Policy is present.",
            ))
            if "frame-ancestors" in csp.lower():
                csp_frame_ancestors_present = True
                items.append(_item(
                    "csp_frame_ancestors", csp, 1.0,
                    "Content-Security-Policy includes frame-ancestors (framing protection).",
                ))

    xcto = _present(headers, "x-content-type-options")
    if xcto is not None:
        if xcto.lower() == "nosniff":
            items.append(_item(
                "nosniff", xcto, 1.0,
                "X-Content-Type-Options is set to nosniff.",
            ))
        else:
            items.append(_item(
                "nosniff", xcto, -1.0,
                "X-Content-Type-Options has an invalid value (expected nosniff).",
            ))

    xfo_protective = False
    xfo = _present(headers, "x-frame-options")
    if xfo is not None:
        if xfo.lower() in {"deny", "sameorigin"}:
            xfo_protective = True
            items.append(_item(
                "x_frame_options", xfo, 1.0,
                "X-Frame-Options provides framing protection.",
            ))
        else:
            items.append(_item(
                "x_frame_options", xfo, -1.0,
                "X-Frame-Options has an invalid or misleading value.",
            ))

    referrer = _present(headers, "referrer-policy")
    if referrer is not None:
        # Referrer-Policy allows a comma-separated list; the UA applies the
        # first recognized value, so the header is valid if any entry is valid.
        parts = [p.strip().lower() for p in referrer.split(",")]
        if any(p in VALID_REFERRER_POLICIES for p in parts):
            items.append(_item(
                "referrer_policy", referrer, 1.0,
                "Referrer-Policy has a valid value.",
            ))
        else:
            items.append(_item(
                "referrer_policy", referrer, -1.0,
                "Referrer-Policy has an invalid value.",
            ))

    permissions = _present(headers, "permissions-policy")
    if permissions is not None:
        if permissions:
            items.append(_item(
                "permissions_policy", permissions, 1.0,
                "Permissions-Policy is present.",
            ))
        else:
            items.append(_item(
                "permissions_policy", permissions, 0.0,
                "Permissions-Policy header is present but empty.",
            ))

    for header, signal, label in _ADDITIONAL_HEADERS:
        value = _present(headers, header)
        if value is not None:
            if value:
                items.append(_item(
                    signal, value, 1.0,
                    f"{label} header is present.",
                ))
            else:
                items.append(_item(
                    signal, value, 0.0,
                    f"{label} header is present but empty.",
                ))

    if scheme == "https" and items:
        cookie_values = _set_cookie_values(headers)
        cookie_item = _cookie_security_item(cookie_values)
        if cookie_item is not None:
            items.append(cookie_item)

    if xfo_protective and csp_frame_ancestors_present:
        items.append(_item(
            "framing", True, 0.0,
            "Framing protection is redundant and consistent: X-Frame-Options "
            "and a CSP frame-ancestors are both present.",
        ))

    return items


def analyze_headers_response(response: Optional[httpx.Response]) -> List[EvidenceItem]:
    """Derive security-header evidence from an already-fetched response.

    Pure and deterministic; used by the evidence orchestrator to reuse the
    single SSRF-validated page response instead of issuing a second GET. The
    final page scheme gates the neutral cookie-attribute audit.
    """
    if response is None:
        return []
    url = getattr(response, "url", None)
    scheme = getattr(url, "scheme", None)
    return _analyze_headers(response.headers, scheme=scheme)


async def collect_security_headers(
    url: str,
    client: Optional[httpx.AsyncClient] = None,
) -> List[EvidenceItem]:
    """Collect security-header evidence for a URL. Never raises.

    ``client`` is optional and only used for test injection (e.g. a client
    backed by ``httpx.MockTransport``). Headers are read from the final
    response after following redirects within ``MAX_REDIRECTS``.
    """
    items: List[EvidenceItem] = []

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=HEADERS_TIMEOUT,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            event_hooks={"request": [_guard_redirect_targets]},
        )

    try:
        response = await client.get(url, headers={"User-Agent": _USER_AGENT})
    except (httpx.TimeoutException, httpx.NetworkError, httpx.TooManyRedirects):
        return items  # unavailable, no penalty
    except Exception:
        return items  # never raise out of the collector boundary
    finally:
        if owns_client:
            try:
                await client.aclose()
            except Exception:
                pass

    return analyze_headers_response(response)
