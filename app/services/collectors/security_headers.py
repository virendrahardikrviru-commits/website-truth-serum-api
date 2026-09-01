"""Security headers evidence collector (Phase 2c-1).

Observes HTTP security headers from a real response and converts them into
small, conservative EvidenceItems. Only actual observations produce items;
missing headers, timeouts, redirect loops and network failures produce no
evidence and zero score impact (a missing header never makes the site unsafe
on its own).

All effects are small (+/-1) so the whole category stays within its +/-5 cap,
and no single header exceeds the per-signal limit.
"""

import re
from typing import List, Optional

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
}


def _item(signal: str, value: Optional[str], effect: float, explanation: str) -> EvidenceItem:
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


def _analyze_headers(headers) -> List[EvidenceItem]:
    """Convert observed response headers into EvidenceItems (pure function)."""
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

    xfo = _present(headers, "x-frame-options")
    if xfo is not None:
        if xfo.lower() in {"deny", "sameorigin"}:
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

    return items


def analyze_headers_response(response: Optional[httpx.Response]) -> List[EvidenceItem]:
    """Derive security-header evidence from an already-fetched response.

    Pure and deterministic; used by the evidence orchestrator to reuse the
    single SSRF-validated page response instead of issuing a second GET.
    """
    if response is None:
        return []
    return _analyze_headers(response.headers)


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
