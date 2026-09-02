"""HTTP behavior evidence collector (Phase 2b).

Performs a real HTTP/HTTPS request with a bounded timeout and a bounded
maximum number of redirects, then records the observed behavior:

- HTTPS endpoint reached successfully -> ``+2``.
- HTTP -> HTTPS redirect observed -> ``+2``.
- HTTPS -> HTTP transport downgrade observed (a request for HTTPS was
  answered over plain HTTP) -> ``-1``. This is the scheme-mirror of the
  upgrade signal and can only occur through a redirect hop (the fetch itself
  is TLS). Plain-HTTP reachability (original scheme ``http``) is never
  penalized here.
- Redirect loop / excessive redirects -> ``-3``.
- Connection / timeout / unavailable -> no evidence, no penalty.

Ordinary HTTP availability is not penalized on its own. Never raises out of
the collector boundary.
"""

from typing import List, Optional
from urllib.parse import urlparse

import httpx

from app.models.evidence import EvidenceItem
from app.services.rdap import is_public_hostname

HTTP_TIMEOUT = 8.0
MAX_REDIRECTS = 5

_USER_AGENT = (
    "WebsiteTruthSerum/1.0 (http://websitetruthserum.com; info@websitetruthserum.com)"
)


async def _guard_redirect_targets(request: httpx.Request) -> None:
    """SSRF guard: abort requests whose target host is not a public hostname."""
    if not is_public_hostname(request.url.host):
        raise ValueError(f"blocked non-public host: {request.url.host}")


def analyze_http_response(
    response: Optional[httpx.Response],
    original_url: str,
    redirect_loop: bool = False,
) -> List[EvidenceItem]:
    """Derive HTTP-behavior evidence from an already-fetched response.

    Pure and deterministic; used by the evidence orchestrator to reuse the
    single SSRF-validated page response instead of issuing a second GET.
    ``redirect_loop`` records a TooManyRedirects outcome when no response
    object was produced.
    """
    if redirect_loop:
        return [
            EvidenceItem(
                id="HTTP_LOOP",
                category="http",
                signal="redirect_loop",
                value=None,
                effect=-3.0,
                confidence=1.0,
                source="http",
                explanation="Excessive redirects or a redirect loop was detected.",
            )
        ]
    if response is None:
        return []

    original_scheme = urlparse(original_url).scheme
    final_url = str(response.url)
    final_scheme = response.url.scheme
    redirect_count = len(response.history)
    status_code = response.status_code

    facts = {
        "final_url": final_url,
        "status_code": status_code,
        "redirect_count": redirect_count,
    }

    items: List[EvidenceItem] = []
    # https_ok rewards genuine reachability: an HTTPS endpoint that actually
    # answered with a successful status. An error response (4xx/5xx) means the
    # site is reachable but NOT serving normally, so it is never credited here.
    if final_scheme == "https" and 200 <= status_code < 400:
        items.append(
            EvidenceItem(
                id="HTTP_HTTPS",
                category="http",
                signal="https_ok",
                value=facts,
                effect=2.0,
                confidence=1.0,
                source="http",
                explanation="HTTPS endpoint responded successfully.",
            )
        )
    if original_scheme == "http" and final_scheme == "https":
        items.append(
            EvidenceItem(
                id="HTTP_UPGRADE",
                category="http",
                signal="http_to_https",
                value=True,
                effect=2.0,
                confidence=1.0,
                source="http",
                explanation="Site redirects HTTP traffic to HTTPS.",
            )
        )
    if original_scheme == "https" and final_scheme == "http":
        items.append(
            EvidenceItem(
                id="HTTP_DOWNGRADE",
                category="http",
                signal="https_downgrade",
                value={
                    "status_code": status_code,
                    "redirect_count": redirect_count,
                },
                effect=-1.0,
                confidence=1.0,
                source="http",
                explanation=(
                    "The site downgraded the request transport from HTTPS to "
                    "HTTP for the final page."
                ),
            )
        )
    # http_entry_error: the site's primary (root) page answered with an error
    # status over HTTPS. A degraded homepage is a real negative signal; a 4xx
    # on a deep scanned path is the scanned URL's fault, not the site's, so it
    # stays neutral. HTTP-only pages are never penalized here.
    if final_scheme == "https" and urlparse(original_url).path in ("", "/") and status_code >= 400:
        items.append(
            EvidenceItem(
                id="HTTP_ENTRY_ERR",
                category="http",
                signal="http_entry_error",
                value=facts,
                effect=-2.0,
                confidence=1.0,
                source="http",
                explanation=(
                    f"The site's primary page returned HTTP error status "
                    f"{status_code} over HTTPS."
                ),
            )
        )
    return items


async def collect_http(
    url: str,
    client: Optional[httpx.AsyncClient] = None,
) -> List[EvidenceItem]:
    """Collect HTTP behavior evidence for a URL. Never raises.

    ``client`` is optional and only used for test injection (e.g. a client
    backed by ``httpx.MockTransport``).
    """
    items: List[EvidenceItem] = []

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            event_hooks={"request": [_guard_redirect_targets]},
        )

    try:
        response = await client.get(url, headers={"User-Agent": _USER_AGENT})
    except httpx.TooManyRedirects:
        return analyze_http_response(None, url, redirect_loop=True)
    except httpx.TimeoutException:
        return items  # unavailable, no penalty
    except httpx.NetworkError:
        return items  # unavailable, no penalty
    except Exception:
        return items  # never raise out of the collector boundary
    finally:
        if owns_client:
            try:
                await client.aclose()
            except Exception:
                pass

    return analyze_http_response(response, url)
