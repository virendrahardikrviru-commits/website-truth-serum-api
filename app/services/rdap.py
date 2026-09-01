"""Real RDAP-based domain intelligence provider.

Discovers the correct RDAP server for each TLD using the IANA RDAP bootstrap
data, performs the lookup, parses the response, and normalizes it into a
provider-independent structure.

This module is intentionally isolated so an alternative RDAP provider (or a
WHOIS provider) can be added later behind the same interface. It never
fabricates registration data: any field RDAP does not provide is returned as
``None`` (or an empty list) and recorded in the ``notes`` list.
"""

import re
from datetime import date
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_TIMEOUT = 10.0

# Module-level cache of the IANA RDAP bootstrap data (tld -> RDAP base URL).
_bootstrap_cache: Optional[Dict[str, str]] = None

# Matches a lowercase hostname with dot-separated labels and a letter TLD.
# Rejects IP addresses, single-label names, underscores, spaces, etc.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def normalize_domain(raw: str) -> Optional[str]:
    """Normalize and validate user-supplied domain input.

    Accepts ``example.com``, ``https://example.com`` and
    ``http://example.com/path`` and normalizes them all to ``example.com``.
    Returns ``None`` for invalid input.
    """
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    if not value:
        return None

    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        # Treat scheme-less values as URLs so paths/ports are handled too.
        parsed = urlparse(f"http://{value}")
        host = parsed.hostname or parsed.path

    host = host.strip().rstrip(".")
    if not _DOMAIN_RE.match(host):
        return None
    return host


def is_public_hostname(host: str) -> bool:
    """True only for a valid, public-looking hostname.

    Rejects IP literals (private, loopback, link-local or otherwise),
    single-label names (e.g. ``localhost``) and anything that is not a
    dot-separated hostname with a letter TLD. Used as an SSRF guard before any
    outbound network request.
    """
    return normalize_domain(host) is not None


def calculate_domain_age(iso_date: Optional[str]) -> Optional[int]:
    """Calculate domain age in whole days from an ISO date string."""
    if not iso_date:
        return None
    try:
        created = date.fromisoformat(str(iso_date)[:10])
    except ValueError:
        return None
    return max((date.today() - created).days, 0)


def parse_rdap_response(domain: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a raw RDAP JSON response into the normalized result shape."""
    notes: List[str] = []
    registered = _event_date(data, "registration")
    expires = _event_date(data, "expiration")
    updated = _event_date(data, "last changed")
    registrar = _registrar(data)
    nameservers = _nameservers(data)
    status = [str(s) for s in (data.get("status") or [])]
    resolved_domain = data.get("ldhName") or data.get("unicodeName") or domain

    if registered is None:
        notes.append("RDAP did not provide a registration date.")
    if expires is None:
        notes.append("RDAP did not provide an expiration date.")
    if updated is None:
        notes.append("RDAP did not provide a last-updated date.")
    if registrar is None:
        notes.append("RDAP did not provide a registrar.")
    if not nameservers:
        notes.append("RDAP did not provide nameservers.")

    return {
        "domain": resolved_domain,
        "registered": registered,
        "expires": expires,
        "updated": updated,
        "registrar": registrar,
        "nameservers": nameservers,
        "domain_age_days": calculate_domain_age(registered),
        "status": status,
        "source": "rdap",
        "notes": notes,
    }


def reset_bootstrap_cache() -> None:
    """Clear the cached IANA bootstrap data (used by tests)."""
    global _bootstrap_cache
    _bootstrap_cache = None


def _parse_bootstrap(data: Dict[str, Any]) -> Dict[str, str]:
    """Convert raw IANA ``dns.json`` into a {tld: base_url} mapping."""
    mapping: Dict[str, str] = {}
    for entry in data.get("services") or []:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        if not urls:
            continue
        base = str(urls[0]).rstrip("/")
        for tld in tlds:
            mapping[str(tld).lower()] = base
    return mapping


async def _load_bootstrap(client: httpx.AsyncClient) -> Optional[Dict[str, str]]:
    """Fetch (and cache) the IANA RDAP bootstrap data."""
    global _bootstrap_cache
    if _bootstrap_cache is not None:
        return _bootstrap_cache
    try:
        response = await client.get(RDAP_BOOTSTRAP_URL)
        response.raise_for_status()
        _bootstrap_cache = _parse_bootstrap(response.json())
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        _bootstrap_cache = None
    return _bootstrap_cache


async def rdap_lookup(
    domain: str,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """Look up RDAP data for a normalized domain.

    Returns a dict compatible with ``DomainIntelResponse`` plus a ``notes``
    list describing RDAP limitations. On any failure the source is set to
    ``rdap_unavailable`` and fields are left as ``None``/empty.

    ``client`` is optional and only used for test injection; when omitted the
    service manages its own ``httpx.AsyncClient``.
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "registered": None,
        "expires": None,
        "updated": None,
        "registrar": None,
        "nameservers": [],
        "domain_age_days": None,
        "status": [],
        "source": "rdap",
        "notes": [],
    }

    owns_client = client is None
    if client is None:
        # Redirects are disabled: an unguarded redirect could redirect a scan
        # to an internal target, and RDAP servers are expected to answer
        # directly. A 3xx is treated as an unavailable result.
        client = httpx.AsyncClient(timeout=RDAP_TIMEOUT, follow_redirects=False)

    try:
        bootstrap = await _load_bootstrap(client)
        if not bootstrap:
            result["source"] = "rdap_unavailable"
            result["notes"].append("RDAP bootstrap data could not be retrieved.")
            return result

        tld = domain.rsplit(".", 1)[-1].lower()
        base_url = bootstrap.get(tld)
        if base_url is None:
            result["source"] = "rdap_unavailable"
            result["notes"].append(
                f"RDAP is not available for the .{tld} top-level domain."
            )
            return result

        url = f"{base_url}/domain/{domain}"
        try:
            response = await client.get(url)
        except httpx.TimeoutException:
            result["source"] = "rdap_unavailable"
            result["notes"].append("RDAP request timed out.")
            return result
        except httpx.NetworkError:
            result["source"] = "rdap_unavailable"
            result["notes"].append("RDAP server is unreachable.")
            return result

        if response.status_code == 404:
            result["source"] = "rdap_unavailable"
            result["notes"].append("Domain was not found in the RDAP registry.")
            return result
        if response.status_code != 200:
            result["source"] = "rdap_unavailable"
            result["notes"].append(
                f"RDAP server returned HTTP {response.status_code}."
            )
            return result

        try:
            data = response.json()
        except ValueError:
            result["source"] = "rdap_unavailable"
            result["notes"].append("RDAP response was malformed.")
            return result

        return parse_rdap_response(domain, data)
    except Exception:
        result["source"] = "rdap_unavailable"
        result["notes"].append("An unexpected error occurred during the RDAP lookup.")
        return result
    finally:
        if owns_client:
            try:
                await client.aclose()
            except Exception:
                pass


def _event_date(data: Dict[str, Any], action: str) -> Optional[str]:
    for event in data.get("events") or []:
        if str(event.get("eventAction", "")).lower() == action:
            event_date = event.get("eventDate")
            if event_date:
                return str(event_date)[:10]
    return None


def _registrar(data: Dict[str, Any]) -> Optional[str]:
    for entity in data.get("entities") or []:
        if "registrar" in (entity.get("roles") or []):
            name = _vcard_fn(entity)
            if name:
                return name
            handle = entity.get("handle")
            if handle:
                return str(handle)
    return None


def _vcard_fn(entity: Dict[str, Any]) -> Optional[str]:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and str(item[0]).lower() == "fn":
                return str(item[3])
    return None


def _nameservers(data: Dict[str, Any]) -> List[str]:
    servers: List[str] = []
    for ns in data.get("nameservers") or []:
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            servers.append(str(name))
    return servers
