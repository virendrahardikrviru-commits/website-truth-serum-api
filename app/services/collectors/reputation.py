"""Threat intelligence / reputation evidence collector (Phase 2c-6).

Keyed, gated, evidence-mode-only provider aggregator. Providers:

- **URLhaus** (abuse.ch): ``POST /v1/host/`` with an ``Auth-Key`` header.
- **Spamhaus DBL** via the Data Query Service DNS zone
  ``{domain}.{key}.dbl.dq.spamhaus.net``.

Design rules enforced here:

- ``REPUTATION_ENABLED`` (default ``false``) must be ``true`` before any
  provider is queried.
- Provider keys come from the environment only (``URLHAUS_API_KEY``,
  ``SPAMHAUS_DQS_KEY``). A missing key makes that provider unavailable
  (neutral) — there are never hardcoded credentials.
- Timeouts, 401/403/429/5xx, DNS failures and malformed responses are all
  treated as unavailable (no evidence, no penalty).
- Clean / not-listed produces **no evidence item** (a clean check is never a
  positive and never inflates breadth/confidence).
- Only confirmed malicious classifications produce negative items. The same
  underlying threat reported by several providers becomes a *single* signal;
  corroboration raises confidence (1 source 0.6, 2 sources 0.8, 3+ 1.0) —
  never one penalty per provider.
- A small in-process cache (~1 hour) reduces repeated provider queries.
- Never raises.
"""

import asyncio
import concurrent.futures
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.models.evidence import EvidenceItem

URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
REPUTATION_TIMEOUT = 6.0
CACHE_TTL_SECONDS = 3600.0
CACHE_MAX_ENTRIES = 512
PER_THREAT_EFFECT = -10.0

# Bounded worker pool for the blocking Spamhaus DNS lookup so sustained
# concurrent scans cannot exhaust the default executor or drift threads.
_DNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="wts-dns"
)

# Corroboration confidence by number of distinct providers confirming a threat.
_CORROBORATION_CONF = {1: 0.6, 2: 0.8}
_DEFAULT_CONF = 1.0

# Spamhaus DBL A-record codes (last octet) -> normalized threat.
_DBL_CODE_TO_THREAT = {
    "2": "spam",    # low-reputation domain
    "4": "phishing",
    "5": "malware",
    "6": "c2",      # botnet C&C domain
    "102": "spam",  # abused-legit domain
    "103": "spam",  # abused redirector
    "104": "phishing",
    "105": "malware",
    "106": "c2",
}

# URLhaus blacklists.spamhaus_dbl value -> normalized threat.
_URLHAUS_DBL_TO_THREAT = {
    "spammer_domain": "spam",
    "phishing_domain": "phishing",
    "botnet_cc_domain": "c2",
    "abused_legit_spam": "spam",
    "abused_legit_malware": "malware",
    "abused_legit_phishing": "phishing",
    "abused_legit_botnetcc": "c2",
}

# In-process cache: key -> (timestamp, ProviderReport). Clean and listed
# results are cached; transient failures are not.
_CACHE: Dict[str, Tuple[float, "ProviderReport"]] = {}


@dataclass
class ProviderReport:
    provider: str
    threats: Tuple[str, ...] = ()
    listed: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)


def _reputation_enabled() -> bool:
    return os.getenv("REPUTATION_ENABLED", "false").strip().lower() == "true"


def _clear_cache() -> None:
    _CACHE.clear()


def _cache_get(key: str) -> Optional["ProviderReport"]:
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL_SECONDS:
        return hit[1]
    return None


def _cache_set(key: str, report: "ProviderReport") -> None:
    now = time.time()
    _CACHE[key] = (now, report)
    # Drop expired entries opportunistically.
    expired = [k for k, (t, _) in _CACHE.items() if now - t >= CACHE_TTL_SECONDS]
    for k in expired:
        _CACHE.pop(k, None)
    # Enforce a hard size bound by evicting the oldest entries deterministically.
    if len(_CACHE) > CACHE_MAX_ENTRIES:
        ordered = sorted(_CACHE.items(), key=lambda kv: kv[1][0])
        for k, _ in ordered[: len(_CACHE) - CACHE_MAX_ENTRIES]:
            _CACHE.pop(k, None)


async def _cached_lookup(provider: str, domain: str, fn, *args):
    key = f"{provider}:{domain}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    report = await fn(*args)
    if report is not None:
        _cache_set(key, report)
    return report


def _urlhaus_threats(data: Dict[str, Any]) -> Tuple[str, ...]:
    """Extract normalized threats from a URLhaus /v1/host/ response."""
    threats = set()
    blacklists = data.get("blacklists") or {}
    dbl = blacklists.get("spamhaus_dbl")
    if dbl in _URLHAUS_DBL_TO_THREAT:
        threats.add(_URLHAUS_DBL_TO_THREAT[dbl])
    if blacklists.get("surbl") == "listed":
        threats.add("spam")
    # URLhaus only tracks hosts observed serving malware payloads.
    if data.get("query_status") == "ok":
        threats.add("malware")
    return tuple(sorted(threats))


async def _check_urlhaus(
    domain: str,
    key: str,
    client: Optional[httpx.AsyncClient] = None,
    outcomes: Optional[Dict[str, str]] = None,
) -> Optional[ProviderReport]:
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=REPUTATION_TIMEOUT, follow_redirects=True)
    try:
        response = await client.post(
            URLHAUS_HOST_URL,
            data={"host": domain},
            headers={"Auth-Key": key},
        )
    except httpx.TimeoutException:
        if outcomes is not None:
            outcomes["urlhaus"] = "timeout"
        return None  # unavailable
    except httpx.NetworkError:
        if outcomes is not None:
            outcomes["urlhaus"] = "unavailable"
        return None
    except Exception:
        if outcomes is not None:
            outcomes["urlhaus"] = "error"
        return None  # never raise
    finally:
        if owns_client:
            try:
                await client.aclose()
            except Exception:
                pass

    if response.status_code in (401, 403):
        if outcomes is not None:
            outcomes["urlhaus"] = "unauthorized"
        return None
    if response.status_code == 429:
        if outcomes is not None:
            outcomes["urlhaus"] = "rate_limited"
        return None
    if response.status_code >= 500:
        if outcomes is not None:
            outcomes["urlhaus"] = "unavailable"
        return None
    if response.status_code != 200:
        if outcomes is not None:
            outcomes["urlhaus"] = "unavailable"
        return None
    try:
        data = response.json()
    except Exception:
        if outcomes is not None:
            outcomes["urlhaus"] = "error"
        return None

    status = data.get("query_status")
    if status == "no_results":
        if outcomes is not None:
            outcomes["urlhaus"] = "clean"
        return ProviderReport(provider="urlhaus", threats=(), listed=False, raw=data)
    if status == "ok":
        threats = _urlhaus_threats(data)
        if outcomes is not None:
            outcomes["urlhaus"] = "listed"
        return ProviderReport(provider="urlhaus", threats=threats, listed=True, raw=data)
    if outcomes is not None:
        outcomes["urlhaus"] = "invalid"
    return None  # invalid_host / unknown -> unavailable


def _dbl_resolve(host: str) -> List[str]:
    """DNS A-record lookup. NXDOMAIN/OSError -> [] (not listed / unavailable)."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    except (socket.gaierror, OSError):
        return []
    return sorted({info[4][0] for info in infos})


async def _check_spamhaus(
    domain: str,
    key: str,
    outcomes: Optional[Dict[str, str]] = None,
) -> Optional[ProviderReport]:
    host = f"{domain}.{key}.dbl.dq.spamhaus.net"
    loop = asyncio.get_running_loop()
    try:
        addrs = await asyncio.wait_for(
            loop.run_in_executor(_DNS_EXECUTOR, _dbl_resolve, host),
            timeout=REPUTATION_TIMEOUT,
        )
    except asyncio.TimeoutError:
        if outcomes is not None:
            outcomes["spamhaus_dbl"] = "timeout"
        return None  # unavailable
    except Exception:
        if outcomes is not None:
            outcomes["spamhaus_dbl"] = "unavailable"
        return None

    listed = False
    threats = set()
    for addr in addrs:
        if not addr.startswith("127.0.1."):
            continue
        listed = True
        code = addr.rsplit(".", 1)[-1]
        if code == "255":
            if outcomes is not None:
                outcomes["spamhaus_dbl"] = "error"
            return None  # 127.0.1.255 = error (IP queries not allowed)
        threat = _DBL_CODE_TO_THREAT.get(code)
        if threat:
            threats.add(threat)

    if not listed:
        if outcomes is not None:
            outcomes["spamhaus_dbl"] = "clean"
        return ProviderReport(provider="spamhaus_dbl", threats=(), listed=False, raw={"a_records": addrs})
    if outcomes is not None:
        outcomes["spamhaus_dbl"] = "listed"
    return ProviderReport(
        provider="spamhaus_dbl", threats=tuple(sorted(threats)), listed=True,
        raw={"a_records": addrs},
    )


def aggregate_reputation(reports: List[ProviderReport]) -> List[EvidenceItem]:
    """Deduplicate threats across providers and produce reputation evidence.

    One normalized threat == one signal. Clean/not-listed reports produce no
    item. A ``reputation_verdict`` audit item is emitted only when at least one
    malicious classification exists.
    """
    threat_providers: Dict[str, set] = {}
    confirmed: set = set()
    clean: set = set()
    for report in reports:
        if report.listed:
            confirmed.add(report.provider)
            for threat in report.threats:
                threat_providers.setdefault(threat, set()).add(report.provider)
        else:
            clean.add(report.provider)

    if not threat_providers:
        return []  # clean / not-listed -> no evidence

    checked = sorted({r.provider for r in reports})
    disagreement = sorted(clean) if confirmed and clean else []

    items: List[EvidenceItem] = []
    confidences: List[float] = []
    for threat in sorted(threat_providers):
        providers = threat_providers[threat]
        source_count = len(providers)
        confidence = _CORROBORATION_CONF.get(source_count, _DEFAULT_CONF)
        confidences.append(confidence)
        items.append(
            EvidenceItem(
                id=f"REP_{threat.upper()}",
                category="reputation",
                signal=f"{threat}_hit",
                value={
                    "threat": threat,
                    "reported_by": sorted(providers),
                    "corroboration_sources": source_count,
                },
                # Raw per-signal effect; the engine applies the corroboration
                # confidence (effect * confidence) so a single source yields
                # -6, two sources -8, three or more -10.
                effect=PER_THREAT_EFFECT,
                confidence=confidence,
                source="reputation",
                explanation=(
                    f"{threat} confirmed by {source_count} provider(s): "
                    f"{', '.join(sorted(providers))}."
                ),
            )
        )

    items.append(
        EvidenceItem(
            id="REP_VERDICT",
            category="reputation",
            signal="reputation_verdict",
            value={
                "threats": sorted(threat_providers),
                "reported_by": {t: sorted(p) for t, p in threat_providers.items()},
                "providers_checked": checked,
                "disagreement": disagreement,
                "corroboration": {t: len(threat_providers[t]) for t in threat_providers},
            },
            effect=0.0,
            confidence=round(sum(confidences) / len(confidences), 2),
            source="reputation",
            explanation=(
                "Confirmed malicious classification: "
                + ", ".join(sorted(threat_providers))
                + (
                    f". Providers reporting clean: {', '.join(disagreement)}."
                    if disagreement
                    else ""
                )
            ),
        )
    )
    return items


async def collect_reputation(
    domain: str,
    client: Optional[httpx.AsyncClient] = None,
    outcomes: Optional[Dict[str, str]] = None,
) -> List[EvidenceItem]:
    """Collect reputation evidence for a domain. Never raises.

    Returns ``[]`` unless ``REPUTATION_ENABLED=true`` and at least one provider
    is configured. ``client`` is optional and only used for test injection
    (URLhaus queries). When ``outcomes`` is provided it is filled with a
    per-provider status (disabled/clean/listed/unavailable/timeout/
    rate_limited/unauthorized/invalid/error) for observability; it never
    affects scoring.
    """
    if not _reputation_enabled():
        return []

    reports: List[ProviderReport] = []

    urlhaus_key = os.getenv("URLHAUS_API_KEY", "")
    if urlhaus_key:
        report = await _cached_lookup(
            "urlhaus", domain, _check_urlhaus, domain, urlhaus_key, client, outcomes
        )
        if report is not None:
            reports.append(report)
        if outcomes is not None and "urlhaus" not in outcomes:
            # Cache hit (provider not called) -> derive from the cached report.
            outcomes["urlhaus"] = (
                "listed" if (report is not None and report.listed)
                else "clean" if report is not None
                else "unavailable"
            )
    elif outcomes is not None:
        outcomes["urlhaus"] = "disabled"

    dqs_key = os.getenv("SPAMHAUS_DQS_KEY", "")
    if dqs_key:
        report = await _cached_lookup(
            "spamhaus_dbl", domain, _check_spamhaus, domain, dqs_key, outcomes
        )
        if report is not None:
            reports.append(report)
        if outcomes is not None and "spamhaus_dbl" not in outcomes:
            outcomes["spamhaus_dbl"] = (
                "listed" if (report is not None and report.listed)
                else "clean" if report is not None
                else "unavailable"
            )
    elif outcomes is not None:
        outcomes["spamhaus_dbl"] = "disabled"

    return aggregate_reputation(reports)
