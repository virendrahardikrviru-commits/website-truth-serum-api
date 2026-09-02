"""TLS/SSL evidence collector (Phase 2b, calibrated Phase 2c-4).

Performs a real HTTPS handshake with certificate verification enabled
(Python's ``ssl`` with the default context — verification is never disabled)
and emits evidence only for what was actually measured:

- Valid certificate/handshake -> ``+6`` (``ssl_valid``). This rewards the
  *transport security* property specifically: that the site presents a valid,
  verified certificate chain. It is distinct from the HTTP behavior signal
  (``https_ok``, ``+2``) which rewards successful HTTPS *reachability*.
- Certificate verification or handshake failure -> ``-10`` (``ssl_error``).
- A valid certificate that expires within 30 days -> ``-2`` (``ssl_expiry``);
  expiry is a real but small availability risk, never as severe as a failed
  or missing verification. Missing/unparseable expiry is neutral.
- Timeout / network / provider failure -> no evidence (effect 0, no penalty).

Raw facts such as the negotiated TLS version and the certificate issuer are
captured in the evidence ``value`` but are NOT scored.
"""

import asyncio
import concurrent.futures
import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

from app.models.evidence import EvidenceItem
from app.services.network_security import NonPublicDestinationError, resolve_and_pin

TLS_TIMEOUT = 8.0
TLS_PORT = 443

# A valid certificate within this many days of expiry earns the small -2
# ``ssl_expiry`` signal.
SSL_EXPIRY_DAYS = 30.0

# Bounded worker pool for the blocking TLS handshake so sustained concurrent
# scans cannot exhaust the default executor or drift unbounded threads.
_TLS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="wts-tls"
)


def _tls_handshake(domain: str, context: ssl.SSLContext):
    # Resolve once, validate fail-closed, and connect to the pinned public IP.
    # The hostname is preserved for SNI / certificate verification; it is never
    # re-resolved by the connect path (closes DNS-rebinding TOCTOU).
    ip = resolve_and_pin(domain, TLS_PORT)
    with socket.create_connection((ip, TLS_PORT), timeout=TLS_TIMEOUT) as sock:
        return context.wrap_socket(sock, server_hostname=domain)


def _now_utc() -> datetime:
    """UTC clock; monkeypatched by tests for deterministic expiry checks."""
    return datetime.now(timezone.utc)


def _parse_not_after(value: Any) -> Optional[datetime]:
    """Parse a certificate ``notAfter`` (the ``asctime``-style string returned
    by ``getpeercert()``, an ISO string, or a naive ``datetime``) into a
    timezone-aware UTC ``datetime``. Returns ``None`` for missing/unparseable
    values so callers can treat them as neutral."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    for candidate in (text, text.replace("  ", " ")):
        try:
            parsed = parsedate_to_datetime(candidate)
        except (TypeError, ValueError, IndexError, OverflowError):
            parsed = None
        if parsed is not None:
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def days_until_expiry(
    cert: Dict[str, Any], now: Optional[datetime] = None
) -> Optional[float]:
    """Whole-days-until-expiry for a ``getpeercert()`` dict, or ``None`` when
    no parseable ``notAfter`` exists. ``now`` is injected by tests; it
    defaults to the UTC clock."""
    if not isinstance(cert, dict):
        return None
    expiry = _parse_not_after(cert.get("notAfter"))
    if expiry is None:
        return None
    now = now or _now_utc()
    return (expiry - now).total_seconds() / 86400.0


def _expiry_evidence(cert: Dict[str, Any]) -> List[EvidenceItem]:
    """Emit the small ``ssl_expiry`` signal only for a *valid* certificate
    whose parsed ``notAfter`` is within ``SSL_EXPIRY_DAYS``. Already-expired
    values are not emitted here (a genuinely expired chain would have failed
    verification and taken the ``ssl_error`` path)."""
    days_left = days_until_expiry(cert)
    if days_left is None or not (0.0 <= days_left <= SSL_EXPIRY_DAYS):
        return []
    not_after = cert.get("notAfter")
    return [
        EvidenceItem(
            id="TLS_EXP",
            category="ssl",
            signal="ssl_expiry",
            value={
                "not_after": not_after,
                "days_remaining": round(days_left, 1),
            },
            effect=-2.0,
            confidence=1.0,
            source="tls",
            explanation=(
                f"Valid TLS certificate expires soon "
                f"({round(days_left)} day{'s' if days_left != 1 else ''} "
                f"remaining)."
            ),
        )
    ]


def _collect_tls_sync(domain: str, outcomes: Optional[Dict[str, str]] = None) -> List[EvidenceItem]:
    try:
        context = ssl.create_default_context()  # verifies against system CAs
        with _tls_handshake(domain, context) as tls:
            version = tls.version()
            cert = tls.getpeercert()
    except NonPublicDestinationError as exc:
        # SSRF/DNS boundary rejection: unavailable/neutral, never a penalty.
        if outcomes is not None:
            outcomes["tls"] = exc.reason
        return []
    except ssl.SSLCertVerificationError as exc:
        return [
            EvidenceItem(
                id="TLS_ERR",
                category="ssl",
                signal="ssl_error",
                value=str(exc),
                effect=-10.0,
                confidence=1.0,
                source="tls",
                explanation="TLS certificate verification failed during the connection handshake.",
            )
        ]
    except ssl.SSLError:
        return [
            EvidenceItem(
                id="TLS_ERR",
                category="ssl",
                signal="ssl_error",
                value=None,
                effect=-10.0,
                confidence=1.0,
                source="tls",
                explanation="TLS handshake failed during the connection attempt.",
            )
        ]
    except (socket.timeout, TimeoutError):
        return []  # unavailable, no penalty
    except OSError:
        return []  # connection/DNS unavailable, no penalty
    except Exception:
        return []  # never raise out of the collector boundary

    return [
        EvidenceItem(
            id="TLS_001",
            category="ssl",
            signal="ssl_valid",
            value={
                "tls_version": version,
                "cert_not_after": cert.get("notAfter"),
                "issuer": cert.get("issuer"),
            },
            effect=6.0,
            confidence=1.0,
            source="tls",
            explanation=f"Valid TLS certificate; connection negotiated {version}.",
        )
    ] + _expiry_evidence(cert)


async def collect_tls(
    domain: str, outcomes: Optional[Dict[str, str]] = None
) -> List[EvidenceItem]:
    """Collect TLS evidence for a hostname. Never raises.

    The blocking handshake runs on a bounded worker pool so the event loop is
    never blocked and concurrent scans cannot exhaust the executor. When the
    destination is rejected by the network security policy, ``[]`` is returned
    (unavailable/neutral) and ``outcomes["tls"]`` records the boundary reason.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _TLS_EXECUTOR, _collect_tls_sync, domain, outcomes
    )
