"""TLS/SSL evidence collector (Phase 2b, calibrated Phase 2c-4).

Performs a real HTTPS handshake with certificate verification enabled
(Python's ``ssl`` with the default context — verification is never disabled)
and emits evidence only for what was actually measured:

- Valid certificate/handshake -> ``+6`` (``ssl_valid``). This rewards the
  *transport security* property specifically: that the site presents a valid,
  verified certificate chain. It is distinct from the HTTP behavior signal
  (``https_ok``, ``+2``) which rewards successful HTTPS *reachability*.
- Certificate verification or handshake failure -> ``-10`` (``ssl_error``).
- Timeout / network / provider failure -> no evidence (effect 0, no penalty).

Raw facts such as the negotiated TLS version and certificate expiry are
captured in the evidence ``value`` but are NOT scored.
"""

import asyncio
import concurrent.futures
import socket
import ssl
from typing import Any, Dict, List, Optional

from app.models.evidence import EvidenceItem
from app.services.network_security import NonPublicDestinationError, resolve_and_pin

TLS_TIMEOUT = 8.0
TLS_PORT = 443

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
    ]


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
