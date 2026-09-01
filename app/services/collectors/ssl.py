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
import socket
import ssl
from typing import Any, Dict, List, Optional

from app.models.evidence import EvidenceItem

TLS_TIMEOUT = 8.0
TLS_PORT = 443


def _tls_handshake(domain: str, context: ssl.SSLContext):
    with socket.create_connection((domain, TLS_PORT), timeout=TLS_TIMEOUT) as sock:
        return context.wrap_socket(sock, server_hostname=domain)


def _collect_tls_sync(domain: str) -> List[EvidenceItem]:
    try:
        context = ssl.create_default_context()  # verifies against system CAs
        with _tls_handshake(domain, context) as tls:
            version = tls.version()
            cert = tls.getpeercert()
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


async def collect_tls(domain: str) -> List[EvidenceItem]:
    """Collect TLS evidence for a hostname. Never raises."""
    return await asyncio.to_thread(_collect_tls_sync, domain)
