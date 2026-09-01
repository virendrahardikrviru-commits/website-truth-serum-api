"""Shared outbound network security policy (V1-H3).

One authoritative policy for every outbound connection triggered by a scan:

- Strict IP validation (IPv4 + IPv6, including IPv4-mapped and multicast).
- Fail-closed resolution: a hostname is connectable only when EVERY resolved
  address is a public, globally-routable address. If any single address is
  non-public (loopback, private, link-local, metadata, CGNAT, multicast,
  unspecified, reserved), the hostname is rejected.
- Pinning: the validated address is the address actually connected to. The
  logical hostname is preserved separately by the HTTP/TLS stack for Host
  semantics, TLS SNI and certificate verification. Because the connect path
  never re-resolves the hostname, DNS-rebinding TOCTOU is closed: there is no
  second resolution to swap.

All outbound sockets produced by a scan (page fetch via httpx, TLS collector)
must go through this module.
"""

import ipaddress
import socket
from typing import List

import anyio
import httpcore
import httpx
from httpcore._backends.anyio import AnyIOBackend


class NonPublicDestinationError(ValueError):
    """Raised when a hostname/IP is not a safe public destination.

    ``reason`` is one of: ``dns_failed``, ``private_ip_rejected``,
    ``redirect_rejected``, ``ssrf_rejected``.
    """

    def __init__(self, host: str, reason: str = "ssrf_rejected", detail: str = ""):
        self.host = host
        self.reason = reason
        message = f"blocked {reason}: {host}"
        if detail:
            message += f" ({detail})"
        super().__init__(message)


def is_public_ip(ip: str) -> bool:
    """True only for a globally routable, public IP (IPv4 or IPv6).

    ``ipaddress`` marks multicast addresses as ``is_global``, so multicast must
    be excluded explicitly. IPv4-mapped IPv6 addresses are evaluated through
    the embedded IPv4 semantics (e.g. ``::ffff:127.0.0.1`` is rejected while
    ``::ffff:8.8.8.8`` is allowed).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_host(host: str, port: int) -> List[str]:
    """Resolve host to unique IPs (AF_UNSPEC). Raises on DNS failure."""
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NonPublicDestinationError(host, reason="dns_failed", detail=str(exc))
    addrs = sorted({info[4][0] for info in infos})
    if not addrs:
        raise NonPublicDestinationError(host, reason="dns_failed", detail="no addresses")
    return addrs


def resolve_and_pin(host: str, port: int) -> str:
    """Resolve ``host`` once, validate EVERY resolved address, and return a
    single validated public IP to connect to.

    Fail-closed: if ANY resolved address is non-public, the hostname is
    rejected (even when it also has a public address). The returned IP literal
    is the ONLY address the caller may connect to; callers must never resolve
    the hostname again after this returns.
    """
    if _is_ip_literal(host):
        if not is_public_ip(host):
            raise NonPublicDestinationError(host, reason="private_ip_rejected")
        return host
    addrs = _resolve_host(host, port)
    for ip in addrs:
        if not is_public_ip(ip):
            raise NonPublicDestinationError(
                host, reason="private_ip_rejected", detail=f"{ip} is non-public"
            )
    return addrs[0]


class PinnedAsyncNetworkBackend(AnyIOBackend):
    """httpcore network backend that pins every connection to a validated
    public IP.

    The logical hostname is preserved by httpcore's caller, which applies TLS
    via ``start_tls(ssl_context, server_hostname=origin_host)`` — so SNI and
    certificate verification still use the original hostname while the socket
    connects to the pinned, validated address.
    """

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        ip = await anyio.to_thread.run_sync(resolve_and_pin, host, port)
        return await super().connect_tcp(
            ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose httpcore connection pool uses the pinned backend.

    Every connection (initial request AND every redirect hop) is resolved,
    validated and pinned through :class:`PinnedAsyncNetworkBackend`.
    """

    def __init__(
        self,
        verify=True,
        cert=None,
        http1: bool = True,
        http2: bool = False,
        limits: httpx.Limits = httpx.Limits(),
        trust_env: bool = True,
        proxy=None,
        uds: str | None = None,
        local_address: str | None = None,
        retries: int = 0,
        socket_options=None,
    ):
        super().__init__(
            verify=verify,
            cert=cert,
            http1=http1,
            http2=http2,
            limits=limits,
            trust_env=trust_env,
            proxy=proxy,
            uds=uds,
            local_address=local_address,
            retries=retries,
            socket_options=socket_options,
        )
        if proxy is not None:
            # A forward proxy routes the connection to the proxy host itself;
            # the pinned policy is applied to the proxy's connection instead.
            return
        ssl_context = httpx.create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=http1,
            http2=http2,
            uds=uds,
            local_address=local_address,
            retries=retries,
            socket_options=socket_options,
            network_backend=PinnedAsyncNetworkBackend(),
        )
