"""V1-H3 — Shared network security policy and rate limiter tests.

All DNS is mocked; no live DNS is required.
"""

import socket
import threading
from unittest import mock

import pytest

from app.services.network_security import (
    NonPublicDestinationError,
    is_public_ip,
    resolve_and_pin,
)
from app.services.rate_limit import SlidingWindowRateLimiter

# ---------------------------------------------------------------- IP matrix

# (ip, expected_public) — the full rejection matrix from the V1-H3 spec plus
# positive controls.
IP_MATRIX = [
    # IPv4 rejection
    ("127.0.0.1", False),
    ("10.0.0.1", False),
    ("172.16.0.1", False),
    ("192.168.1.1", False),
    ("169.254.169.254", False),
    ("100.64.0.1", False),
    ("0.0.0.0", False),
    ("224.0.0.1", False),  # multicast
    ("240.0.0.1", False),  # reserved
    ("255.255.255.255", False),
    ("192.0.0.1", False),  # IETF protocol assignment
    ("198.51.100.1", False),  # documentation
    ("203.0.113.1", False),  # documentation
    # IPv6 rejection
    ("::1", False),
    ("::", False),
    ("fe80::1", False),  # link-local
    ("fc00::1", False),  # ULA / private
    ("ff02::1", False),  # multicast
    ("2001:db8::1", False),  # documentation
    # IPv4-mapped internal
    ("::ffff:127.0.0.1", False),
    ("::ffff:10.0.0.1", False),
    ("::ffff:169.254.169.254", False),
    # positive controls
    ("8.8.8.8", True),
    ("1.1.1.1", True),
    ("172.32.0.1", True),
    ("11.0.0.1", True),
    ("2606:4700::1111", True),
    ("::ffff:8.8.8.8", True),  # IPv4-mapped public
]


@pytest.mark.parametrize("ip,expected", IP_MATRIX)
def test_is_public_ip(ip, expected):
    assert is_public_ip(ip) is expected, ip


def test_is_public_ip_invalid_string():
    assert is_public_ip("not-an-ip") is False
    assert is_public_ip("") is False
    assert is_public_ip("1.2.3.4.5") is False


# ------------------------------------------------------ resolve → validate → pin

def _mock_getaddrinfo(monkeypatch, mapping):
    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        addrs = mapping[host]
        infos = []
        for ip in addrs:
            if ":" in ip:
                infos.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, port, 0, 0)))
            else:
                infos.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)))
        return infos

    monkeypatch.setattr("app.services.network_security.socket.getaddrinfo", fake_getaddrinfo)


def test_resolve_and_pin_public_host_allowed(monkeypatch):
    _mock_getaddrinfo(monkeypatch, {"safe.example": ["93.184.216.34", "2606:2800:220:1::248:1893"]})
    ip = resolve_and_pin("safe.example", 443)
    assert ip in ("93.184.216.34", "2606:2800:220:1::248:1893")


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1",
                                    "169.254.169.254", "::1", "fe80::1", "fc00::1"])
def test_resolve_and_pin_private_ip_rejected(monkeypatch, target):
    _mock_getaddrinfo(monkeypatch, {"evil.example": [target]})
    with pytest.raises(NonPublicDestinationError) as exc:
        resolve_and_pin("evil.example", 443)
    assert exc.value.reason == "private_ip_rejected"


def test_resolve_and_pin_mixed_public_private_rejected_fail_closed(monkeypatch):
    # One public + one private address -> the hostname must be rejected.
    _mock_getaddrinfo(monkeypatch, {"evil.example": ["8.8.8.8", "10.0.0.1"]})
    with pytest.raises(NonPublicDestinationError) as exc:
        resolve_and_pin("evil.example", 443)
    assert exc.value.reason == "private_ip_rejected"


def test_resolve_and_pin_dns_failure_rejected(monkeypatch):
    def boom(host, port, family=0, type=0, proto=0, flags=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr("app.services.network_security.socket.getaddrinfo", boom)
    with pytest.raises(NonPublicDestinationError) as exc:
        resolve_and_pin("doesnotexist.example", 443)
    assert exc.value.reason == "dns_failed"


def test_resolve_and_pin_ip_literal():
    assert resolve_and_pin("8.8.8.8", 443) == "8.8.8.8"
    with pytest.raises(NonPublicDestinationError):
        resolve_and_pin("127.0.0.1", 443)
    with pytest.raises(NonPublicDestinationError):
        resolve_and_pin("169.254.169.254", 443)


def test_resolve_and_pin_no_addresses_rejected(monkeypatch):
    _mock_getaddrinfo(monkeypatch, {"empty.example": []})
    with pytest.raises(NonPublicDestinationError) as exc:
        resolve_and_pin("empty.example", 443)
    assert exc.value.reason == "dns_failed"


# ------------------------------------------------- DNS rebinding / pinning

def test_page_fetch_client_uses_pinned_transport_by_default():
    """The production default fetch client must use the pinned transport.

    This guards the dependency contract: if httpx/httpcore upgrade and the
    PinnedAsyncHTTPTransport becomes inert, this test fails loudly instead of
    silently re-opening the DNS-resolution SSRF boundary."""
    import asyncio

    from app.routers import analyze as analyze_module
    from app.services.network_security import PinnedAsyncHTTPTransport

    with mock.patch("app.routers.analyze._page_fetch_transport", None):
        client = analyze_module._new_fetch_client(5.0)
    try:
        assert isinstance(client._transport, PinnedAsyncHTTPTransport)
    finally:
        asyncio.run(client.aclose())


def test_backend_pins_validated_ip_and_never_re_resolves():
    """The connection target is the validated public IP literal, and the
    hostname is resolved exactly once. A rebinding DNS (public -> private on a
    second answer) cannot change the connection target because the connect
    path never re-resolves the hostname."""
    import asyncio

    from app.services.network_security import PinnedAsyncNetworkBackend

    calls = {"n": 0}

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        calls["n"] += 1
        # First resolution -> public; any later resolution -> private (rebind).
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ] if calls["n"] == 1 else [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port))
        ]

    connected = {}

    async def fake_anyio_connect_tcp(remote_host, remote_port, local_host=None, **kwargs):
        connected["host"] = remote_host
        connected["port"] = remote_port
        raise RuntimeError("stop-after-connect")

    backend = PinnedAsyncNetworkBackend()
    with mock.patch(
        "app.services.network_security.socket.getaddrinfo", fake_getaddrinfo
    ), mock.patch(
        "httpcore._backends.anyio.anyio.connect_tcp", fake_anyio_connect_tcp
    ):
        try:
            asyncio.run(backend.connect_tcp("evil.example", 443))
        except RuntimeError:
            pass

    assert connected["host"] == "93.184.216.34"  # pinned validated IP, not the hostname
    assert connected["port"] == 443
    assert calls["n"] == 1  # resolved exactly once; no re-resolution on connect


# ------------------------------------------------------------- rate limiter

def _clock_sequence(values):
    state = {"i": 0}

    def clock():
        v = values[min(state["i"], len(values) - 1)]
        state["i"] += 1
        return v

    return clock


def test_rate_limiter_under_limit_succeeds():
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is True


def test_rate_limiter_over_limit_rejected():
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False


def test_rate_limiter_window_expiry_allows_again():
    clock = _clock_sequence([0.0, 0.1, 0.2, 61.0])
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60, clock=clock)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    assert limiter.allow("a") is True  # window slid past the old timestamps


def test_rate_limiter_keys_are_independent():
    limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=60)
    assert limiter.allow("ip1") is True
    assert limiter.allow("ip1") is False
    assert limiter.allow("ip2") is True  # different key unaffected


def test_rate_limiter_memory_is_bounded():
    limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=60, max_keys=5)
    for i in range(100):
        limiter.allow(f"key-{i}")
    assert limiter.size() <= 5


def test_rate_limiter_concurrent_access_is_safe():
    limiter = SlidingWindowRateLimiter(max_requests=1000, window_seconds=60, max_keys=20)
    errors = []

    def worker(n):
        try:
            for i in range(200):
                limiter.allow(f"k{(n + i) % 20}")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert limiter.size() <= 20
