import asyncio
import os
import re
from pathlib import Path
from unittest import mock

import httpx
import pytest

from app.models.evidence import EvidenceItem
from app.services.collectors import reputation as rep
from app.services.collectors.reputation import ProviderReport, aggregate_reputation, collect_reputation
from app.services.scoring import CATEGORY_CAPS, evaluate_evidence


@pytest.fixture(autouse=True)
def _clean_env_and_cache():
    rep._CACHE.clear()
    saved = {
        key: os.environ.get(key)
        for key in ("REPUTATION_ENABLED", "URLHAUS_API_KEY", "SPAMHAUS_DQS_KEY")
    }
    for key in saved:
        os.environ.pop(key, None)
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    rep._CACHE.clear()


def _urlhaus_ok(**overrides):
    data = {
        "query_status": "ok",
        "host": "example.com",
        "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
    }
    data.update(overrides)
    return httpx.Response(200, json=data)


async def _run(domain="example.com", handler=None, resolve=None):
    kwargs = {}
    if handler is not None:
        transport = httpx.MockTransport(handler)
        kwargs["client"] = httpx.AsyncClient(transport=transport, timeout=5.0)
    with mock.patch.object(rep, "_dbl_resolve", return_value=resolve or []):
        try:
            return await collect_reputation(domain, **kwargs)
        finally:
            if "client" in kwargs:
                await kwargs["client"].aclose()


# ---------- Feature gate / keys ----------

def test_feature_disabled_returns_empty_even_with_keys():
    os.environ["URLHAUS_API_KEY"] = "test-key"
    os.environ["SPAMHAUS_DQS_KEY"] = "test-key"
    # REPUTATION_ENABLED unset -> default false
    assert asyncio.run(collect_reputation("example.com")) == []


def test_no_keys_both_providers_unavailable():
    os.environ["REPUTATION_ENABLED"] = "true"
    assert asyncio.run(collect_reputation("example.com")) == []


def test_missing_urlhaus_key_skips_urlhaus():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["SPAMHAUS_DQS_KEY"] = "test-key"
    with mock.patch.object(rep, "_dbl_resolve", return_value=["127.0.1.4"]):
        items = asyncio.run(collect_reputation("example.com"))
    signals = {i.signal for i in items}
    assert "phishing_hit" in signals
    verdict = next(i for i in items if i.signal == "reputation_verdict")
    assert verdict.value["providers_checked"] == ["spamhaus_dbl"]


def test_missing_spamhaus_key_skips_spamhaus():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"
    with mock.patch.object(rep, "_dbl_resolve") as dbl:
        items = asyncio.run(
            _run(
                handler=lambda req: httpx.Response(
                    200, json={"query_status": "no_results"}
                )
            )
        )
    dbl.assert_not_called()
    assert items == []


# ---------- URLhaus provider ----------

def test_urlhaus_clean_no_evidence():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"
    items = asyncio.run(
        _run(handler=lambda req: httpx.Response(200, json={"query_status": "no_results"}))
    )
    assert items == []


def test_urlhaus_malicious_single_source():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"

    def handler(req):
        assert req.headers["Auth-Key"] == "test-key"
        return _urlhaus_ok(
            blacklists={"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"}
        )

    items = asyncio.run(_run(handler=handler))
    assert any(i.signal == "malware_hit" for i in items)
    assert any(i.signal == "reputation_verdict" for i in items)
    # Single source -> engine applies confidence 0.6 to the raw -10.
    assert evaluate_evidence(items).category_contributions["reputation"] == -6.0


def test_urlhaus_401_unavailable():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"
    items = asyncio.run(_run(handler=lambda req: httpx.Response(401, text="{}")))
    assert items == []


def test_urlhaus_403_unavailable():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"
    items = asyncio.run(_run(handler=lambda req: httpx.Response(403, text="{}")))
    assert items == []


def test_urlhaus_rate_limit_429_unavailable():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"
    items = asyncio.run(_run(handler=lambda req: httpx.Response(429, text="{}")))
    assert items == []


def test_urlhaus_timeout_unavailable():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"

    def handler(req):
        raise httpx.ReadTimeout("timed out", request=req)

    assert asyncio.run(_run(handler=handler)) == []


def test_urlhaus_network_failure_unavailable():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"

    def handler(req):
        raise httpx.ConnectError("refused", request=req)

    assert asyncio.run(_run(handler=handler)) == []


# ---------- Spamhaus provider ----------

def test_spamhaus_malicious():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["SPAMHAUS_DQS_KEY"] = "test-key"
    items = asyncio.run(_run(resolve=["127.0.1.4"]))
    assert any(i.signal == "phishing_hit" for i in items)
    assert evaluate_evidence(items).category_contributions["reputation"] == -6.0


def test_spamhaus_clean():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["SPAMHAUS_DQS_KEY"] = "test-key"
    assert asyncio.run(_run(resolve=[])) == []


def test_spamhaus_dns_failure_unavailable():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["SPAMHAUS_DQS_KEY"] = "test-key"
    with mock.patch.object(rep, "_dbl_resolve", side_effect=OSError("dns boom")):
        items = asyncio.run(collect_reputation("example.com"))
    assert items == []


def test_spamhaus_error_code_unavailable():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["SPAMHAUS_DQS_KEY"] = "test-key"
    items = asyncio.run(_run(resolve=["127.0.1.255"]))  # 255 = query error
    assert items == []


# ---------- Pure aggregation ----------

def test_clean_reports_no_evidence():
    reports = [ProviderReport(provider="urlhaus", threats=(), listed=False, raw={})]
    assert aggregate_reputation(reports) == []


def test_single_provider_single_threat():
    reports = [ProviderReport(provider="urlhaus", threats=("malware",), listed=True, raw={})]
    items = aggregate_reputation(reports)
    malware = next(i for i in items if i.signal == "malware_hit")
    assert malware.effect == -10.0  # raw; engine scales by confidence
    assert malware.confidence == 0.6
    assert any(i.signal == "reputation_verdict" for i in items)
    assert evaluate_evidence(items).category_contributions["reputation"] == -6.0


def test_duplicate_threat_two_providers_single_signal():
    reports = [
        ProviderReport(provider="urlhaus", threats=("malware",), listed=True, raw={}),
        ProviderReport(provider="spamhaus_dbl", threats=("malware",), listed=True, raw={}),
    ]
    items = aggregate_reputation(reports)
    malware = [i for i in items if i.signal == "malware_hit"]
    assert len(malware) == 1  # not one penalty per provider
    assert malware[0].effect == -10.0
    assert malware[0].confidence == 0.8
    assert evaluate_evidence(items).category_contributions["reputation"] == -8.0


def test_three_provider_corroboration():
    reports = [
        ProviderReport(provider=f"provider{i}", threats=("c2",), listed=True, raw={})
        for i in range(3)
    ]
    items = aggregate_reputation(reports)
    c2 = next(i for i in items if i.signal == "c2_hit")
    assert c2.effect == -10.0
    assert c2.confidence == 1.0


def test_multiple_different_threats_separate_signals():
    reports = [
        ProviderReport(provider="urlhaus", threats=("malware", "phishing"), listed=True, raw={}),
        ProviderReport(provider="spamhaus_dbl", threats=("c2",), listed=True, raw={}),
    ]
    items = aggregate_reputation(reports)
    signals = {i.signal for i in items if i.signal != "reputation_verdict"}
    assert signals == {"malware_hit", "phishing_hit", "c2_hit"}


def test_provider_disagreement_is_transparent():
    reports = [
        ProviderReport(provider="urlhaus", threats=("malware",), listed=True, raw={}),
        ProviderReport(provider="spamhaus_dbl", threats=(), listed=False, raw={}),
    ]
    items = aggregate_reputation(reports)
    verdict = next(i for i in items if i.signal == "reputation_verdict")
    assert verdict.value["disagreement"] == ["spamhaus_dbl"]
    assert "malware_hit" in {i.signal for i in items}


def test_verdict_attribution_preserved():
    reports = [
        ProviderReport(provider="urlhaus", threats=("phishing",), listed=True, raw={}),
        ProviderReport(provider="spamhaus_dbl", threats=("phishing",), listed=True, raw={}),
    ]
    items = aggregate_reputation(reports)
    verdict = next(i for i in items if i.signal == "reputation_verdict")
    assert verdict.value["reported_by"]["phishing"] == ["spamhaus_dbl", "urlhaus"]
    assert verdict.value["providers_checked"] == ["spamhaus_dbl", "urlhaus"]


# ---------- Cache ----------

def test_cache_reduces_provider_queries():
    os.environ["REPUTATION_ENABLED"] = "true"
    os.environ["URLHAUS_API_KEY"] = "test-key"
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return _urlhaus_ok(blacklists={"spamhaus_dbl": "not listed", "surbl": "not listed"})

    async def run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
            first = await collect_reputation("example.com", client=client)
            second = await collect_reputation("example.com", client=client)
            return first, second

    first, second = asyncio.run(run())
    assert calls["n"] == 1  # second call served from the in-process cache
    assert first == second


# ---------- Scoring integration ----------

def test_reputation_cap_15():
    reports = [
        ProviderReport(provider="urlhaus", threats=("malware", "phishing", "c2"), listed=True, raw={}),
    ]
    items = aggregate_reputation(reports)  # 3 x -6 = -18 raw
    result = evaluate_evidence(items)
    assert CATEGORY_CAPS["reputation"] == 15.0
    assert result.category_contributions["reputation"] == -15.0  # capped
    assert any("cap" in n and "reputation" in n for n in result.notes)


def test_score_reconciliation_with_reputation():
    reports = [ProviderReport(provider="urlhaus", threats=("malware",), listed=True, raw={})]
    items = aggregate_reputation(reports)
    result = evaluate_evidence(items)
    assert result.score == round(50.0 + sum(result.category_contributions.values()), 2)


def test_negative_reputation_never_increases_score():
    base = [
        EvidenceItem(id="SSL", category="ssl", signal="ssl_valid", value="TLSv1.3",
                     effect=6.0, confidence=1.0, source="tls"),
    ]
    base_score = evaluate_evidence(base).score
    rep_items = aggregate_reputation(
        [ProviderReport(provider="urlhaus", threats=("malware",), listed=True, raw={})]
    )
    assert evaluate_evidence(base + rep_items).score <= base_score


def test_confidence_rises_with_reputation_finding():
    base = [
        EvidenceItem(id="SSL", category="ssl", signal="ssl_valid", value="TLSv1.3",
                     effect=6.0, confidence=1.0, source="tls"),
        EvidenceItem(id="HTTP", category="http", signal="https_ok", value=200,
                     effect=2.0, confidence=1.0, source="http"),
    ]
    base_conf = evaluate_evidence(base).confidence
    rep_items = aggregate_reputation(
        [ProviderReport(provider="urlhaus", threats=("malware",), listed=True, raw={})]
    )
    assert evaluate_evidence(base + rep_items).confidence > base_conf


def test_clean_reputation_does_not_change_breadth_or_confidence():
    base = [
        EvidenceItem(id="SSL", category="ssl", signal="ssl_valid", value="TLSv1.3",
                     effect=6.0, confidence=1.0, source="tls"),
        EvidenceItem(id="HTTP", category="http", signal="https_ok", value=200,
                     effect=2.0, confidence=1.0, source="http"),
    ]
    clean = aggregate_reputation(
        [ProviderReport(provider="urlhaus", threats=(), listed=False, raw={})]
    )
    assert clean == []  # clean check -> no evidence, not usable
    assert "reputation" not in evaluate_evidence(base).category_contributions


# ---------- No credentials in source ----------

def test_no_hardcoded_credentials_in_source():
    src = Path(rep.__file__).read_text(encoding="utf-8")
    assert 'os.getenv("URLHAUS_API_KEY"' in src
    assert 'os.getenv("SPAMHAUS_DQS_KEY"' in src
    assert "REPUTATION_ENABLED" in src
    for line in src.splitlines():
        stripped = line.strip()
        if not stripped or "os.getenv" in stripped or "=" not in stripped:
            continue
        if re.search(r'=\s*"[A-Za-z0-9_\-]{24,}"', stripped):
            raise AssertionError(f"suspicious literal token: {line}")
