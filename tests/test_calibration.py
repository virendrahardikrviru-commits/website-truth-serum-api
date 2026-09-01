"""Phase 2c-3 — Evidence scoring calibration review.

Synthetic, deterministic calibration fixtures and invariants for the
evidence engine. No live websites are required. Verifies the matrix
(unavailable / strong / ordinary / problematic / mixed / dominance),
monotonicity, and exact score reconciliation.
"""

import httpx

from app.models.evidence import EvidenceItem
from app.services.collectors.content import analyze_page_content
from app.services.collectors.security_headers import _analyze_headers
from app.services.evidence import rdap_evidence_items
from app.services.scoring import (
    BASE_SCORE,
    CATEGORY_CAPS,
    evaluate_evidence,
)

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}

BODY = (
    "This is a substantial paragraph with enough words to exceed the minimum "
    "threshold for meaningful text content on a page. " * 8
)

RICH = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="A test page with real content.">
<link rel="canonical" href="https://example.com/">
<title>Example Page</title>
</head>
<body>
<h1>Welcome</h1>
<p>{BODY}</p>
<img src="x.png" alt="An example image">
</body>
</html>"""

NO_TITLE = f"<html><head></head><body><p>{BODY}</p></body></html>"


# ---------- Signal builders (synthetic, deterministic) ----------

def _item(category, signal, effect, value=None, explanation="Observed signal."):
    return EvidenceItem(
        id=f"{category.upper()}_{signal}", category=category, signal=signal,
        value=value, effect=effect, confidence=1.0,
        source="test", explanation=explanation,
    )


def tls_valid():
    return _item("ssl", "ssl_valid", 6.0, "TLSv1.3", "Valid TLS certificate.")


def tls_error():
    return _item("ssl", "ssl_error", -10.0, None, "TLS certificate verification failed.")


def http_https():
    return _item("http", "https_ok", 2.0, {"status_code": 200}, "HTTPS endpoint responded.")


def http_upgrade():
    return _item("http", "http_to_https", 2.0, True, "HTTP redirects to HTTPS.")


def http_loop():
    return _item("http", "redirect_loop", -3.0, None, "Redirect loop detected.")


def content_positive():
    return _item("content", "title_present", 1.0, "T", "The page has a title.")


def content_negative():
    return _item("content", "no_title", -1.0, None, "Substantial page without a title.")


def rdap_old():
    return rdap_evidence_items({"source": "rdap", "domain_age_days": 4000, "status": []})


def rdap_mid():
    return rdap_evidence_items({"source": "rdap", "domain_age_days": 500, "status": []})


def rdap_young():
    return rdap_evidence_items({"source": "rdap", "domain_age_days": 10, "status": []})


def rdap_old_hold():
    return rdap_evidence_items(
        {"source": "rdap", "domain_age_days": 4000, "status": ["clientHold"]}
    )


# ---------- Reconciliation / invariant helper ----------

def assert_reconciliation(items, expected_contribs, expected_score, expected_conf):
    result = evaluate_evidence(items)
    assert result.category_contributions == expected_contribs
    assert result.score == round(
        max(0.0, min(100.0, BASE_SCORE + sum(expected_contribs.values()))), 2
    )
    assert result.score == expected_score
    assert result.confidence == expected_conf
    # Each contribution respects its category cap.
    for category, delta in result.category_contributions.items():
        assert abs(delta) <= CATEGORY_CAPS[category] + 1e-9
    # Confidence always within [0, 1].
    assert 0.0 <= result.confidence <= 1.0
    # Evidence items are preserved verbatim (effects are not mutated).
    assert [i.effect for i in result.applied_evidence] == [i.effect for i in items]
    return result


# ---------- TASK 2: Calibration matrix ----------

def test_matrix_A_completely_unavailable():
    result = evaluate_evidence([])
    assert result.score == 50.0
    assert result.confidence == 0.0
    assert result.negative_signals == [] and result.positive_signals == []
    assert result.applied_evidence == []
    assert result.category_contributions == {}
    assert "No usable evidence" in result.notes[0]


def test_matrix_B_strong_legitimate_site():
    items = (
        rdap_old()
        + [tls_valid(), http_https(), http_upgrade()]
        + _analyze_headers(httpx.Headers(GOOD_HEADERS))
        + analyze_page_content(RICH)
    )
    result = assert_reconciliation(
        items,
        expected_contribs={"domain": 5.0, "ssl": 6.0, "http": 4.0,
                           "security_headers": 5.0, "content": 4.0},
        expected_score=74.0,
        expected_conf=0.65,  # 5 of 11 planned categories usable
    )
    assert result.negative_signals == []
    assert len(result.positive_signals) > 0  # per-signal positive summaries


def test_matrix_C_ordinary_site_incomplete_metadata():
    items = (
        rdap_mid()
        + [tls_valid(), http_https()]
        + _analyze_headers(httpx.Headers({
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        }))
        + analyze_page_content(f"<html><head><title>Only Title</title></head><body><p>{BODY}</p></body></html>")
    )
    result = assert_reconciliation(
        items,
        expected_contribs={"domain": 0.0, "ssl": 6.0, "http": 2.0,
                           "security_headers": 2.0, "content": 1.0},
        expected_score=61.0,
        expected_conf=0.65,
    )
    # Missing optional metadata must not create penalties.
    assert result.negative_signals == []


def test_matrix_D_problematic_technical_site():
    items = (
        rdap_young()
        + [tls_error(), http_loop()]
        + _analyze_headers(httpx.Headers({
            "strict-transport-security": "max-age=0",
            "x-content-type-options": "nosniff-extra",
            "x-frame-options": "FOOBAR",
            "referrer-policy": "not-a-real-policy",
        }))
        + analyze_page_content(NO_TITLE)
    )
    result = assert_reconciliation(
        items,
        expected_contribs={"domain": -5.0, "ssl": -10.0, "http": -3.0,
                           "security_headers": -4.0, "content": 0.0},
        expected_score=28.0,
        # content holds +1 (substantial) and -1 (no_title) -> conflict reduces confidence
        expected_conf=0.45,
    )
    assert len(result.negative_signals) > 0
    # Every deduction is visible as a negative signal (no hidden deductions).
    for explanation in result.negative_signals:
        assert explanation


def test_matrix_E_mixed_site():
    items = (
        rdap_old_hold()  # +5 (age) and -5 (hold) -> net 0
        + [tls_valid()]
        + [http_https(), http_upgrade(), http_loop()]  # net +1
        + _analyze_headers(httpx.Headers(GOOD_HEADERS))
        + [_item("security_headers", "x_frame_options", -1.0, "FOO",
                 "Misleading X-Frame-Options value.")]  # 7 good + 1 bad -> capped 5
        + analyze_page_content(RICH)
    )
    result = assert_reconciliation(
        items,
        expected_contribs={"domain": 0.0, "ssl": 6.0, "http": 1.0,
                           "security_headers": 5.0, "content": 4.0},
        expected_score=66.0,
        # conflict within security_headers halves confidence
        expected_conf=0.45,
    )
    # Cap + conflict notes explain the clamping.
    assert any("cap" in n and "security_headers" in n for n in result.notes)
    assert any("Conflicting evidence" in n for n in result.notes)


def test_matrix_F_single_category_dominance():
    items = [tls_valid(), tls_valid(), tls_valid()] + analyze_page_content(RICH)
    result = assert_reconciliation(
        items,
        expected_contribs={"ssl": 10.0, "content": 4.0},
        expected_score=64.0,
        expected_conf=0.47,  # 2 of 11 usable
    )
    assert any("cap" in n and "ssl" in n for n in result.notes)


def test_unavailable_categories_contribute_exactly_zero():
    items = [tls_valid(), content_positive()]
    result = evaluate_evidence(items)
    assert set(result.category_contributions) == {"ssl", "content"}
    assert "domain" not in result.category_contributions
    assert "http" not in result.category_contributions
    assert "security_headers" not in result.category_contributions


# ---------- TASK 3: Monotonicity ----------

def test_adding_positive_evidence_cannot_decrease_score():
    base = [tls_valid()]
    base_score = evaluate_evidence(base).score
    extras = [
        [content_positive()],
        [http_https()],
        [_item("security_headers", "hsts", 1.0, "max-age=1")],
        rdap_old(),
    ]
    for extra in extras:
        assert evaluate_evidence(base + extra).score >= base_score


def test_adding_negative_evidence_cannot_increase_score():
    base = [tls_valid()]
    base_score = evaluate_evidence(base).score
    extras = [
        [http_loop()],
        [tls_error()],
        [content_negative()],
        rdap_young(),
    ]
    for extra in extras:
        assert evaluate_evidence(base + extra).score <= base_score


def test_adding_unavailable_evidence_has_zero_effect():
    base = [tls_valid()]
    base_score = evaluate_evidence(base).score
    assert evaluate_evidence(base + []).score == base_score
    # A neutral observation (effect 0) also cannot move the score.
    neutral = _item("domain", "domain_age", 0.0, 500, "Mid-aged domain.")
    assert evaluate_evidence(base + [neutral]).score == base_score


def test_unavailable_replaced_by_observed_signal_moves_score_only_in_its_direction():
    base = [tls_valid()]
    base_score = evaluate_evidence(base).score
    # content unavailable -> available positive: score non-decreasing
    assert evaluate_evidence(base + [content_positive()]).score >= base_score
    # content unavailable -> available negative: score non-increasing
    assert evaluate_evidence(base + [content_negative()]).score <= base_score


# ---------- TASK 6: Confidence independence ----------

def test_confidence_not_derived_from_score():
    # Same usable-category count, different scores -> identical confidence.
    positive = evaluate_evidence([tls_valid()])      # score 58
    negative = evaluate_evidence([tls_error()])      # score 40
    assert positive.score != negative.score
    assert positive.confidence == negative.confidence
    # Different usable-category counts -> different confidence.
    wider = evaluate_evidence([tls_valid(), http_https()])
    assert wider.confidence != positive.confidence


def test_confidence_within_range_for_all_matrix_cases():
    cases = [
        [],
        rdap_old() + [tls_valid(), http_https(), http_upgrade()]
        + _analyze_headers(httpx.Headers(GOOD_HEADERS)) + analyze_page_content(RICH),
        rdap_young() + [tls_error(), http_loop()] + analyze_page_content(NO_TITLE),
        [tls_valid(), tls_valid(), tls_valid()],
    ]
    for items in cases:
        result = evaluate_evidence(items)
        assert 0.0 <= result.confidence <= 1.0
