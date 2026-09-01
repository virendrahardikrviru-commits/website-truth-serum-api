import httpx

from app.models.evidence import EvidenceItem
from app.services.collectors.content import analyze_page_content
from app.services.collectors.http_behavior import collect_http
from app.services.collectors.security_headers import _analyze_headers
from app.services.collectors.ssl import collect_tls
from app.services.evidence import rdap_evidence_items
from app.services.scoring import evaluate_evidence

BODY = (
    "This is a substantial paragraph with enough words to exceed the minimum "
    "threshold for meaningful text content on a page. " * 8
)

RICH = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
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


def _signals(items):
    return {i.signal: i.effect for i in items}


def test_all_content_signals_present():
    items = analyze_page_content(RICH)
    effects = _signals(items)
    assert effects["title_present"] == 1.0
    assert effects["description_present"] == 1.0
    assert effects["lang_present"] == 1.0
    assert effects["viewport_present"] == 1.0
    assert effects["canonical_present"] == 1.0
    assert effects["alt_text_present"] == 1.0
    assert effects["substantial_content"] == 1.0
    assert "no_title" not in effects
    assert all(effect > 0 for effect in effects.values())
    for item in items:
        assert item.category == "content"
        assert item.source == "content"
        assert isinstance(item.explanation, str) and item.explanation


def test_meta_description_both_attribute_orders():
    later = f"""<html><head><meta content="Desc here" name="description"></head>
    <body><p>{BODY}</p></body></html>"""
    items = analyze_page_content(later)
    assert _signals(items)["description_present"] == 1.0


def test_missing_optional_metadata_is_neutral():
    html = f"<html><head><title>Only Title</title></head><body><p>{BODY}</p></body></html>"
    items = analyze_page_content(html)
    effects = _signals(items)
    assert effects["title_present"] == 1.0
    assert effects["substantial_content"] == 1.0
    # Optional metadata absent -> neutral, never negative.
    for signal in ("description_present", "lang_present", "viewport_present",
                   "canonical_present", "alt_text_present"):
        assert signal not in effects, signal
    assert not any(effect < 0 for effect in effects.values())


def test_minimal_page_never_penalized():
    # Short/minimal HTML must not be treated as empty or untrustworthy.
    minimal = "<html><head><title>X</title></head><body><p>Hi</p></body></html>"
    items = analyze_page_content(minimal)
    effects = _signals(items)
    assert effects == {"title_present": 1.0}
    assert not any(effect < 0 for effect in effects.values())


def test_minimal_page_without_title_never_penalized():
    html = "<html><body><p>Hello world</p></body></html>"
    assert analyze_page_content(html) == []


def test_no_title_penalized_only_for_substantial_page():
    html = f"<html><body><p>{BODY}</p></body></html>"
    items = analyze_page_content(html)
    effects = _signals(items)
    assert effects["substantial_content"] == 1.0
    assert effects["no_title"] == -1.0


def test_script_content_does_not_count_as_substantial():
    html = f"""<html><head><title>Shell</title></head><body>
    <script>{"var x = 'y';" * 5000}</script></body></html>"""
    items = analyze_page_content(html)
    effects = _signals(items)
    assert effects.get("title_present") == 1.0
    assert "substantial_content" not in effects
    assert "no_title" not in effects


def test_empty_or_none_html_is_neutral():
    assert analyze_page_content(None) == []
    assert analyze_page_content("") == []
    assert analyze_page_content("   \n  ") == []


def test_content_category_cap():
    items = analyze_page_content(RICH)  # 7 positive signals
    result = evaluate_evidence(items)
    assert result.category_contributions["content"] == 5.0  # capped, not 7
    assert result.score == 55.0
    assert any("cap" in n and "content" in n for n in result.notes)


def test_content_reconciles_under_cap():
    items = analyze_page_content(RICH)
    result = evaluate_evidence(items)
    assert result.score == round(50.0 + sum(result.category_contributions.values()), 2)


def test_assembly_with_content():
    rdap = rdap_evidence_items({"source": "rdap", "domain_age_days": 4000, "status": []})
    tls = [
        EvidenceItem(id="TLS_001", category="ssl", signal="ssl_valid",
                     value="TLSv1.3", effect=8.0, confidence=1.0, source="tls"),
    ]
    http = [
        EvidenceItem(id="HTTP_HTTPS", category="http", signal="https_ok",
                     effect=2.0, confidence=1.0, source="http"),
    ]
    headers = _analyze_headers(httpx.Headers({
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
    }))
    content = analyze_page_content(RICH)
    result = evaluate_evidence(rdap + tls + http + headers + content)
    # 50 + 5 (domain) + 8 (ssl) + 2 (http) + 2 (headers) + 5 (content capped) = 72
    assert result.score == 72.0
    assert result.category_contributions == {
        "domain": 5.0, "ssl": 8.0, "http": 2.0,
        "security_headers": 2.0, "content": 5.0,
    }
    assert result.confidence == 0.65  # 5 of 11 planned categories usable


def test_deterministic_pure_function():
    first = analyze_page_content(RICH)
    second = analyze_page_content(RICH)
    assert [(i.signal, i.effect, i.explanation) for i in first] == [
        (i.signal, i.effect, i.explanation) for i in second
    ]
