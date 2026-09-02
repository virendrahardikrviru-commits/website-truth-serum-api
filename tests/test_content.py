import httpx

from app.models.evidence import EvidenceItem
from app.services.collectors.content import _metadata_effect, analyze_page_content
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


# ---------- Metadata aggregation ----------

def test_all_content_signals_present_with_aggregation():
    items = analyze_page_content(RICH)
    effects = _signals(items)
    assert effects["metadata_quality"] == 3.0  # aggregated, not 6 separate points
    assert effects["substantial_content"] == 1.0
    # Individual routine-metadata observations stay visible but neutralized.
    for signal in ("title_present", "description_present", "lang_present",
                   "viewport_present", "canonical_present", "alt_text_present"):
        assert effects[signal] == 0.0
    assert "no_title" not in effects
    assert not any(effect < 0 for effect in effects.values())
    # 6 neutralized observations + metadata_quality + substantial = 8 items.
    assert len(items) == 8
    for item in items:
        assert item.category == "content"
        assert item.source == "content"
        assert isinstance(item.explanation, str) and item.explanation


def test_metadata_quality_tiering():
    assert _metadata_effect(6) == 3.0
    assert _metadata_effect(4) == 2.0
    assert _metadata_effect(2) == 1.0
    assert _metadata_effect(1) == 0.0
    assert _metadata_effect(0) == 0.0


def test_meta_description_both_attribute_orders():
    later = f"""<html><head><meta content="Desc here" name="description"></head>
    <body><p>{BODY}</p></body></html>"""
    items = analyze_page_content(later)
    effects = _signals(items)
    assert effects["description_present"] == 0.0  # observed but neutralized
    assert effects["metadata_quality"] == 0.0  # only 1 metadata element


def test_missing_optional_metadata_is_neutral():
    html = f"<html><head><title>Only Title</title></head><body><p>{BODY}</p></body></html>"
    items = analyze_page_content(html)
    effects = _signals(items)
    assert effects["title_present"] == 0.0
    assert effects["metadata_quality"] == 0.0  # 1 of 6 -> no metadata credit
    assert effects["substantial_content"] == 1.0
    # Optional metadata absent -> neutral, never negative.
    for signal in ("description_present", "lang_present", "viewport_present",
                   "canonical_present", "alt_text_present"):
        assert signal not in effects, signal
    assert not any(effect < 0 for effect in effects.values())


def test_minimal_page_never_penalized():
    minimal = "<html><head><title>X</title></head><body><p>Hi</p></body></html>"
    items = analyze_page_content(minimal)
    effects = _signals(items)
    assert effects["title_present"] == 0.0
    assert effects["metadata_quality"] == 0.0
    assert "substantial_content" not in effects
    assert not any(effect < 0 for effect in effects.values())


def test_minimal_page_without_title_never_penalized():
    html = "<html><body><p>Hello world</p></body></html>"
    items = analyze_page_content(html)
    effects = _signals(items)
    assert effects == {"metadata_quality": 0.0}
    assert not any(effect < 0 for effect in effects.values())


def test_no_title_penalized_only_for_substantial_page():
    html = f"<html><body><p>{BODY}</p></body></html>"
    items = analyze_page_content(html)
    effects = _signals(items)
    assert effects["metadata_quality"] == 0.0
    assert effects["substantial_content"] == 1.0
    assert effects["no_title"] == -1.0


def test_script_content_does_not_count_as_substantial():
    html = f"""<html><head><title>Shell</title></head><body>
    <script>{"var x = 'y';" * 5000}</script></body></html>"""
    items = analyze_page_content(html)
    effects = _signals(items)
    assert effects.get("title_present") == 0.0
    assert "substantial_content" not in effects
    assert "no_title" not in effects


def test_empty_or_none_html_is_neutral():
    assert analyze_page_content(None) == []
    assert analyze_page_content("") == []
    assert analyze_page_content("   \n  ") == []
    # Even with a scheme, no body means no evidence.
    assert analyze_page_content(None, scheme="https") == []
    assert analyze_page_content(None, scheme="http") == []


# ---------- V1.2: transport-hygiene signals ----------

def test_https_page_with_http_subresource_mixed_content():
    html = (
        '<html><head><title>T</title></head><body>'
        '<img src="http://cdn.example.com/a.png">'
        '<script src="http://cdn.example.com/app.js"></script>'
        "</body></html>"
    )
    items = analyze_page_content(html, scheme="https")
    mixed = [i for i in items if i.signal == "insecure_mixed_content"]
    assert len(mixed) == 1
    assert mixed[0].effect == -1.0
    assert mixed[0].value == 2
    assert mixed[0].category == "content"


def test_https_page_no_http_subresources_no_mixed_item():
    items = analyze_page_content(RICH, scheme="https")
    assert all(i.signal != "insecure_mixed_content" for i in items)
    assert "insecure_login" not in {i.signal for i in items}


def test_http_page_with_http_resources_no_mixed_signal():
    # Mixed content only applies to HTTPS-served pages.
    html = (
        '<html><head><title>T</title></head><body>'
        '<img src="http://cdn.example.com/a.png">'
        "</body></html>"
    )
    items = analyze_page_content(html, scheme="http")
    assert all(i.signal != "insecure_mixed_content" for i in items)


def test_http_password_form_posting_http_insecure_login():
    html = (
        '<html><head><title>Login</title></head><body>'
        '<form action="http://example.com/login" method="post">'
        '<input type="password" name="pw">'
        "</form></body></html>"
    )
    items = analyze_page_content(html, scheme="http")
    login = [i for i in items if i.signal == "insecure_login"]
    assert len(login) == 1
    assert login[0].effect == -2.0


def test_http_password_form_relative_action_insecure_login():
    # A relative action posts back to the current HTTP page.
    html = (
        '<html><head><title>Login</title></head><body>'
        '<form action="/login" method="post">'
        '<input type="password" name="pw">'
        "</form></body></html>"
    )
    items = analyze_page_content(html, scheme="http")
    assert any(i.signal == "insecure_login" for i in items)


def test_http_password_form_posting_https_neutral():
    html = (
        '<html><head><title>Login</title></head><body>'
        '<form action="https://example.com/login" method="post">'
        '<input type="password" name="pw">'
        "</form></body></html>"
    )
    items = analyze_page_content(html, scheme="http")
    assert all(i.signal != "insecure_login" for i in items)


def test_https_password_form_no_insecure_login():
    html = (
        '<html><head><title>Login</title></head><body>'
        '<form action="/login" method="post">'
        '<input type="password" name="pw">'
        "</form></body></html>"
    )
    items = analyze_page_content(html, scheme="https")
    assert all(i.signal != "insecure_login" for i in items)


def test_no_password_input_is_neutral():
    html = (
        '<html><head><title>Search</title></head><body>'
        '<form action="/search"><input type="text" name="q"></form>'
        "</body></html>"
    )
    items = analyze_page_content(html, scheme="http")
    assert all(i.signal not in ("insecure_login", "insecure_mixed_content") for i in items)


def test_no_scheme_suppresses_transport_signals():
    # When no page scheme is known (page unavailable) both hygiene signals stay
    # neutral even if the HTML would otherwise trigger them.
    html = (
        '<html><head><title>Login</title></head><body>'
        '<img src="http://cdn.example.com/a.png">'
        '<form action="/login"><input type="password" name="pw"></form>'
        "</body></html>"
    )
    items = analyze_page_content(html)
    assert all(
        i.signal not in ("insecure_login", "insecure_mixed_content") for i in items
    )


# ---------- Content category behaviour in the engine ----------

def test_content_aggregation_is_bounded_below_cap():
    items = analyze_page_content(RICH)  # metadata +3, substantial +1
    result = evaluate_evidence(items)
    assert result.category_contributions["content"] == 4.0  # aggregation bound, not clamp
    assert result.score == 54.0
    assert not any("cap" in n and "content" in n for n in result.notes)


def test_content_category_cap_still_enforced():
    # Hand-built content items far exceeding the cap must still be clamped.
    items = [
        EvidenceItem(id=f"C{i}", category="content", signal="sig", effect=1.0,
                     confidence=1.0, source="content")
        for i in range(8)
    ]
    result = evaluate_evidence(items)
    assert result.category_contributions["content"] == 5.0
    assert result.score == 55.0
    assert any("cap" in n and "content" in n for n in result.notes)


def test_content_reconciles():
    items = analyze_page_content(RICH)
    result = evaluate_evidence(items)
    assert result.score == round(50.0 + sum(result.category_contributions.values()), 2)


def test_assembly_with_content():
    rdap = rdap_evidence_items({"source": "rdap", "domain_age_days": 4000, "status": []})
    tls = [
        EvidenceItem(id="TLS_001", category="ssl", signal="ssl_valid",
                     value="TLSv1.3", effect=6.0, confidence=1.0, source="tls"),
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
    # 50 + 5 + 6 + 2 + 2 (headers) + 4 (content) = 69
    assert result.score == 69.0
    assert result.category_contributions == {
        "domain": 5.0, "ssl": 6.0, "http": 2.0,
        "security_headers": 2.0, "content": 4.0,
    }
    assert result.confidence == 0.65  # 5 of 11 planned categories usable


def test_deterministic_pure_function():
    first = analyze_page_content(RICH)
    second = analyze_page_content(RICH)
    assert [(i.signal, i.effect, i.explanation) for i in first] == [
        (i.signal, i.effect, i.explanation) for i in second
    ]
