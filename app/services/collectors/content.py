"""Page/content evidence collector (Phase 2c-2).

Pure, deterministic analysis of HTML already fetched by the analyzer. No
network calls, no domain-name logic, no LLM.

Rules enforced here:

- Only facts actually present in the HTML produce items.
- Missing *optional* metadata (description, lang, viewport, canonical, alt)
  is neutral — never penalized.
- A short/minimal document is never penalized on its own; there is no
  ``empty_page`` signal. The only negative is ``no_title``, and it fires only
  when a page has substantial text content yet is missing a <title>.
- ``html=None`` or an empty document produces no evidence (unavailable).

All effects are +/-1 so the ``content`` category stays within its +/-5 cap.
"""

import re
from typing import List, Optional

from app.models.evidence import EvidenceItem

# Minimum visible text length (chars) to be considered "substantial".
MIN_SUBSTANTIAL_TEXT = 300

_IDS = {
    "title_present": "CONTENT_TITLE",
    "description_present": "CONTENT_DESC",
    "lang_present": "CONTENT_LANG",
    "viewport_present": "CONTENT_VIEWPORT",
    "canonical_present": "CONTENT_CANONICAL",
    "alt_text_present": "CONTENT_ALT",
    "substantial_content": "CONTENT_SIZE",
    "no_title": "CONTENT_NO_TITLE",
}

_TAG_RE = re.compile(r"<[^>]+>")
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL
)


def _visible_text(html: str) -> str:
    text = _SCRIPT_STYLE_RE.sub(" ", html)
    text = _TAG_RE.sub(" ", text)
    text = re.sub(r"&\w+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _attr_value(tag: str, attr: str) -> Optional[str]:
    match = re.search(
        r"\b" + re.escape(attr) + r"\s*=\s*[\"']([^\"']*)", tag, re.IGNORECASE
    )
    return match.group(1).strip() if match else None


def _has_meta(html: str, name: str) -> bool:
    for match in _META_TAG_RE.finditer(html):
        tag = match.group(0)
        if (_attr_value(tag, "name") or "").lower() == name:
            if _attr_value(tag, "content"):
                return True
    return False


def _title(html: str) -> Optional[str]:
    match = re.search(r"<title\b[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", match.group(1))).strip()


def _item(signal: str, value, effect: float, explanation: str) -> EvidenceItem:
    return EvidenceItem(
        id=_IDS[signal],
        category="content",
        signal=signal,
        value=value,
        effect=effect,
        confidence=1.0,
        source="content",
        explanation=explanation,
    )


def analyze_page_content(html: Optional[str]) -> List[EvidenceItem]:
    """Analyze fetched HTML and return content evidence. Never raises."""
    if not isinstance(html, str) or not html.strip():
        return []

    items: List[EvidenceItem] = []
    title = _title(html)
    text_len = len(_visible_text(html))
    has_substantial = text_len >= MIN_SUBSTANTIAL_TEXT

    if title:
        items.append(_item(
            "title_present", title, 1.0,
            "The page includes a <title> element.",
        ))
    if _has_meta(html, "description"):
        items.append(_item(
            "description_present", True, 1.0,
            "The page includes a meta description.",
        ))
    if re.search(r"<html\b[^>]*\blang\s*=\s*[\"'][^\"']+", html, re.IGNORECASE):
        items.append(_item(
            "lang_present", True, 1.0,
            "The page declares a lang attribute.",
        ))
    if _has_meta(html, "viewport"):
        items.append(_item(
            "viewport_present", True, 1.0,
            "The page includes a viewport meta tag.",
        ))
    if re.search(
        r"<link\b[^>]*\brel\s*=\s*[\"']canonical[\"']", html, re.IGNORECASE
    ):
        items.append(_item(
            "canonical_present", True, 1.0,
            "The page declares a canonical URL.",
        ))
    if re.search(r"<img\b[^>]*\balt\s*=\s*[\"']", html, re.IGNORECASE):
        items.append(_item(
            "alt_text_present", True, 1.0,
            "The page includes images with alt text.",
        ))
    if has_substantial:
        items.append(_item(
            "substantial_content", text_len, 1.0,
            "The page contains substantial text content.",
        ))

    # Only negative: a real, substantial page missing its <title>.
    if has_substantial and not title:
        items.append(_item(
            "no_title", None, -1.0,
            "A page with substantial content has no <title> element.",
        ))

    return items
