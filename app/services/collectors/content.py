"""Page/content evidence collector (Phase 2c-2, calibrated Phase 2c-4).

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

Anti-inflation (Phase 2c-4):

- The six routine metadata observations (title, description, lang, viewport,
  canonical, alt) remain visible in the evidence output with effect ``0`` so
  they stay auditable, but they no longer each award a point.
- A single ``metadata_quality`` item aggregates overall metadata completeness
  into one small bounded contribution (+1/+2/+3).
- ``substantial_content`` remains a separate, small signal (+1).
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
    "metadata_quality": "CONTENT_META",
    "substantial_content": "CONTENT_SIZE",
    "no_title": "CONTENT_NO_TITLE",
}

# Routine metadata observations that are aggregated into metadata_quality.
_METADATA_SIGNALS = (
    "title_present",
    "description_present",
    "lang_present",
    "viewport_present",
    "canonical_present",
    "alt_text_present",
)

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


def _metadata_effect(count: int) -> float:
    """Aggregate routine-metadata completeness into one small contribution."""
    if count >= 6:
        return 3.0
    if count >= 4:
        return 2.0
    if count >= 2:
        return 1.0
    return 0.0


def analyze_page_content(html: Optional[str]) -> List[EvidenceItem]:
    """Analyze fetched HTML and return content evidence. Never raises."""
    if not isinstance(html, str) or not html.strip():
        return []

    items: List[EvidenceItem] = []
    title = _title(html)
    text_len = len(_visible_text(html))
    has_substantial = text_len >= MIN_SUBSTANTIAL_TEXT

    # Individual routine-metadata observations stay visible but neutralized.
    present: List[str] = []
    observations = {
        "title_present": title,
        "description_present": _has_meta(html, "description"),
        "lang_present": bool(
            re.search(r"<html\b[^>]*\blang\s*=\s*[\"'][^\"']+", html, re.IGNORECASE)
        ),
        "viewport_present": _has_meta(html, "viewport"),
        "canonical_present": bool(
            re.search(r"<link\b[^>]*\brel\s*=\s*[\"']canonical[\"']", html, re.IGNORECASE)
        ),
        "alt_text_present": bool(
            re.search(r"<img\b[^>]*\balt\s*=\s*[\"']", html, re.IGNORECASE)
        ),
    }
    for signal, is_present in observations.items():
        if is_present:
            present.append(signal)
            items.append(_item(
                signal, True if signal != "title_present" else title, 0.0,
                f"Observed: {signal}.",
            ))

    # Aggregate metadata completeness into a single small contribution.
    metadata_count = len(present)
    metadata_effect = _metadata_effect(metadata_count)
    items.append(_item(
        "metadata_quality",
        {"present": metadata_count, "of": len(_METADATA_SIGNALS)},
        metadata_effect,
        (
            f"Routine metadata present in {metadata_count} of "
            f"{len(_METADATA_SIGNALS)} categories; aggregated contribution "
            f"{metadata_effect:+g}."
        ),
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
