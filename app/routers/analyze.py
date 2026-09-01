from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import httpx
from datetime import datetime
import os
import asyncio
import logging
import re
import time
import uuid

from app.models.evidence import EvidenceItem
from app.services import observability as obs
from app.services.collectors.content import analyze_page_content
from app.services.collectors.http_behavior import analyze_http_response, collect_http
from app.services.collectors.reputation import collect_reputation
from app.services.collectors.security_headers import analyze_headers_response, collect_security_headers
from app.services.collectors.ssl import collect_tls
from app.services.evidence import (
    evaluate_rdap_evidence,
    format_domain_age,
    rdap_evidence_items,
)
from app.services.rdap import is_public_hostname, normalize_domain, rdap_lookup
from app.services.scoring import evaluate_evidence, summarize

# Maximum page body bytes the analyzer will buffer (resource bound).
MAX_PAGE_BYTES = 2_000_000

# Evidence-mode-only overall scan deadline (wall-clock budget for the whole
# evidence scan, including page fetch and RDAP). Unfinished collectors are
# treated as unavailable/neutral when the deadline is reached.
SCAN_DEADLINE_SECONDS = 22.0


def _cap_page_html(raw: Optional[str], max_bytes: int = MAX_PAGE_BYTES) -> Optional[str]:
    """Truncate a fetched page body to a bounded size (safety net for bodies
    served without a usable Content-Length header)."""
    if raw is None:
        return None
    return raw[:max_bytes]


async def _guard_public_redirects(request: httpx.Request) -> None:
    """SSRF guard: abort any outbound request whose target host is not a
    public hostname (blocks IP literals, loopback, link-local and single-label
    targets, including redirect hops)."""
    if not is_public_hostname(request.url.host):
        raise ValueError(f"blocked non-public host: {request.url.host}")

router = APIRouter(prefix="/api/analyze", tags=["analysis"])

class AnalyzeRequest(BaseModel):
    url: HttpUrl
    deep_analysis: bool = False

class AnalyzeResponse(BaseModel):
    url: str
    trust_score: float
    category: str
    ai_probability: Optional[float] = None
    red_flags: List[str]
    green_flags: List[str]
    summary: str
    analyzed_at: datetime
    domain: str
    domain_age: Optional[str] = None
    ssl_valid: Optional[bool] = None
    domain_intel: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None
    risk_level: Optional[str] = None
    evidence: Optional[List[EvidenceItem]] = None
    category_contributions: Optional[Dict[str, float]] = None
    notes: Optional[List[str]] = None

# ============================================
# Mock Data (Replace with real API calls)
# ============================================

def analyze_domain(domain: str) -> Dict[str, Any]:
    """Analyze domain based on patterns"""
    
    # Define patterns for different types of websites
    scam_patterns = [
        r'free', r'win', r'lucky', r'giveaway', r'bonus', r'doubler',
        r'shady', r'rypto', r'crypto-give', r'off', r'deal', r'biz'
    ]
    trusted_patterns = [
        r'github', r'google', r'wikipedia', r'apple', r'microsoft',
        r'mozilla', r'stackoverflow', r'vercel', r'linear', r'amazon',
        r'netflix', r'spotify', r'adobe', r'facebook', r'twitter'
    ]
    
    # Check if domain matches patterns
    is_scam = any(re.search(pattern, domain.lower()) for pattern in scam_patterns)
    is_trusted = any(re.search(pattern, domain.lower()) for pattern in trusted_patterns)
    
    if is_scam:
        return {
            "score": 15,
            "ai": 85,
            "category": "untrustworthy",
            "red_flags": [
                "Suspicious domain name detected",
                "No contact information found",
                "Poor grammar in content",
                "No privacy policy"
            ],
            "green_flags": [],
            "summary": "This site shows multiple red flags and appears to be a scam or AI-generated content farm.",
            "domain_age": "2 months",
            "ssl_valid": False
        }
    elif is_trusted:
        return {
            "score": 95,
            "ai": 5,
            "category": "trusted",
            "red_flags": [],
            "green_flags": [
                "Well-established domain (9+ years)",
                "Valid SSL certificate",
                "Clear contact information",
                "Privacy policy present"
            ],
            "summary": "A legitimate, well-established website with strong trust signals.",
            "domain_age": "9+ years",
            "ssl_valid": True
        }
    else:
        return {
            "score": 65,
            "ai": 40,
            "category": "moderate",
            "red_flags": [
                "Some content appears AI-generated",
                "Limited author information"
            ],
            "green_flags": [
                "Published articles with dates",
                "Valid SSL certificate",
                "Some human-written content"
            ],
            "summary": "This site has a mix of human and AI-generated content. Verify sources before trusting.",
            "domain_age": "3 years",
            "ssl_valid": True
        }

# ============================================
# API Endpoints
# ============================================

@router.post("/", response_model=AnalyzeResponse)
async def analyze_website(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks
):
    """
    Analyze a website for trustworthiness and AI-generated content.
    Returns a trust score, AI probability, and detailed analysis.
    """
    
    # Extract domain from URL
    domain = str(request.url).replace("https://", "").replace("http://", "").split("/")[0]
    
    # Add background task for logging (optional)
    background_tasks.add_task(log_scan, domain)
    
    # Select the scoring path. Default is 'legacy' for safe rollback; set
    # SCORING_MODE=evidence to enable the deterministic evidence engine.
    scoring_mode = os.getenv("SCORING_MODE", "legacy").lower()
    scan_id = str(uuid.uuid4())
    scan_started = time.monotonic()
    deadline = scan_started + SCAN_DEADLINE_SECONDS if scoring_mode == "evidence" else None

    # Validate/normalize the domain before ANY network access (SSRF guard).
    normalized = normalize_domain(domain)

    # Fetch the website content only for public hostnames. Redirect targets are
    # restricted to public hostnames too, and the body size is bounded. The
    # response object is retained so evidence mode can derive HTTP-behavior and
    # security-header evidence from this single request.
    html = None
    page_response = None
    page_redirect_loop = False
    if normalized is not None:
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                event_hooks={"request": [_guard_public_redirects]},
            ) as client:
                page_response = await client.get(
                    str(request.url),
                    headers={
                        "User-Agent": "WebsiteTruthSerum/1.0 (http://websitetruthserum.com; info@websitetruthserum.com)"
                    },
                )
                content_length = page_response.headers.get("content-length")
                if (
                    content_length
                    and content_length.isdigit()
                    and int(content_length) > MAX_PAGE_BYTES
                ):
                    # Abort oversized downloads before buffering them.
                    html = None
                else:
                    html = _cap_page_html(page_response.text)
        except httpx.TooManyRedirects:
            # A redirect loop was detected; HTTP evidence records it.
            page_redirect_loop = True
            html = None
        except httpx.TimeoutException:
            # If fetch times out, use mock data
            html = None
        except Exception:
            # Handle other errors (incl. blocked non-public redirect targets)
            html = None
    
    # Analyze the domain (legacy pattern baseline, retained for rollback).
    analysis = analyze_domain(domain)

    # Fetch real RDAP intelligence (shared by both scoring modes, never fatal).
    rdap = None
    domain_intel = None
    try:
        if normalized is not None:
            rdap = await rdap_lookup(normalized)
            domain_intel = {
                "domain": normalized,
                "registered": rdap.get("registered"),
                "expires": rdap.get("expires"),
                "updated": rdap.get("updated"),
                "registrar": rdap.get("registrar"),
                "nameservers": rdap.get("nameservers") or [],
                "domain_age_days": rdap.get("domain_age_days"),
                "status": rdap.get("status") or [],
                "source": rdap.get("source", "rdap_unavailable"),
                "notes": rdap.get("notes") or None,
            }
    except Exception:
        # RDAP must never break the analysis.
        rdap = None
        domain_intel = None

    real_age_days = None
    if rdap is not None:
        age_days = rdap.get("domain_age_days")
        if isinstance(age_days, int) and age_days >= 0:
            real_age_days = age_days

    if scoring_mode == "evidence":
        items = rdap_evidence_items(rdap) if rdap is not None else []
        if normalized is not None:
            # Pure evidence derived from the single SSRF-validated page response.
            def _log_sync(collector, started, produced, outcome=None):
                duration_ms = (time.monotonic() - started) * 1000
                obs.log_collector(
                    scan_id, normalized, scoring_mode, collector, duration_ms,
                    outcome or ("success" if produced else "unavailable"),
                    len(produced) if produced else 0,
                )

            try:
                _started = time.monotonic()
                http_items = analyze_http_response(
                    page_response, str(request.url), redirect_loop=page_redirect_loop
                )
                items = items + http_items
                _log_sync("http", _started, http_items)
            except Exception:
                obs.log_collector(scan_id, normalized, scoring_mode, "http",
                                  (time.monotonic() - _started) * 1000, "error", 0,
                                  level=logging.ERROR)

            if page_response is not None:
                try:
                    _started = time.monotonic()
                    header_items = analyze_headers_response(page_response)
                    items = items + header_items
                    _log_sync("security_headers", _started, header_items)
                except Exception:
                    obs.log_collector(scan_id, normalized, scoring_mode,
                                      "security_headers",
                                      (time.monotonic() - _started) * 1000, "error", 0,
                                      level=logging.ERROR)

            try:
                _started = time.monotonic()
                content_items = analyze_page_content(html)
                items = items + content_items
                _log_sync("content", _started, content_items)
            except Exception:
                obs.log_collector(scan_id, normalized, scoring_mode, "content",
                                  (time.monotonic() - _started) * 1000, "error", 0,
                                  level=logging.ERROR)

            # Async collectors run under the overall evidence deadline. When the
            # deadline is reached, already-completed evidence is retained and
            # unfinished collectors are cancelled (treated unavailable/neutral).
            async def _task(coro):
                try:
                    return await coro
                except asyncio.CancelledError:
                    raise
                except Exception:
                    return []

            rep_outcomes: Dict[str, str] = {}
            async_tasks = {}
            task_starts = {}
            async_tasks["tls"] = asyncio.ensure_future(_task(collect_tls(normalized)))
            task_starts["tls"] = time.monotonic()
            if os.getenv("REPUTATION_ENABLED", "false").lower() == "true":
                async_tasks["reputation"] = asyncio.ensure_future(
                    _task(collect_reputation(normalized, outcomes=rep_outcomes))
                )
                task_starts["reputation"] = time.monotonic()

            remaining = max(0.0, deadline - time.monotonic()) if deadline else None
            done, pending = await asyncio.wait(
                list(async_tasks.values()),
                timeout=remaining,
                return_when=asyncio.ALL_COMPLETED,
            )
            for task in pending:
                task.cancel()

            for name, task in async_tasks.items():
                duration_ms = (time.monotonic() - task_starts[name]) * 1000
                if task in done:
                    try:
                        result = task.result()
                        obs.log_collector(
                            scan_id, normalized, scoring_mode, name, duration_ms,
                            "success" if result else "unavailable", len(result),
                        )
                        items = items + result
                    except Exception:
                        obs.log_collector(scan_id, normalized, scoring_mode, name,
                                          duration_ms, "error", 0, level=logging.ERROR)
                else:
                    obs.log_collector(scan_id, normalized, scoring_mode, name,
                                      duration_ms, "timeout", 0, level=logging.WARNING)

            # Surface reputation provider configuration problems without
            # affecting the score.
            for provider in ("urlhaus", "spamhaus_dbl"):
                outcome = rep_outcomes.get(provider)
                if outcome in ("rate_limited", "unauthorized"):
                    obs.log_collector(
                        scan_id, normalized, scoring_mode, f"reputation:{provider}",
                        (time.monotonic() - task_starts.get("reputation", scan_started)) * 1000,
                        outcome, 0, level=logging.WARNING)
        result = evaluate_evidence(items)
        trust_score = result.score
        confidence = result.confidence
        risk_level = result.risk_level
        category = result.category
        ai_probability = None  # not measured until a content collector exists
        red_flags = list(result.negative_signals)
        green_flags = list(result.positive_signals)
        notes = list(result.notes)
        ssl_valid = None  # TLS validity is represented by ssl evidence, not this field
        applied_evidence = result.applied_evidence
        category_contributions = result.category_contributions
        domain_age = (
            format_domain_age(real_age_days) if real_age_days is not None else "Unknown"
        )
        summary = summarize(result)
        obs.log_scan_result(
            scan_id, normalized or domain, scoring_mode,
            (time.monotonic() - scan_started) * 1000,
            result.score, result.category, result.confidence,
            len(result.category_contributions),
        )
    else:
        # Legacy path: Phase 1 behavior unchanged (pattern baseline + bounded
        # RDAP signal), isolated from the evidence engine.
        trust_score = analysis["score"]
        ai_probability = analysis["ai"]
        category = analysis["category"]
        red_flags = list(analysis["red_flags"])
        green_flags = list(analysis["green_flags"])
        summary = analysis["summary"]
        domain_age = analysis.get("domain_age", "Unknown")
        ssl_valid = analysis.get("ssl_valid", None)
        confidence = None
        risk_level = None
        notes = None
        applied_evidence = None
        category_contributions = None
        if rdap is not None:
            evidence = evaluate_rdap_evidence(rdap)
            trust_score = max(0.0, min(100.0, trust_score + evidence["score_delta"]))
            red_flags = red_flags + evidence["red_flags"]
            green_flags = green_flags + evidence["green_flags"]
            if real_age_days is not None:
                domain_age = format_domain_age(real_age_days)

    return AnalyzeResponse(
        url=str(request.url),
        trust_score=trust_score,
        category=category,
        ai_probability=ai_probability,
        red_flags=red_flags,
        green_flags=green_flags,
        summary=summary,
        analyzed_at=datetime.now(),
        domain=domain,
        domain_age=domain_age,
        ssl_valid=ssl_valid,
        domain_intel=domain_intel,
        confidence=confidence,
        risk_level=risk_level,
        evidence=applied_evidence,
        category_contributions=category_contributions,
        notes=notes,
    )

@router.get("/test")
async def test_analysis():
    """Test endpoint to verify the API is working"""
    return {
        "status": "ok",
        "message": "Analysis API is ready",
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# Helper Functions
# ============================================

async def log_scan(domain: str):
    """Background task to log scans (for analytics)"""
    # In production, you'd save this to a database
    print(f"[SCAN] {domain} scanned at {datetime.now()}")
    return

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    url = url.replace("https://", "").replace("http://", "")
    return url.split("/")[0].split("?")[0]

def analyze_with_ai(content: str) -> Dict[str, Any]:
    """
    Analyze content using AI (DeepSeek API integration placeholder)
    In production, replace this with actual API calls to DeepSeek V4
    """
    # This is where you'd integrate DeepSeek V4
    # Example:
    # from deepseek import DeepSeekClient
    # client = DeepSeekClient(api_key=os.getenv("DEEPSEEK_API_KEY"))
    # response = client.chat.completions.create(...)
    
    # For now, return mock analysis
    return {
        "ai_probability": 30,
        "red_flags": [],
        "green_flags": ["Content appears authentic"],
        "summary": "Content analysis complete."
    }