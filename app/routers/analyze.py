from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import httpx
from datetime import datetime
import os
import asyncio
import re

from app.models.evidence import EvidenceItem
from app.services.collectors.content import analyze_page_content
from app.services.collectors.http_behavior import collect_http
from app.services.collectors.reputation import collect_reputation
from app.services.collectors.security_headers import collect_security_headers
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
    
    # Validate/normalize the domain before ANY network access (SSRF guard).
    normalized = normalize_domain(domain)

    # Fetch the website content only for public hostnames. Redirect targets are
    # restricted to public hostnames too, and the body size is bounded.
    html = None
    if normalized is not None:
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                event_hooks={"request": [_guard_public_redirects]},
            ) as client:
                response = await client.get(
                    str(request.url),
                    headers={
                        "User-Agent": "WebsiteTruthSerum/1.0 (http://websitetruthserum.com; info@websitetruthserum.com)"
                    },
                )
                content_length = response.headers.get("content-length")
                if (
                    content_length
                    and content_length.isdigit()
                    and int(content_length) > MAX_PAGE_BYTES
                ):
                    # Abort oversized downloads before buffering them.
                    html = None
                else:
                    html = _cap_page_html(response.text)
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

    # Select the scoring path. Default is 'legacy' for safe rollback; set
    # SCORING_MODE=evidence to enable the deterministic evidence engine.
    scoring_mode = os.getenv("SCORING_MODE", "legacy").lower()

    if scoring_mode == "evidence":
        items = rdap_evidence_items(rdap) if rdap is not None else []
        if normalized is not None:
            try:
                items = items + await collect_tls(normalized)
            except Exception:
                pass  # a collector must never break the analysis
            try:
                items = items + await collect_http(str(request.url))
            except Exception:
                pass
            try:
                items = items + await collect_security_headers(str(request.url))
            except Exception:
                pass
            try:
                items = items + analyze_page_content(html)
            except Exception:
                pass
            if os.getenv("REPUTATION_ENABLED", "false").lower() == "true":
                try:
                    items = items + await collect_reputation(normalized)
                except Exception:
                    pass  # a collector must never break the analysis
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