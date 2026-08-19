from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import httpx
from datetime import datetime
import os
import asyncio
import re

router = APIRouter(prefix="/api/analyze", tags=["analysis"])

class AnalyzeRequest(BaseModel):
    url: HttpUrl
    deep_analysis: bool = False

class AnalyzeResponse(BaseModel):
    url: str
    trust_score: float
    category: str
    ai_probability: float
    red_flags: List[str]
    green_flags: List[str]
    summary: str
    analyzed_at: datetime
    domain: str
    domain_age: Optional[str] = None
    ssl_valid: Optional[bool] = None

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
    
    try:
        # Fetch the website content
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(
                str(request.url),
                headers={
                    "User-Agent": "WebsiteTruthSerum/1.0 (http://websitetruthserum.com; info@websitetruthserum.com)"
                }
            )
            html = response.text
            
            # Here you would add actual AI analysis using DeepSeek API
            # For now, we'll use the mock data
            
    except httpx.TimeoutException:
        # If fetch times out, use mock data
        html = None
    except Exception as e:
        # Handle other errors
        html = None
    
    # Analyze the domain
    analysis = analyze_domain(domain)
    
    # Calculate trust score (0-100)
    trust_score = analysis["score"]
    ai_probability = analysis["ai"]
    category = analysis["category"]
    red_flags = analysis["red_flags"]
    green_flags = analysis["green_flags"]
    summary = analysis["summary"]
    
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
        domain_age=analysis.get("domain_age", "Unknown"),
        ssl_valid=analysis.get("ssl_valid", None)
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