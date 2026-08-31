from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
import httpx
import re
from typing import Optional, List, Dict, Any

router = APIRouter(prefix="/api/domain-intel", tags=["domain intelligence"])

class DomainIntelResponse(BaseModel):
    domain: str
    registered: Optional[str] = None
    expires: Optional[str] = None
    updated: Optional[str] = None
    registrar: Optional[str] = None
    nameservers: Optional[List[str]] = None
    domain_age_days: Optional[int] = None
    status: Optional[List[str]] = None
    source: str  # 'rdap', 'whois', or 'mock'

# ============================================
# Mock Domain Data (for testing)
# ============================================

def get_mock_domain_data(domain: str) -> Dict[str, Any]:
    """Return mock domain data for testing"""
    return {
        "domain": domain,
        "registered": "2015-03-15",
        "expires": "2028-03-15",
        "updated": "2026-01-01",
        "registrar": "GoDaddy.com, LLC",
        "nameservers": ["ns1.example.com", "ns2.example.com"],
        "domain_age_days": 3965,  # ~10.8 years
        "status": ["clientTransferProhibited", "serverTransferProhibited"],
        "source": "mock"
    }

# ============================================
# Basic WHOIS-like Analysis (No External API)
# ============================================

def analyze_domain_age(domain: str) -> Dict[str, Any]:
    """
    Analyze domain age using pattern matching (mock for now)
    In production, use RDAP or WHOIS API
    """
    # Mock logic for different domains
    trusted_patterns = [
        r'github', r'google', r'wikipedia', r'apple', r'microsoft',
        r'amazon', r'netflix', r'spotify', r'adobe', r'facebook',
        r'twitter', r'linkedin', r'stackoverflow'
    ]
    
    scam_patterns = [
        r'free', r'win', r'lucky', r'giveaway', r'bonus', r'doubler',
        r'shady', r'rypto', r'crypto-give', r'off', r'deal', r'biz'
    ]
    
    is_trusted = any(re.search(pattern, domain.lower()) for pattern in trusted_patterns)
    is_scam = any(re.search(pattern, domain.lower()) for pattern in scam_patterns)
    
    if is_trusted:
        return {
            "registered": "2010-01-01",
            "expires": "2030-01-01",
            "updated": "2026-01-01",
            "registrar": "MarkMonitor Inc.",
            "nameservers": ["ns1.trusted.com", "ns2.trusted.com"],
            "domain_age_days": 5800,
            "status": ["clientTransferProhibited"],
            "source": "mock"
        }
    elif is_scam:
        return {
            "registered": "2026-06-01",
            "expires": "2027-06-01",
            "updated": "2026-06-01",
            "registrar": "Unknown (privacy-locked)",
            "nameservers": ["ns1.scamhost.com", "ns2.scamhost.com"],
            "domain_age_days": 90,
            "status": ["clientHold"],
            "source": "mock"
        }
    else:
        return {
            "registered": "2022-01-01",
            "expires": "2027-01-01",
            "updated": "2025-07-01",
            "registrar": "Namecheap, Inc.",
            "nameservers": ["dns1.namecheap.com", "dns2.namecheap.com"],
            "domain_age_days": 1400,
            "status": ["ok"],
            "source": "mock"
        }

# ============================================
# API Endpoints
# ============================================

@router.get("/{domain}", response_model=DomainIntelResponse)
async def get_domain_intelligence(domain: str):
    """
    Get domain intelligence including:
    - Registration date
    - Expiry date
    - Registrar
    - Nameservers
    - Domain age
    - Status
    
    Currently uses mock data. Will be upgraded to RDAP/WHOIS.
    """
    
    # Clean domain
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    
    # Get domain data
    data = analyze_domain_age(domain)
    
    return DomainIntelResponse(
        domain=domain,
        registered=data.get("registered"),
        expires=data.get("expires"),
        updated=data.get("updated"),
        registrar=data.get("registrar"),
        nameservers=data.get("nameservers"),
        domain_age_days=data.get("domain_age_days"),
        status=data.get("status"),
        source=data.get("source", "mock")
    )

@router.get("/{domain}/age")
async def get_domain_age(domain: str):
    """Get just the domain age in days"""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    
    data = analyze_domain_age(domain)
    
    return {
        "domain": domain,
        "domain_age_days": data.get("domain_age_days"),
        "source": data.get("source", "mock")
    }

@router.get("/{domain}/registrar")
async def get_registrar(domain: str):
    """Get registrar information"""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    
    data = analyze_domain_age(domain)
    
    return {
        "domain": domain,
        "registrar": data.get("registrar"),
        "registered": data.get("registered"),
        "expires": data.get("expires"),
        "source": data.get("source", "mock")
    }