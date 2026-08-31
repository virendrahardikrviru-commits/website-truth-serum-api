from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from app.services.rdap import normalize_domain, rdap_lookup

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
    source: str  # 'rdap' or 'rdap_unavailable'
    notes: Optional[List[str]] = None  # RDAP limitations / unavailable fields


async def _domain_intel(domain: str) -> dict:
    """Fetch real RDAP intelligence for a domain and shape it for the API."""
    normalized = normalize_domain(domain)
    if normalized is None:
        raise HTTPException(status_code=400, detail="Invalid domain.")
    data = await rdap_lookup(normalized)
    return {
        "domain": normalized,
        "registered": data.get("registered"),
        "expires": data.get("expires"),
        "updated": data.get("updated"),
        "registrar": data.get("registrar"),
        "nameservers": data.get("nameservers") or [],
        "domain_age_days": data.get("domain_age_days"),
        "status": data.get("status") or [],
        "source": data.get("source", "rdap_unavailable"),
        "notes": data.get("notes") or None,
    }


# ============================================
# API Endpoints
# ============================================

@router.get("/{domain}", response_model=DomainIntelResponse)
async def get_domain_intelligence(domain: str):
    """
    Get real RDAP-based domain intelligence:
    - Registration date
    - Expiry date
    - Last updated date
    - Registrar
    - Nameservers
    - Domain status
    - Calculated domain age (from the RDAP registration date)
    """
    return await _domain_intel(domain)


@router.get("/{domain}/age")
async def get_domain_age(domain: str):
    """Get just the domain age in days (calculated from RDAP registration)."""
    normalized = normalize_domain(domain)
    if normalized is None:
        raise HTTPException(status_code=400, detail="Invalid domain.")
    data = await rdap_lookup(normalized)
    return {
        "domain": normalized,
        "domain_age_days": data.get("domain_age_days"),
        "source": data.get("source", "rdap_unavailable"),
    }


@router.get("/{domain}/registrar")
async def get_registrar(domain: str):
    """Get registrar information from RDAP."""
    normalized = normalize_domain(domain)
    if normalized is None:
        raise HTTPException(status_code=400, detail="Invalid domain.")
    data = await rdap_lookup(normalized)
    return {
        "domain": normalized,
        "registrar": data.get("registrar"),
        "registered": data.get("registered"),
        "expires": data.get("expires"),
        "source": data.get("source", "rdap_unavailable"),
    }
