"""Typed evidence model for the deterministic scoring engine.

EvidenceItems are produced by collectors/adapters and consumed by
``app.services.scoring.evaluate_evidence``. They carry facts and a signed
effect (delta to the neutral score) that is applied deterministically.

The engine never invents facts: an adapter emits an item only for a real
observation. Missing data or unavailable providers simply produce no item,
which is scored as neutral.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    id: str
    category: str
    signal: str
    value: Optional[Any] = None
    effect: float = Field(ge=-100.0, le=100.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str
    explanation: Optional[str] = None
    expected: bool = False


class ScoreResult(BaseModel):
    score: float
    confidence: float
    category: str
    risk_level: str
    positive_signals: List[str] = Field(default_factory=list)
    negative_signals: List[str] = Field(default_factory=list)
    applied_evidence: List[EvidenceItem] = Field(default_factory=list)
    category_contributions: Dict[str, float] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)
