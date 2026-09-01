"""Structured, safe observability for evidence scans.

Emits one JSON object per event via the stdlib logger so logs stay
grep-able, machine-readable and testable (caplog). Fields are deliberately
restricted: never log API keys, authorization headers, response bodies,
passwords or credentials. Only the normalized hostname is logged, never a raw
URL (which can embed userinfo).
"""

import json
import logging

logger = logging.getLogger("wts.evidence")

_LOG_RECORD_KEYS = ("scan_id", "domain", "mode", "event")


def _emit(scan_id: str, domain: str, mode: str, event: str, level: int, **fields):
    record = {
        "scan_id": scan_id,
        "domain": domain,
        "mode": mode,
        "event": event,
    }
    record.update(fields)
    logger.log(level, json.dumps(record, sort_keys=True))


def log_collector(
    scan_id: str,
    domain: str,
    mode: str,
    collector: str,
    duration_ms: float,
    outcome: str,
    evidence_count: int,
    level: int = logging.INFO,
) -> None:
    """Log the outcome of one evidence collector.

    ``outcome`` is one of: success, unavailable, timeout, rate_limited,
    unauthorized, invalid, error, disabled, ssrf_rejected, dns_failed,
    private_ip_rejected, redirect_rejected.
    """
    _emit(
        scan_id,
        domain,
        mode,
        "collector",
        level,
        collector=collector,
        duration_ms=round(float(duration_ms), 1),
        outcome=outcome,
        evidence_count=int(evidence_count),
    )


def log_scan_result(
    scan_id: str,
    domain: str,
    mode: str,
    duration_ms: float,
    score: float,
    category: str,
    confidence: float,
    usable_categories: int,
) -> None:
    """Log the final evidence-mode result for a scan."""
    _emit(
        scan_id,
        domain,
        mode,
        "scan_result",
        logging.INFO,
        duration_ms=round(float(duration_ms), 1),
        score=score,
        category=category,
        confidence=confidence,
        usable_categories=int(usable_categories),
    )
