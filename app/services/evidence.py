"""Conservative, additive RDAP evidence evaluation for the analyzer.

Rules (all objective, bounded, never based on domain-name patterns):

- RDAP unavailable -> no effect on the score.
- Missing RDAP data -> no effect on the score.
- Old domain age -> small positive signal.
- Very young domain -> small negative signal.
- Registry/registrar hold states -> small negative signal.
- Registrar and nameservers are informational only and never affect score.

The RDAP contribution is tightly bounded so it can never dominate the
existing analyzer.
"""

from typing import Any, Dict, List

from app.models.evidence import EvidenceItem

MAX_SCORE_DELTA = 10

# Registry/registrar states indicating the domain is not in normal operation.
HOLD_STATUSES = {
    "clienthold",
    "serverhold",
    "redemptionperiod",
    "pendingdelete",
}

OLD_DOMAIN_DAYS = 3650  # 10 years
YOUNG_DOMAIN_DAYS = 30  # 30 days


def evaluate_rdap_evidence(rdap: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate RDAP evidence conservatively.

    Accepts the normalized dict produced by ``app.services.rdap.rdap_lookup``
    and returns ``{score_delta, red_flags, green_flags}``.
    """
    score_delta = 0
    red_flags: List[str] = []
    green_flags: List[str] = []

    if rdap.get("source") != "rdap":
        return {"score_delta": 0, "red_flags": [], "green_flags": []}

    status = [str(s).lower() for s in (rdap.get("status") or [])]
    hold_states = sorted(s for s in status if s in HOLD_STATUSES)
    if hold_states:
        score_delta -= 5
        red_flags.append(
            "Domain is in a registry/registrar suspension state "
            f"({', '.join(hold_states)})."
        )

    age_days = rdap.get("domain_age_days")
    if isinstance(age_days, int) and age_days >= 0:
        if age_days >= OLD_DOMAIN_DAYS:
            score_delta += 5
            green_flags.append(
                f"Well-established domain (over {OLD_DOMAIN_DAYS // 365} years old)."
            )
        elif age_days < YOUNG_DOMAIN_DAYS:
            score_delta -= 5
            red_flags.append(
                f"Domain registered recently ({age_days} days ago)."
            )

    # Bound the RDAP contribution tightly.
    score_delta = max(-MAX_SCORE_DELTA, min(MAX_SCORE_DELTA, score_delta))

    return {
        "score_delta": score_delta,
        "red_flags": red_flags,
        "green_flags": green_flags,
    }


def format_domain_age(days: int) -> str:
    """Human-readable age string from a number of days."""
    if days < 30:
        return f"{days} day{'s' if days != 1 else ''}"
    if days < 365:
        months = days // 30
        return f"{months} month{'s' if months != 1 else ''}"
    years, remainder = divmod(days, 365)
    months = remainder // 30
    base = f"{years} year{'s' if years != 1 else ''}"
    if months:
        base += f", {months} month{'s' if months != 1 else ''}"
    return base


def rdap_evidence_items(rdap: Dict[str, Any]) -> List[EvidenceItem]:
    """Convert a normalized RDAP result into EvidenceItems (Phase 2a).

    Only real observations produce items:

    - ``domain_age`` item when a valid age is present (+5 / -5 / 0).
    - ``domain_status`` item only when a hold/suspension state is present (-5).

    Missing age, missing status and ``source != rdap`` produce no items, so
    the engine scores them as neutral. Multiple hold statuses emit a single
    -5 item (they do not stack).
    """
    items: List[EvidenceItem] = []
    if not rdap or rdap.get("source") != "rdap":
        return items

    age_days = rdap.get("domain_age_days")
    if isinstance(age_days, int) and age_days >= 0:
        if age_days >= OLD_DOMAIN_DAYS:
            effect = 5.0
        elif age_days < YOUNG_DOMAIN_DAYS:
            effect = -5.0
        else:
            effect = 0.0
        items.append(
            EvidenceItem(
                id="RDAP_001",
                category="domain",
                signal="domain_age",
                value=age_days,
                effect=effect,
                confidence=1.0,
                source="rdap",
                explanation=f"Domain age is {format_domain_age(age_days)}.",
            )
        )

    status = [str(s).lower() for s in (rdap.get("status") or [])]
    hold_states = sorted(s for s in status if s in HOLD_STATUSES)
    if hold_states:
        items.append(
            EvidenceItem(
                id="RDAP_002",
                category="domain",
                signal="domain_status",
                value=hold_states,
                effect=-5.0,
                confidence=1.0,
                source="rdap",
                explanation=(
                    "Domain is in a registry/registrar suspension state "
                    f"({', '.join(hold_states)})."
                ),
            )
        )

    return items
