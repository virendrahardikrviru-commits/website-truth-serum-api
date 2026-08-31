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
