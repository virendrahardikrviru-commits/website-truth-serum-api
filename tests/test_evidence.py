from app.services.evidence import (
    MAX_SCORE_DELTA,
    evaluate_rdap_evidence,
    format_domain_age,
)


def test_rdap_unavailable_is_neutral():
    ev = evaluate_rdap_evidence(
        {
            "domain": "example.com",
            "registered": None,
            "domain_age_days": None,
            "status": [],
            "source": "rdap_unavailable",
            "notes": ["RDAP request timed out."],
        }
    )
    assert ev["score_delta"] == 0
    assert ev["red_flags"] == []
    assert ev["green_flags"] == []


def test_missing_rdap_fields_is_neutral():
    ev = evaluate_rdap_evidence(
        {
            "domain": "example.com",
            "registered": None,
            "expires": None,
            "updated": None,
            "registrar": None,
            "nameservers": [],
            "domain_age_days": None,
            "status": [],
            "source": "rdap",
            "notes": ["RDAP did not provide a registration date."],
        }
    )
    assert ev["score_delta"] == 0
    assert ev["red_flags"] == []
    assert ev["green_flags"] == []


def test_old_domain_small_positive():
    ev = evaluate_rdap_evidence(
        {"domain": "example.com", "domain_age_days": 4000, "status": [], "source": "rdap"}
    )
    assert ev["score_delta"] == 5
    assert ev["green_flags"]
    assert not ev["red_flags"]


def test_very_young_domain_small_negative():
    ev = evaluate_rdap_evidence(
        {"domain": "example.com", "domain_age_days": 10, "status": [], "source": "rdap"}
    )
    assert ev["score_delta"] == -5
    assert ev["red_flags"]
    assert not ev["green_flags"]


def test_mid_age_domain_neutral():
    ev = evaluate_rdap_evidence(
        {"domain": "example.com", "domain_age_days": 500, "status": [], "source": "rdap"}
    )
    assert ev["score_delta"] == 0
    assert ev["red_flags"] == []
    assert ev["green_flags"] == []


def test_hold_status_negative_evidence():
    for state in ("clientHold", "serverHold", "redemptionPeriod", "pendingDelete"):
        ev = evaluate_rdap_evidence(
            {
                "domain": "example.com",
                "domain_age_days": 500,
                "status": [state],
                "source": "rdap",
            }
        )
        assert ev["score_delta"] < 0, state
        assert any("suspension" in f.lower() for f in ev["red_flags"]), state


def test_old_age_and_hold_cancel_within_bounds():
    ev = evaluate_rdap_evidence(
        {
            "domain": "example.com",
            "domain_age_days": 4000,
            "status": ["clientHold"],
            "source": "rdap",
        }
    )
    assert ev["score_delta"] == 0
    assert ev["red_flags"]
    assert ev["green_flags"]


def test_ok_status_no_signal():
    ev = evaluate_rdap_evidence(
        {"domain": "example.com", "domain_age_days": 500, "status": ["ok"], "source": "rdap"}
    )
    assert ev["score_delta"] == 0
    assert ev["red_flags"] == []
    assert ev["green_flags"] == []


def test_registrar_and_nameservers_do_not_affect_score():
    with_registrar = evaluate_rdap_evidence(
        {
            "domain": "example.com",
            "registrar": "GoDaddy.com, LLC",
            "nameservers": ["ns1.example.com"],
            "source": "rdap",
        }
    )
    without_registrar = evaluate_rdap_evidence(
        {
            "domain": "example.com",
            "registrar": None,
            "nameservers": [],
            "source": "rdap",
        }
    )
    assert with_registrar["score_delta"] == without_registrar["score_delta"] == 0
    assert with_registrar["red_flags"] == []
    assert with_registrar["green_flags"] == []


def test_score_delta_is_bounded():
    ev = evaluate_rdap_evidence(
        {
            "domain": "example.com",
            "domain_age_days": 5,
            "status": ["clientHold", "serverHold", "redemptionPeriod", "pendingDelete"],
            "source": "rdap",
        }
    )
    assert -MAX_SCORE_DELTA <= ev["score_delta"] <= MAX_SCORE_DELTA


def test_format_domain_age():
    assert format_domain_age(1) == "1 day"
    assert format_domain_age(5) == "5 days"
    assert format_domain_age(60) == "2 months"
    assert format_domain_age(800) == "2 years, 2 months"
    assert format_domain_age(3650) == "10 years"
