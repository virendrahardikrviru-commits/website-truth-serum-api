from unittest import mock

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


CANNED_RDAP = {
    "domain": "example.com",
    "registered": "1995-08-14",
    "expires": "2027-08-13",
    "updated": "2023-07-20",
    "registrar": "GoDaddy.com, LLC",
    "nameservers": ["ns1.example.com"],
    "domain_age_days": 1234,
    "status": ["ok"],
    "source": "rdap",
    "notes": [],
}


def test_domain_intel_success():
    with mock.patch(
        "app.routers.domain_intel.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=CANNED_RDAP,
    ):
        resp = client.get("/api/domain-intel/example.com")

    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["source"] == "rdap"
    assert data["registered"] == "1995-08-14"
    assert data["expires"] == "2027-08-13"
    assert data["updated"] == "2023-07-20"
    assert data["registrar"] == "GoDaddy.com, LLC"
    assert data["nameservers"] == ["ns1.example.com"]
    assert data["domain_age_days"] == 1234
    assert data["status"] == ["ok"]


def test_domain_intel_unavailable_fields():
    unavailable = dict(CANNED_RDAP)
    unavailable.update(
        {
            "registered": None,
            "expires": None,
            "updated": None,
            "registrar": None,
            "nameservers": [],
            "domain_age_days": None,
            "status": [],
        }
    )
    with mock.patch(
        "app.routers.domain_intel.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=unavailable,
    ):
        resp = client.get("/api/domain-intel/example.com")

    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "rdap"
    assert data["registered"] is None
    assert data["domain_age_days"] is None
    assert data["nameservers"] == []
    assert data["status"] == []


def test_domain_intel_invalid_domain_rejected():
    resp = client.get("/api/domain-intel/localhost")
    assert resp.status_code == 400
    resp = client.get("/api/domain-intel/192.168.1.1")
    assert resp.status_code == 400


def test_domain_intel_rdap_unavailable_source():
    unavailable = dict(CANNED_RDAP)
    unavailable.update(
        {
            "source": "rdap_unavailable",
            "registered": None,
            "domain_age_days": None,
            "notes": ["RDAP request timed out."],
        }
    )
    with mock.patch(
        "app.routers.domain_intel.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=unavailable,
    ):
        resp = client.get("/api/domain-intel/example.com")

    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "rdap_unavailable"
    assert data["registered"] is None
    assert "RDAP request timed out." in (data["notes"] or [])


def test_domain_age_endpoint_uses_rdap():
    with mock.patch(
        "app.routers.domain_intel.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=CANNED_RDAP,
    ):
        resp = client.get("/api/domain-intel/example.com/age")

    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["domain_age_days"] == 1234
    assert data["source"] == "rdap"


def test_registrar_endpoint_uses_rdap():
    with mock.patch(
        "app.routers.domain_intel.rdap_lookup",
        new_callable=mock.AsyncMock,
        return_value=CANNED_RDAP,
    ):
        resp = client.get("/api/domain-intel/example.com/registrar")

    assert resp.status_code == 200
    data = resp.json()
    assert data["registrar"] == "GoDaddy.com, LLC"
    assert data["source"] == "rdap"
