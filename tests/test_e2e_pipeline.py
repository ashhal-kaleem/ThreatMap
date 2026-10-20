"""
End-to-End Pipeline & Integration Tests for ThreatMap Lite.
Verifies the complete automated workflow:
PDF upload -> text extraction -> IOC extraction & normalization -> DB persistence -> REST API query -> cascade deletion.
"""

import io
from pathlib import Path
import fitz  # PyMuPDF
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database import Base, SessionLocal, engine
from backend.app.models.db_models import Report, ReportPage, IOC


@pytest.fixture(scope="module")
def client():
    # Setup database tables
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
    # Cleanup


def create_mock_threat_pdf() -> bytes:
    """Creates an in-memory PDF containing defanged threat indicators across pages."""
    doc = fitz.open()

    # Page 1: C2 and network indicators
    p1 = doc.new_page()
    p1.insert_text(
        (50, 72),
        "Threat Advisory: APT-Test Intrusions\n"
        "C2 communication observed connecting to 185.141.63.25 on port 443.\n"
        "Actors beaconed to hxxps://malicious-command[.]org/gate.php\n"
        "Reconnaissance probed victim-portal[.]net.\n"
    )

    # Page 2: Malware drops and hashes
    p2 = doc.new_page()
    p2.insert_text(
        (50, 72),
        "Malware Samples Recovered:\n"
        "Backdoor dropped via CVE-2023-38606 vulnerability.\n"
        "Payload MD5: 5d41402abc4b2a76b9719d911017c592\n"
        "Stager SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    )

    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "threatmap-lite-backend"


def test_upload_invalid_non_pdf(client):
    # Upload plain text without %PDF- magic bytes
    files = {"file": ("malicious.txt", b"This is not a PDF file", "text/plain")}
    response = client.post("/reports/upload", files=files)
    assert response.status_code == 400
    assert "missing %PDF- magic bytes" in response.json()["detail"]


def test_e2e_upload_and_extraction_workflow(client):
    pdf_bytes = create_mock_threat_pdf()
    files = {"file": ("apt_test_advisory.pdf", pdf_bytes, "application/pdf")}

    # 1. Upload PDF
    upload_resp = client.post("/reports/upload", files=files)
    assert upload_resp.status_code == 201
    upload_data = upload_resp.json()
    report_id = upload_data["report_id"]
    assert upload_data["status"] == "complete"

    # 2. Poll Status
    status_resp = client.get(f"/reports/{report_id}/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "complete"
    assert status_resp.json()["current_step"] == "complete"
    assert status_resp.json()["error_msg"] is None

    # 3. Query IOCs
    iocs_resp = client.get(f"/reports/{report_id}/iocs")
    assert iocs_resp.status_code == 200
    iocs = iocs_resp.json()
    assert len(iocs) >= 6

    # Verify extracted IOC types and values
    values_by_type = {i["type"]: [] for i in iocs}
    for i in iocs:
        values_by_type[i["type"]].append(i["value"])

    # Refanged IPv4
    assert "185.141.63.25" in values_by_type.get("ipv4", [])
    # Refanged URL
    assert "https://malicious-command.org/gate.php" in values_by_type.get("url", [])
    # Refanged Domain
    assert "victim-portal.net" in values_by_type.get("domain", [])
    # CVE
    assert "CVE-2023-38606" in values_by_type.get("cve", [])
    # Hashes
    assert "5d41402abc4b2a76b9719d911017c592" in values_by_type.get("md5", [])
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in values_by_type.get("sha256", [])

    # Check page accuracy
    ipv4_ioc = next(i for i in iocs if i["value"] == "185.141.63.25")
    assert ipv4_ioc["source_page"] == 1
    assert "185.141.63.25" in ipv4_ioc["evidence"]

    cve_ioc = next(i for i in iocs if i["value"] == "CVE-2023-38606")
    assert cve_ioc["source_page"] == 2
    assert "CVE-2023-38606" in cve_ioc["evidence"]

    # 4. Query Consolidated Results
    results_resp = client.get(f"/reports/{report_id}/results")
    assert results_resp.status_code == 200
    results = results_resp.json()
    assert results["report_id"] == report_id
    assert results["page_count"] == 2
    assert results["ioc_summary"]["ipv4"] == 1
    assert results["ioc_summary"]["url"] == 1
    assert results["ioc_summary"]["domain"] == 2
    assert results["ioc_summary"]["cve"] == 1
    assert results["ioc_summary"]["md5"] == 1
    assert results["ioc_summary"]["sha256"] == 1

    # 5. List Reports
    list_resp = client.get("/reports")
    assert list_resp.status_code == 200
    reports_list = list_resp.json()
    assert any(r["id"] == report_id for r in reports_list)

    # 6. Delete Report
    del_resp = client.delete(f"/reports/{report_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # Confirm not found after deletion
    after_resp = client.get(f"/reports/{report_id}/status")
    assert after_resp.status_code == 404
