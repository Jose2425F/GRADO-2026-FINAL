"""Alcance e identidad de hallazgos coherentes sin ejecutar adaptadores."""
import copy
import json

from auditoria.modulo_reportes import finding_identifier, prepare_report, report_scope, save_report


def sample():
    attempt = "ab" * 16
    return {
        "audit_id": "report_fixture", "mode": "live", "status": "partial",
        "architecture": "single", "operator": "Operador sintético",
        "authorization_ref": "LAB-PROPIO", "llm": {"status": "disabled", "model": None},
        "note": "Únicamente el banco sintético; no acredita otros activos.",
        "findings": [{"asset_id": "portal", "address": "192.0.2.10",
            "defect_key": "ssh_default_credential", "condition": "ssh_default_credential",
            "title": "Acceso SSH corroborado", "state": "verified", "severity": "high",
            "task_id": "report_fixture_ssh", "evidence_ref": "evidence/access.json",
            "confirmation_ref": "evidence/confirmation.json", "reference": "CWE-1392",
            "remediation": "Rotar y verificar la credencial."}],
        "tasks": [{"task_id": "report_fixture_scan", "attempt_id": attempt,
            "status": "completed_no_findings", "reason_code": None,
            "evidence_ref": "evidence/scan.xml", "diagnostic_ref": None},
            {"task_id": "report_fixture_blocked", "attempt_id": None, "status": "blocked",
             "reason_code": "credential_service_not_discovered", "evidence_ref": None}],
        "inventory": [{"asset_id": "portal", "address": "192.0.2.10",
            "discovery_tasks": [{"task_id": "report_fixture_scan", "attempt_id": attempt,
                                 "evidence_ref": "evidence/scan.xml"}],
            "services": [{"port": 22, "protocol": "tcp", "state": "open", "name": "ssh"}]},
            {"asset_id": "control", "address": "2001:db8::20", "discovery_tasks": [], "services": []}],
        "validation": [{"task_id": "report_fixture_scan", "case_id": None}],
    }


def request():
    return {"bank": "empresa", "authorization_ref": "LAB-PROPIO",
        "scope_ipv4": ["192.0.2.0/24"], "scope_ipv6": ["2001:db8::/64"],
        "targets": [{"asset_id": "portal", "address": "192.0.2.10", "interface": "lab0",
                     "ports": [22], "credential_ref": "PRIVATE_REF", "credential_refs": ["PRIVATE_REF"]}],
        "sessions": {"private": "PRIVATE_SESSION"}}


def test_identifier_is_stable_per_asset_condition_and_preserves_existing_id():
    finding = sample()["findings"][0]
    assert finding_identifier(finding) == "portal:ssh_default_credential"
    assert finding_identifier({**finding, "task_id": "another_audit_task", "address": "192.0.2.11"}) == finding_identifier(finding)
    assert finding_identifier({**finding, "asset_id": "different"}) != finding_identifier(finding)
    assert finding_identifier({**finding, "defect_key": "ftp_default_credential"}) != finding_identifier(finding)
    assert finding_identifier({**finding, "finding_id": "existing-public-id"}) == "existing-public-id"


def test_scope_whitelists_public_request_and_personal_configuration():
    scope = report_scope(request())
    assert scope["ipv4"] == ["192.0.2.0/24"]
    assert scope["targets"][0]["address"] == "192.0.2.10"
    assert "PRIVATE_" not in json.dumps(scope)
    personal = report_scope({"bank": "personal", "authorization_ref": "LAB-PROPIO",
        "personal": {"ipv4": "192.0.2.1,192.0.2.2", "ipv6": "2001:db8::1",
                     "interface": "lab0", "ports": [443]}, "applications": [{"session": "PRIVATE_SESSION"}]})
    assert personal["ipv4"] == ["192.0.2.1", "192.0.2.2"]
    assert personal["ipv6"] == ["2001:db8::1"]
    assert "PRIVATE_" not in json.dumps(personal)


def test_projection_is_non_destructive_and_does_not_invent_historical_scope():
    source = sample();before = copy.deepcopy(source)
    projected = prepare_report(source, request())
    assert source == before
    assert projected["findings"][0]["finding_id"] == "portal:ssh_default_credential"
    assert projected["tasks"] == source["tasks"]
    assert "scope" not in prepare_report(source)
    assert projected["limitations"] == [source["note"]]


def test_json_html_pdf_keep_scope_findings_attempts_and_discovery_links(tmp_path, monkeypatch):
    from reportlab.platypus import SimpleDocTemplate
    captured = []
    original_build = SimpleDocTemplate.build
    def capture(document, flowables, *args, **kwargs):
        for flowable in flowables:
            if hasattr(flowable, "getPlainText"):
                captured.append(flowable.getPlainText())
            for row in getattr(flowable, "_cellvalues", []):
                for cell in row:
                    if hasattr(cell, "getPlainText"):
                        captured.append(cell.getPlainText())
        return original_build(document, flowables, *args, **kwargs)
    monkeypatch.setattr(SimpleDocTemplate, "build", capture)
    source = sample();projected = prepare_report(source, request())
    before = copy.deepcopy(projected)
    save_report(tmp_path, projected)
    assert projected == before
    persisted = json.loads((tmp_path / "report.json").read_text())
    html = (tmp_path / "report.html").read_text()
    pdf_text = "\n".join(captured)
    for text in ["portal:ssh_default_credential", "192.0.2.0/24", "2001:db8::/64",
                 "192.0.2.10", "2001:db8::20", "report_fixture_scan", "ab" * 16, "evidence/scan.xml",
                 "credential_service_not_discovered", source["note"]]:
        assert text in json.dumps(persisted, ensure_ascii=False)
        assert text in html
        assert text in pdf_text
    assert persisted["scope"] == report_scope(request())
    assert "PRIVATE_" not in html + pdf_text + json.dumps(persisted)
    assert (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF-")
    assert "Gemini:" not in html


def test_html_escapes_provided_identifier_and_keeps_legacy_inventory(tmp_path):
    report = sample();report["findings"][0]["finding_id"] = "<script>alert(1)</script>"
    report["inventory"] = [{"task_id": "legacy_scan", "services": [{"port": 22, "protocol": "tcp", "name": "ssh"}]}]
    save_report(tmp_path, report)
    html = (tmp_path / "report.html").read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "legacy_scan" in html
    assert "El alcance no se consolidó" in html
