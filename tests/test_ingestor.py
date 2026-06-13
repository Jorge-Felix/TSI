"""Tests de la Capa 1 — report_ingestor."""
from pipeline import report_ingestor


REPORT_MODEL_KEYS = {
    "source", "sample_hash", "filename", "platform", "score",
    "processes", "network", "filesystem", "registry", "signatures", "raw_syscalls",
}


def test_any_run_produces_full_contract(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    assert REPORT_MODEL_KEYS <= set(report.keys())


def test_any_run_extracts_metadata(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    assert report["source"] == "any_run"
    assert report["filename"] == "malware.exe"
    assert report["sample_hash"].startswith("abc123def456")
    assert report["score"] == 95


def test_any_run_extracts_network(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    assert "evil-c2.com" in report["network"]["domains"]
    assert "185.234.10.10" in report["network"]["ips"]
    assert report["network"]["http"][0]["url"] == "http://evil-c2.com/gate.php"


def test_any_run_marks_injection(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    injector = next(p for p in report["processes"] if p["pid"] == 1234)
    assert injector["injects"] is True


def test_any_run_extracts_registry_and_fs(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    assert any("Run" in r["key"] for r in report["registry"])
    assert any("AppData" in f["path"] for f in report["filesystem"])


def test_triage_produces_full_contract(triage_raw):
    report = report_ingestor.parse_triage(triage_raw)
    assert REPORT_MODEL_KEYS <= set(report.keys())


def test_triage_normalizes_score_to_100(triage_raw):
    report = report_ingestor.parse_triage(triage_raw)
    assert report["score"] == 100  # 10 en escala triage -> 100


def test_triage_consolidates_iocs(triage_raw):
    report = report_ingestor.parse_triage(triage_raw)
    assert "evil-c2.com" in report["network"]["domains"]
    assert "185.234.10.10" in report["network"]["ips"]


def test_triage_family_in_signatures(triage_raw):
    report = report_ingestor.parse_triage(triage_raw)
    names = [s["name"] for s in report["signatures"]]
    assert any("remcos" in n for n in names)


def test_detect_format(any_run_raw, triage_raw):
    assert report_ingestor._detect_format(any_run_raw) == "any_run"
    assert report_ingestor._detect_format(triage_raw) == "triage"
