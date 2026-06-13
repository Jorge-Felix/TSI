"""Tests del ingestor de VirusTotal (Capa 1)."""
from pipeline import report_ingestor


REPORT_MODEL_KEYS = {
    "source", "sample_hash", "filename", "platform", "score",
    "processes", "network", "filesystem", "registry", "signatures", "raw_syscalls",
}


def test_vt_produces_full_contract(virustotal_behaviour, virustotal_file_info):
    report = report_ingestor.parse_virustotal(
        virustotal_behaviour, virustotal_file_info)
    assert REPORT_MODEL_KEYS <= set(report.keys())
    assert report["source"] == "virustotal"


def test_vt_metadata_from_file_info(virustotal_behaviour, virustotal_file_info):
    report = report_ingestor.parse_virustotal(
        virustotal_behaviour, virustotal_file_info)
    assert report["filename"] == "malware.exe"
    assert report["sample_hash"].startswith("abc123def456")
    # score = malicious / total * 100 = 58 / 70 -> 83
    assert report["score"] == 83


def test_vt_flattens_process_tree(virustotal_behaviour):
    report = report_ingestor.parse_virustotal(virustotal_behaviour)
    pids = {p["pid"] for p in report["processes"]}
    assert "1234" in pids and "2345" in pids
    child = next(p for p in report["processes"] if p["pid"] == "2345")
    assert child["ppid"] == "1234"  # ppid heredado del padre en el árbol


def test_vt_marks_injection(virustotal_behaviour):
    report = report_ingestor.parse_virustotal(virustotal_behaviour)
    injected = next(p for p in report["processes"]
                    if p["image"].endswith("malware.exe"))
    assert injected["injects"] is True


def test_vt_command_executions_become_processes(virustotal_behaviour):
    report = report_ingestor.parse_virustotal(virustotal_behaviour)
    cmds = [p["command_line"] for p in report["processes"]]
    assert any("-enc" in c for c in cmds)  # comando ofuscado preservado


def test_vt_network(virustotal_behaviour):
    report = report_ingestor.parse_virustotal(virustotal_behaviour)
    assert "evil-c2.com" in report["network"]["domains"]
    assert "185.234.10.10" in report["network"]["ips"]
    assert report["network"]["http"][0]["url"] == "http://evil-c2.com/gate.php"
    assert report["network"]["connections"][0]["port"] == 4782


def test_vt_filesystem_includes_dropped(virustotal_behaviour):
    report = report_ingestor.parse_virustotal(virustotal_behaviour)
    paths = [f["path"] for f in report["filesystem"]]
    assert any("svc.exe" in p for p in paths)
    assert any("payload.dll" in p for p in paths)


def test_vt_registry(virustotal_behaviour):
    report = report_ingestor.parse_virustotal(virustotal_behaviour)
    keys = [r["key"] for r in report["registry"]]
    assert any("CurrentVersion\\Run" in k for k in keys)


def test_vt_mitre_techniques_as_signatures(virustotal_behaviour):
    report = report_ingestor.parse_virustotal(virustotal_behaviour)
    names = [s["name"] for s in report["signatures"]]
    assert any("T1055" in n for n in names)
    assert any("T1547.001" in n for n in names)


def test_vt_handles_data_wrapper(virustotal_behaviour):
    """El parser debe aceptar la respuesta envuelta en {"data": {...}}."""
    wrapped = {"data": {"attributes": virustotal_behaviour}}
    report = report_ingestor.parse_virustotal(wrapped)
    assert len(report["processes"]) > 0


def test_vt_detect_format(virustotal_behaviour):
    assert report_ingestor._detect_format(virustotal_behaviour) == "virustotal"
    wrapped = {"data": {"attributes": virustotal_behaviour}}
    assert report_ingestor._detect_format(wrapped) == "virustotal"


def test_vt_missing_file_info(virustotal_behaviour):
    """Sin file_info el parser sigue funcionando (score 0, hash del sha256)."""
    report = report_ingestor.parse_virustotal(virustotal_behaviour, sha256="aabbcc")
    assert report["sample_hash"] == "aabbcc"
    assert report["score"] == 0
    assert len(report["processes"]) > 0
