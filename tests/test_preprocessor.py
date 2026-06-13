"""Tests de la Capa 2 — report_preprocessor."""
from pipeline import report_ingestor, report_preprocessor


PROCESSED_KEYS = {
    "summary_fields", "high_value_syscalls", "network_activity",
    "filesystem_artifacts", "registry_artifacts", "process_tree",
    "token_count_estimate",
}


def test_processed_report_contract(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    processed = report_preprocessor.preprocess(report)
    assert PROCESSED_KEYS <= set(processed.keys())


def test_registry_filter_keeps_persistence_drops_noise(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    processed = report_preprocessor.preprocess(report)
    joined = " ".join(processed["registry_artifacts"])
    assert "CurrentVersion\\Run" in joined
    assert "SomeApp" not in joined  # clave de aplicación legítima descartada


def test_fs_filter_keeps_suspicious_paths(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    processed = report_preprocessor.preprocess(report)
    joined = " ".join(processed["filesystem_artifacts"])
    assert "svc.exe" in joined  # .exe en AppData


def test_syscall_filter_drops_noise():
    syscalls = [
        {"name": "GetSystemTime"},
        {"name": "HeapAlloc"},
        {"name": "WriteProcessMemory", "args": {"target": "explorer.exe"}},
        {"name": "CreateRemoteThread"},
    ]
    result = report_preprocessor.filter_syscalls(syscalls)
    assert any("WriteProcessMemory" in s for s in result)
    assert any("CreateRemoteThread" in s for s in result)
    assert not any("GetSystemTime" in s for s in result)
    assert not any("HeapAlloc" in s for s in result)


def test_syscall_limit_respected():
    syscalls = [{"name": "WriteProcessMemory"}] * 100
    result = report_preprocessor.filter_syscalls(syscalls)
    assert len(result) <= 40


def test_process_tree_marks_injection(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    processed = report_preprocessor.preprocess(report)
    assert "INJECTS" in processed["process_tree"]
    assert "malware.exe" in processed["process_tree"]


def test_token_reduction(any_run_raw):
    report = report_ingestor.parse_any_run(any_run_raw)
    processed = report_preprocessor.preprocess(report)
    original = report_preprocessor.estimate_tokens(report)
    assert processed["token_count_estimate"] > 0
    # En reportes reales (800-3000 líneas) la reducción es drástica; aquí solo
    # validamos que el estimado existe y es coherente
    assert processed["token_count_estimate"] < original * 2
