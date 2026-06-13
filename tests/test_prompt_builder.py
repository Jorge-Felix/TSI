"""Tests de la Capa 3 — prompt_builder."""
from pipeline import prompt_builder, report_ingestor, report_preprocessor


def _processed(any_run_raw):
    return report_preprocessor.preprocess(report_ingestor.parse_any_run(any_run_raw))


def test_system_prompt_loads_and_has_attack_vocabulary():
    prompt = prompt_builder.load_system_prompt()
    assert "MITRE ATT&CK" in prompt
    assert "TA0003" in prompt
    assert "T1547" in prompt


def test_system_prompt_forces_three_sections():
    prompt = prompt_builder.load_system_prompt()
    assert "SECCIÓN 1" in prompt
    assert "SECCIÓN 2" in prompt
    assert "SECCIÓN 3" in prompt


def test_user_message_contains_report_data(any_run_raw):
    _, user_message = prompt_builder.build_prompt(_processed(any_run_raw))
    assert "malware.exe" in user_message
    assert "evil-c2.com" in user_message
    assert "95/100" in user_message


def test_build_prompt_returns_both_parts(any_run_raw):
    system_prompt, user_message = prompt_builder.build_prompt(_processed(any_run_raw))
    assert len(system_prompt) > 500
    assert len(user_message) > 100


def test_token_budget_truncation(any_run_raw):
    processed = _processed(any_run_raw)
    processed["high_value_syscalls"] = [f"Syscall{i}(args)" for i in range(40)]
    processed["token_count_estimate"] = 999_999  # fuerza el modo truncado
    _, user_message = prompt_builder.build_prompt(processed)
    # tras truncar, máximo 20 syscalls en el mensaje
    assert user_message.count("Syscall") <= 20
