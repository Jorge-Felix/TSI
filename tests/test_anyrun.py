"""Tests del adjunto opcional ANY.RUN (anyrun_report)."""
from pipeline import anyrun_report, prompt_builder


def test_filter_keeps_relevant_drops_boilerplate():
    text = "\n".join([
        "Copyright 2024 todos los derechos reservados",
        "Home About Contact page",
        "Suscribete a nuestro newsletter hoy",
        "Process svchost.exe spawned malware.exe",
        "Network connection to 185.234.10.10:4782",
        "Registry key HKCU Run modified",
    ])
    out = anyrun_report._filter_relevant(text)
    assert "svchost.exe" in out
    assert "185.234.10.10" in out
    assert "Run modified" in out
    assert "Copyright" not in out
    assert "newsletter" not in out


def test_filter_keeps_ioc_lines_without_keyword():
    text = "encabezado aleatorio\n8.8.8.8\nabcdef0123456789abcdef0123456789ab"
    out = anyrun_report._filter_relevant(text)
    assert "8.8.8.8" in out
    assert "abcdef0123456789abcdef0123456789ab" in out
    assert "encabezado aleatorio" not in out


def test_cap_tokens_truncates():
    big = "linea con ip 1.2.3.4\n" * 5000
    capped = anyrun_report._cap_tokens(big, 100)
    assert len(capped) <= 100 * 4 + 80
    assert "truncado" in capped


def test_extract_context_txt(tmp_path):
    p = tmp_path / "anyrun.txt"
    p.write_text("Proceso malicioso ejecuta powershell -enc\n"
                 "Conexion de red a evil-c2.com\npie de pagina legal",
                 encoding="utf-8")
    ctx = anyrun_report.extract_context(str(p))
    assert ctx is not None
    assert "powershell" in ctx
    assert "evil-c2.com" in ctx


def test_extract_context_html(tmp_path):
    p = tmp_path / "anyrun.html"
    p.write_text("<html><head><style>x{}</style></head><body>"
                 "<script>bad_func()</script>"
                 "<p>Malicious process injects into explorer.exe</p>"
                 "<p>C2 domain evil.ru</p></body></html>", encoding="utf-8")
    ctx = anyrun_report.extract_context(str(p))
    assert ctx is not None
    assert "explorer.exe" in ctx
    assert "evil.ru" in ctx
    assert "bad_func" not in ctx  # <script> eliminado


def test_extract_context_missing_file():
    assert anyrun_report.extract_context("no_existe_xyz.pdf") is None


def test_extract_context_empty(tmp_path):
    p = tmp_path / "empty.txt"
    p.write_text("   \n  \n", encoding="utf-8")
    assert anyrun_report.extract_context(str(p)) is None


def test_prompt_anyrun_section():
    text = "\n".join(prompt_builder._build_anyrun_section("Proceso malicioso detectado"))
    assert "CONTEXTO ADICIONAL" in text
    assert "ANY.RUN" in text
    assert "Proceso malicioso detectado" in text
    assert "VirusTotal" in text  # deja claro que ANY.RUN es solo apoyo


def test_prompt_anyrun_section_empty():
    assert prompt_builder._build_anyrun_section(None) == []
    assert prompt_builder._build_anyrun_section("") == []
