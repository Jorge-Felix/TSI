"""Tests de la Capa 5 — output_parser."""
from pipeline import output_parser


ANALYSIS_RESULT_KEYS = {
    "sample", "behavior_summary", "malware_family", "threat_category",
    "ttps", "narrative", "iocs", "analysis_cost_usd", "analysis_time_s",
}


def test_analysis_result_contract(claude_response):
    result = output_parser.parse(claude_response)
    assert ANALYSIS_RESULT_KEYS <= set(result.keys())


def test_extracts_json_fields(claude_response):
    result = output_parser.parse(claude_response)
    assert result["malware_family"] == "Remcos RAT (probable)"
    assert result["threat_category"] == "RAT"
    assert "RAT" in result["behavior_summary"]


def test_extracts_ttps_with_mitre_ids(claude_response):
    result = output_parser.parse(claude_response)
    assert len(result["ttps"]) == 2
    techniques = [t["technique"] for t in result["ttps"]]
    assert any("T1547.001" in t for t in techniques)
    assert any("T1071" in t for t in techniques)


def test_extracts_ioc_table(claude_response):
    result = output_parser.parse(claude_response)
    assert len(result["iocs"]) == 3
    values = [i["value"] for i in result["iocs"]]
    assert "185.234.10.10" in values
    assert "evil-c2.com" in values


def test_extracts_narrative(claude_response):
    result = output_parser.parse(claude_response)
    assert "RAT" in result["narrative"]
    assert "|" not in result["narrative"]  # la tabla no se cuela en la narrativa


def test_metrics_passthrough(claude_response):
    result = output_parser.parse(claude_response,
                                 {"cost_usd": 0.0123, "response_time_s": 4.5})
    assert result["analysis_cost_usd"] == 0.0123
    assert result["analysis_time_s"] == 4.5


def test_malformed_json_fallback():
    raw = '''```json
{ "malware_family": "AgentTesla", "threat_category": "Infostealer", broken
```
Narrativa breve.

| Tipo | Valor | Confianza | Contexto |
|------|-------|-----------|----------|
| IP | 1.2.3.4 | Alta | C2 |
'''
    result = output_parser.parse(raw)
    assert result["malware_family"] == "AgentTesla"  # regex fallback
    assert len(result["iocs"]) == 1


def test_no_json_block_at_all():
    result = output_parser.parse("Respuesta sin estructura alguna.")
    assert result["malware_family"] == "Unknown"
    assert result["iocs"] == []
