"""Tests de la capa de enriquecimiento (abuse.ch) y su sección en el prompt."""
from pipeline import enrichment, prompt_builder


# ---------------------------------------------------- parsers abuse.ch ---

def test_malwarebazaar_parse(malwarebazaar_raw):
    mb = enrichment.parse_malwarebazaar(malwarebazaar_raw)
    assert mb["found"] is True
    assert mb["signature"] == "RedLineStealer"
    assert "RedLine" in mb["tags"]
    assert "win_redline_stealer" in mb["yara_rules"]
    assert "VirusTotal" in mb["vendor_intel"]


def test_malwarebazaar_not_found():
    mb = enrichment.parse_malwarebazaar({"query_status": "hash_not_found"})
    assert mb["found"] is False


def test_threatfox_parse(threatfox_raw):
    tf = enrichment.parse_threatfox(threatfox_raw)
    assert tf["found"] is True
    assert "RedLine Stealer" in tf["malware_families"]
    assert len(tf["iocs"]) == 2
    iocs = {i["ioc"] for i in tf["iocs"]}
    assert "evil-c2.com" in iocs
    assert "185.234.10.10:4782" in iocs


def test_threatfox_no_result():
    tf = enrichment.parse_threatfox({"query_status": "no_result", "data": []})
    assert tf["found"] is False


# ------------------------------------------------- pivote de IOCs (red) ---

def test_threatfox_ioc_parse(threatfox_ioc_raw):
    r = enrichment.parse_threatfox_ioc(threatfox_ioc_raw)
    assert r["found"] is True
    assert r["malware"] == "Mirai"
    assert r["threat_type"] == "botnet_cc"
    assert r["confidence"] == 100


def test_threatfox_ioc_no_result():
    assert enrichment.parse_threatfox_ioc({"query_status": "no_result"})["found"] is False


def test_urlhaus_host_parse(urlhaus_host_raw):
    r = enrichment.parse_urlhaus_host(urlhaus_host_raw)
    assert r["found"] is True
    assert r["url_count"] == 7
    assert "malware_download" in r["threats"]
    assert "mirai" in r["tags"]


def test_urlhaus_host_not_found():
    assert enrichment.parse_urlhaus_host({"query_status": "no_results"})["found"] is False


# ---------------------------------------------- degradación con gracia ---

def test_enrich_without_key(monkeypatch):
    """Sin Auth-Key, enrich() devuelve vacío sin lanzar ni llamar a la red."""
    monkeypatch.setattr("config.ABUSECH_AUTH_KEY", "")
    result = enrichment.enrich("abc123")
    assert result["available"] is False
    assert result["malware_bazaar"]["found"] is False


def test_enrich_without_hash(monkeypatch):
    monkeypatch.setattr("config.ABUSECH_AUTH_KEY", "fake-key")
    result = enrichment.enrich("")
    assert result["available"] is False


# ------------------------------------------- sección en el prompt (Capa 3) ---

def test_prompt_enrichment_section_present():
    enrich = {
        "available": True,
        "malware_bazaar": {
            "found": True, "signature": "RedLineStealer",
            "tags": ["stealer"], "yara_rules": ["win_redline_stealer"],
            "vendor_intel": ["VirusTotal"], "file_type": "exe",
            "delivery_method": "web_download",
        },
        "threatfox": {
            "found": True, "malware_families": ["RedLine Stealer"],
            "iocs": [{"ioc": "evil-c2.com", "ioc_type": "domain",
                      "malware": "RedLine Stealer", "threat_type": "botnet_cc",
                      "confidence": 90}],
        },
    }
    lines = prompt_builder._build_enrichment_section(enrich)
    text = "\n".join(lines)
    assert "INTELIGENCIA DE AMENAZAS" in text
    assert "RedLineStealer" in text
    assert "evil-c2.com" in text
    assert "MalwareBazaar" in text and "ThreatFox" in text


def test_prompt_enrichment_section_empty_when_unavailable():
    assert prompt_builder._build_enrichment_section(None) == []
    assert prompt_builder._build_enrichment_section({"available": False}) == []


def test_prompt_ioc_pivot_section():
    enrich = {
        "available": True,
        "malware_bazaar": {"found": False},
        "threatfox": {"found": False},
        "ioc_pivot": {
            "found": True,
            "threatfox": [{"ioc": "129.121.114.124", "malware": "Mirai",
                           "threat_type": "botnet_cc", "confidence": 100}],
            "urlhaus": [{"host": "129.121.114.124", "threats": ["malware_download"],
                         "tags": ["mirai"], "url_count": 7}],
        },
    }
    text = "\n".join(prompt_builder._build_enrichment_section(enrich))
    assert "infraestructura" in text.lower()
    assert "Mirai" in text
    assert "129.121.114.124" in text
    assert "URLhaus" in text
