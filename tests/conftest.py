"""Datos de prueba mínimos basados en los Apéndices A y B del documento de
arquitectura. Son solo para tests unitarios — la demo usa fixtures reales."""
import sys
from pathlib import Path

import pytest

# Permite importar config y pipeline desde la raíz del proyecto
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def any_run_raw():
    return {
        "analysis": {
            "content": {
                "mainObject": {
                    "filename": "malware.exe",
                    "hashes": {"sha256": "abc123def456" + "0" * 52},
                },
                "maliciousness": 100,
            },
            "scores": {"verdict": {"threatLevel": 2, "score": 95}},
        },
        "processes": [
            {
                "pid": 1234, "ppid": 5678,
                "image": "C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe",
                "commandLine": "malware.exe --config C2:port",
                "scores": {"specs": {"injects": True, "loadsSusp": True, "network": True}},
            },
            {
                "pid": 5678, "ppid": 1,
                "image": "C:\\Windows\\explorer.exe",
                "commandLine": "explorer.exe",
                "scores": {"specs": {}},
            },
        ],
        "network": {
            "dns": [{"domain": "evil-c2.com", "ips": ["185.234.10.10"]}],
            "http": [{"url": "http://evil-c2.com/gate.php", "method": "POST", "status": 200}],
            "connections": [{"remoteIp": "185.234.10.10", "port": 4782, "protocol": "tcp"}],
        },
        "modified": {
            "files": [
                {"filename": "C:\\Users\\user\\AppData\\Roaming\\svc.exe", "operation": "create"},
                {"filename": "C:\\Windows\\Temp\\log.tmp", "operation": "write"},
            ],
            "registry": [
                {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "value": "svc.exe", "operation": "write"},
                {"key": "HKCU\\Software\\SomeApp\\Settings",
                 "value": "1", "operation": "write"},
            ],
        },
        "incidents": [
            {"title": "Possible use of process hollowing", "threatlevel": 3},
            {"title": "Connects to C2 server", "threatlevel": 3},
        ],
    }


@pytest.fixture
def triage_raw():
    return {
        "analysis": {
            "score": 10,
            "family": ["remcos"],
            "tags": ["rat", "keylogger", "persistence"],
        },
        "targets": [
            {
                "iocs": {
                    "urls": ["http://evil-c2.com/gate.php"],
                    "domains": ["evil-c2.com"],
                    "ips": ["185.234.10.10"],
                },
                "signatures": [
                    {"label": "persistence-registry", "score": 9},
                    {"label": "network-cnc-generic", "score": 10},
                ],
            }
        ],
        "processes": [
            {"pid": 1234, "ppid": 5678, "name": "malware.exe",
             "cmd": "malware.exe --config ...", "injected": True},
        ],
    }


@pytest.fixture
def virustotal_behaviour():
    """Atributos de GET /files/{id}/behaviour_summary (forma agregada de VT v3)."""
    return {
        "processes_tree": [
            {
                "name": "C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe",
                "process_id": "1234",
                "children": [
                    {"name": "C:\\Windows\\System32\\cmd.exe", "process_id": "2345"},
                ],
            },
        ],
        "processes_injected": ["C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe"],
        "command_executions": [
            "powershell.exe -enc QQBCAEMA",
            "cmd.exe /c start malware.exe",
        ],
        "dns_lookups": [
            {"hostname": "evil-c2.com", "resolved_ips": ["185.234.10.10"]},
        ],
        "http_conversations": [
            {"url": "http://evil-c2.com/gate.php", "request_method": "POST",
             "response_status_code": 200},
        ],
        "ip_traffic": [
            {"destination_ip": "185.234.10.10", "destination_port": 4782,
             "transport_layer_protocol": "tcp"},
        ],
        "files_written": ["C:\\Users\\user\\AppData\\Roaming\\svc.exe"],
        "files_dropped": [
            {"path": "C:\\Windows\\Temp\\payload.dll", "sha256": "deadbeef"},
        ],
        "registry_keys_set": [
            {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
             "value": "svc.exe"},
            {"key": "HKCU\\Software\\SomeApp\\Settings", "value": "1"},
        ],
        "mitre_attack_techniques": [
            {"id": "T1055", "signature_description": "Process Injection",
             "severity": "IMPACT_SEVERITY_HIGH"},
            {"id": "T1547.001", "signature_description": "Registry Run Keys",
             "severity": "IMPACT_SEVERITY_MEDIUM"},
        ],
        "tags": ["PERSISTENCE", "EVADER"],
    }


@pytest.fixture
def virustotal_file_info():
    """Atributos de GET /files/{id} (para hash/score/nombre)."""
    return {
        "data": {
            "attributes": {
                "sha256": "abc123def456" + "0" * 52,
                "meaningful_name": "malware.exe",
                "names": ["malware.exe", "invoice.exe"],
                "last_analysis_stats": {
                    "malicious": 58, "suspicious": 2, "undetected": 8,
                    "harmless": 0, "timeout": 2,
                },
            }
        }
    }


@pytest.fixture
def malwarebazaar_raw():
    """Respuesta de MalwareBazaar get_info."""
    return {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "abc123" + "0" * 58,
                "file_type": "exe",
                "signature": "RedLineStealer",
                "tags": ["exe", "RedLine", "stealer"],
                "delivery_method": "web_download",
                "first_seen": "2024-01-15 10:00:00",
                "yara_rules": [
                    {"rule_name": "win_redline_stealer"},
                    {"rule_name": "INDICATOR_EXE_Packed"},
                ],
                "vendor_intel": {"VirusTotal": {}, "ANY.RUN": {}, "Triage": {}},
            }
        ],
    }


@pytest.fixture
def threatfox_raw():
    """Respuesta de ThreatFox search_hash."""
    return {
        "query_status": "ok",
        "data": [
            {
                "ioc": "185.234.10.10:4782",
                "ioc_type": "ip:port",
                "malware": "win.redline_stealer",
                "malware_printable": "RedLine Stealer",
                "threat_type": "botnet_cc",
                "confidence_level": 75,
            },
            {
                "ioc": "evil-c2.com",
                "ioc_type": "domain",
                "malware": "win.redline_stealer",
                "malware_printable": "RedLine Stealer",
                "threat_type": "botnet_cc",
                "confidence_level": 90,
            },
        ],
    }


@pytest.fixture
def threatfox_ioc_raw():
    """Respuesta de ThreatFox search_ioc (pivote sobre una IP/dominio)."""
    return {
        "query_status": "ok",
        "data": [
            {
                "ioc": "129.121.114.124",
                "malware": "elf.mirai",
                "malware_printable": "Mirai",
                "threat_type": "botnet_cc",
                "confidence_level": 100,
            }
        ],
    }


@pytest.fixture
def urlhaus_host_raw():
    """Respuesta de URLhaus host lookup."""
    return {
        "query_status": "ok",
        "url_count": "7",
        "urls": [
            {"url": "http://129.121.114.124/vl0", "threat": "malware_download",
             "tags": ["elf", "mirai"]},
            {"url": "http://129.121.114.124/g0G", "threat": "malware_download",
             "tags": ["32-bit"]},
        ],
    }


@pytest.fixture
def claude_response():
    return '''```json
{
  "sample": { "hash": "abc123", "filename": "malware.exe", "score": 95 },
  "behavior_summary": "RAT con persistencia via Run key y C2 sobre TCP/4782",
  "ttps": [
    {
      "tactic": "TA0003 Persistence",
      "technique": "T1547.001 Registry Run Keys / Startup Folder",
      "evidence": "Escribe svc.exe en HKCU\\\\...\\\\CurrentVersion\\\\Run",
      "confidence": "high"
    },
    {
      "tactic": "TA0011 Command and Control",
      "technique": "T1071 Application Layer Protocol",
      "evidence": "POST a http://evil-c2.com/gate.php",
      "confidence": "high"
    }
  ],
  "malware_family": "Remcos RAT (probable)",
  "threat_category": "RAT"
}
```

La muestra exhibe comportamiento de RAT clásico: establece persistencia
mediante la clave Run del registro y se comunica con su servidor C2.

| Tipo | Valor | Confianza | Contexto |
|------|-------|-----------|----------|
| IP | 185.234.10.10 | Alta | C2 communication |
| Dominio | evil-c2.com | Alta | C2 domain |
| URL | http://evil-c2.com/gate.php | Alta | Payload gate |
'''
