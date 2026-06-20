"""Capa 1 — Ingesta.

Recibe el reporte desde cualquier fuente soportada (Any.run JSON, Triage API,
fixture estático) y produce el ReportModel normalizado, independiente del
formato de origen. Es la capa de abstracción que aísla el resto del pipeline.
"""
import json
import logging
from pathlib import Path
from typing import Any

import requests

import config

logger = logging.getLogger(__name__)


def _empty_report(source: str) -> dict[str, Any]:
    """ReportModel con todos los campos del contrato, vacíos."""
    return {
        "source": source,
        "sample_hash": "",
        "filename": "",
        "platform": "",
        "score": 0,
        "processes": [],
        "network": {"dns": [], "http": [], "connections": [], "domains": [], "ips": []},
        "filesystem": [],
        "registry": [],
        "signatures": [],
        "raw_syscalls": [],
        "enrichment": None,  # lo rellena la capa de enriquecimiento (abuse.ch)
    }


# ---------------------------------------------------------------- Any.run ---

def parse_any_run(raw: dict[str, Any]) -> dict[str, Any]:
    """Normaliza el JSON exportado desde la UI de Any.run al ReportModel."""
    report = _empty_report("any_run")
    analysis = raw.get("analysis", {})
    content = analysis.get("content", {})
    main_object = content.get("mainObject", {})

    report["sample_hash"] = main_object.get("hashes", {}).get("sha256", "")
    report["filename"] = main_object.get("filename", "")
    report["platform"] = content.get("os", {}).get("title", "") or "windows"
    report["score"] = (
        analysis.get("scores", {}).get("verdict", {}).get("score", 0)
        or content.get("maliciousness", 0)
    )

    for proc in raw.get("processes", []):
        specs = proc.get("scores", {}).get("specs", {})
        report["processes"].append({
            "pid": proc.get("pid"),
            "ppid": proc.get("ppid"),
            "image": proc.get("image", ""),
            "command_line": proc.get("commandLine", ""),
            "injects": bool(specs.get("injects")),
            "loads_suspicious": bool(specs.get("loadsSusp")),
            "network": bool(specs.get("network")),
        })

    network = raw.get("network", {})
    report["network"]["dns"] = [
        {"domain": d.get("domain", ""), "ips": d.get("ips", [])}
        for d in network.get("dns", [])
    ]
    report["network"]["http"] = [
        {"url": h.get("url", ""), "method": h.get("method", ""), "status": h.get("status")}
        for h in network.get("http", [])
    ]
    report["network"]["connections"] = [
        {"ip": c.get("remoteIp", ""), "port": c.get("port"), "protocol": c.get("protocol", "")}
        for c in network.get("connections", [])
    ]
    report["network"]["domains"] = [d["domain"] for d in report["network"]["dns"] if d["domain"]]
    report["network"]["ips"] = sorted({
        ip for d in report["network"]["dns"] for ip in d["ips"]
    } | {c["ip"] for c in report["network"]["connections"] if c["ip"]})

    # Any.run reporta artefactos FS bajo "modified" e incidentes como firmas
    for item in raw.get("modified", {}).get("files", []) if isinstance(raw.get("modified"), dict) else []:
        report["filesystem"].append({
            "path": item.get("filename", "") or item.get("path", ""),
            "operation": item.get("operation", "write"),
        })
    for item in raw.get("modified", {}).get("registry", []) if isinstance(raw.get("modified"), dict) else []:
        report["registry"].append({
            "key": item.get("key", ""),
            "value": item.get("value", ""),
            "operation": item.get("operation", "write"),
        })

    report["signatures"] = [
        {"name": inc.get("title", ""), "score": inc.get("threatlevel", 0)}
        for inc in raw.get("incidents", [])
    ]

    # Any.run no exporta syscalls crudos en el JSON público; queda vacío
    report["raw_syscalls"] = raw.get("syscalls", [])
    return report


# ----------------------------------------------------------------- Triage ---

def parse_triage(raw: dict[str, Any]) -> dict[str, Any]:
    """Normaliza la respuesta de la API REST de tria.ge al ReportModel."""
    report = _empty_report("triage")
    analysis = raw.get("analysis", {})

    report["sample_hash"] = raw.get("sample", {}).get("sha256", "")
    report["filename"] = raw.get("sample", {}).get("target", "")
    report["platform"] = "windows"
    # Triage usa escala 0-10; normalizamos a 0-100 como Any.run
    report["score"] = int(analysis.get("score", 0)) * 10

    families = analysis.get("family", [])
    tags = analysis.get("tags", [])
    if families:
        report["signatures"].append({"name": f"family: {', '.join(families)}", "score": 10})
    for tag in tags:
        report["signatures"].append({"name": f"tag: {tag}", "score": 0})

    for target in raw.get("targets", []):
        iocs = target.get("iocs", {})
        report["network"]["domains"].extend(iocs.get("domains", []))
        report["network"]["ips"].extend(iocs.get("ips", []))
        report["network"]["http"].extend(
            {"url": u, "method": "", "status": None} for u in iocs.get("urls", [])
        )
        for sig in target.get("signatures", []):
            report["signatures"].append({
                "name": sig.get("label", "") or sig.get("name", ""),
                "score": sig.get("score", 0),
            })

    report["network"]["domains"] = sorted(set(report["network"]["domains"]))
    report["network"]["ips"] = sorted(set(report["network"]["ips"]))

    for proc in raw.get("processes", []):
        report["processes"].append({
            "pid": proc.get("pid"),
            "ppid": proc.get("ppid"),
            "image": proc.get("image", "") or proc.get("name", ""),
            "command_line": proc.get("cmd", ""),
            "injects": bool(proc.get("injected")),
            "loads_suspicious": False,
            "network": False,
        })
    return report


def fetch_triage_report(sample_id: str) -> dict[str, Any]:
    """Descarga el reporte triage de un sample via API REST."""
    if not config.TRIAGE_API_TOKEN:
        raise RuntimeError("TRIAGE_API_TOKEN no está configurado en .env")
    url = f"{config.TRIAGE_API_BASE}/samples/{sample_id}/reports/triage"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {config.TRIAGE_API_TOKEN}"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


# ------------------------------------------------------------ VirusTotal ---

# Severidad textual de técnicas MITRE de VT -> score aproximado 0-10
_VT_SEVERITY = {
    "IMPACT_SEVERITY_HIGH": 9, "HIGH": 9,
    "IMPACT_SEVERITY_MEDIUM": 6, "MEDIUM": 6,
    "IMPACT_SEVERITY_LOW": 3, "LOW": 3,
    "IMPACT_SEVERITY_INFO": 1, "INFO": 1,
    "IMPACT_SEVERITY_UNKNOWN": 0, "UNKNOWN": 0,
}


def _vt_unwrap(raw: dict[str, Any]) -> dict[str, Any]:
    """La API v3 envuelve todo en {"data": {"attributes": {...}}} o
    {"data": {...}}. Devuelve el diccionario de atributos sin envolver."""
    data = raw.get("data", raw)
    if isinstance(data, dict) and "attributes" in data:
        return data["attributes"]
    return data


def _vt_flatten_process_tree(nodes: list[dict], ppid: Any = None) -> list[dict]:
    """Aplana processes_tree (recursivo) a la lista de procesos del ReportModel."""
    flat = []
    for node in nodes or []:
        pid = node.get("process_id")
        name = node.get("name", "")
        flat.append({
            "pid": pid,
            "ppid": node.get("parent_process_id", ppid),
            "image": name,
            "command_line": name,
            "injects": False,
            "loads_suspicious": False,
            "network": False,
        })
        flat.extend(_vt_flatten_process_tree(node.get("children", []), ppid=pid))
    return flat


def parse_virustotal(behaviour: dict[str, Any],
                     file_info: dict[str, Any] | None = None,
                     sha256: str = "") -> dict[str, Any]:
    """Normaliza el behaviour_summary de VirusTotal v3 al ReportModel.

    behaviour: atributos de GET /files/{id}/behaviour_summary
    file_info: atributos de GET /files/{id} (opcional, para hash/score/nombre)
    """
    behaviour = _vt_unwrap(behaviour) if "data" in behaviour else behaviour
    report = _empty_report("virustotal")

    # --- metadata (del file report si está disponible) ---
    info = _vt_unwrap(file_info) if file_info else {}
    report["sample_hash"] = info.get("sha256", "") or sha256
    report["filename"] = (
        info.get("meaningful_name", "")
        or (info.get("names", [""]) or [""])[0]
    )
    report["platform"] = "windows"
    stats = info.get("last_analysis_stats", {})
    total = sum(stats.values()) if stats else 0
    if total:
        report["score"] = round(100 * stats.get("malicious", 0) / total)

    # --- procesos: árbol + ejecuciones de comandos ---
    report["processes"] = _vt_flatten_process_tree(behaviour.get("processes_tree", []))
    injected = {p for p in behaviour.get("processes_injected", []) if isinstance(p, str)}
    for proc in report["processes"]:
        if proc["image"] in injected:
            proc["injects"] = True
    # command_executions traen líneas de comando completas (powershell -enc, etc.)
    for cmd in behaviour.get("command_executions", []):
        report["processes"].append({
            "pid": None, "ppid": None,
            "image": cmd.split(" ")[0] if isinstance(cmd, str) else "",
            "command_line": cmd if isinstance(cmd, str) else "",
            "injects": False, "loads_suspicious": False, "network": False,
        })

    # --- red ---
    for dns in behaviour.get("dns_lookups", []):
        report["network"]["dns"].append({
            "domain": dns.get("hostname", ""),
            "ips": dns.get("resolved_ips", []),
        })
    for http in behaviour.get("http_conversations", []):
        report["network"]["http"].append({
            "url": http.get("url", ""),
            "method": http.get("request_method", ""),
            "status": http.get("response_status_code"),
        })
    for conn in behaviour.get("ip_traffic", []):
        report["network"]["connections"].append({
            "ip": conn.get("destination_ip", ""),
            "port": conn.get("destination_port"),
            "protocol": conn.get("transport_layer_protocol", ""),
        })
    report["network"]["domains"] = sorted({
        d["domain"] for d in report["network"]["dns"] if d["domain"]
    })
    report["network"]["ips"] = sorted(
        {ip for d in report["network"]["dns"] for ip in d["ips"]}
        | {c["ip"] for c in report["network"]["connections"] if c["ip"]}
    )

    # --- filesystem ---
    fs_map = [
        ("files_written", "write"), ("files_deleted", "delete"),
        ("files_opened", "open"),
    ]
    for key, op in fs_map:
        for item in behaviour.get(key, []):
            path = item if isinstance(item, str) else item.get("path", "")
            if path:
                report["filesystem"].append({"path": path, "operation": op})
    for item in behaviour.get("files_dropped", []):
        path = item.get("path", "") if isinstance(item, dict) else item
        if path:
            report["filesystem"].append({"path": path, "operation": "drop"})

    # --- registro ---
    for item in behaviour.get("registry_keys_set", []):
        if isinstance(item, dict):
            report["registry"].append({
                "key": item.get("key", ""), "value": item.get("value", ""),
                "operation": "set",
            })
        elif isinstance(item, str):
            report["registry"].append({"key": item, "value": "", "operation": "set"})
    for item in behaviour.get("registry_keys_deleted", []):
        key = item if isinstance(item, str) else item.get("key", "")
        if key:
            report["registry"].append({"key": key, "value": "", "operation": "delete"})

    # --- firmas: técnicas MITRE + tags + verdicts ---
    for tech in behaviour.get("mitre_attack_techniques", []):
        tid = tech.get("id", "")
        desc = tech.get("signature_description", "")
        sev = tech.get("severity", "")
        report["signatures"].append({
            "name": f"{tid} {desc}".strip(),
            "score": _VT_SEVERITY.get(str(sev).upper(), 0),
        })
    for tag in behaviour.get("tags", []):
        report["signatures"].append({"name": f"tag: {tag}", "score": 0})

    return report


def fetch_virustotal_report(sha256: str) -> dict[str, Any]:
    """Descarga behaviour_summary + file report de VirusTotal v3.

    Devuelve {"behaviour": {...}, "file_info": {...}, "sha256": ...} listo para
    parse_virustotal. Respeta el rate limit del free tier (4 req/min): hace 2
    llamadas por muestra.
    """
    if not config.VIRUSTOTAL_API_KEY:
        raise RuntimeError("VIRUSTOTAL_API_KEY no está configurado en .env")
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

    beh_url = f"{config.VT_API_BASE}/files/{sha256}/behaviour_summary"
    beh_resp = requests.get(beh_url, headers=headers, timeout=30)
    beh_resp.raise_for_status()
    behaviour = beh_resp.json()

    file_info = None
    try:
        info_resp = requests.get(f"{config.VT_API_BASE}/files/{sha256}",
                                 headers=headers, timeout=30)
        info_resp.raise_for_status()
        file_info = info_resp.json()
    except requests.RequestException as e:
        logger.warning("No se pudo obtener el file report de VT (%s); "
                       "se continúa solo con behaviour_summary", e)

    return {"behaviour": behaviour, "file_info": file_info, "sha256": sha256}


# ----------------------------------------------------------- Entry points ---

def _detect_format(raw: dict[str, Any]) -> str:
    """Detecta el formato de un JSON guardado por sus claves."""
    # VirusTotal behaviour_summary: claves distintivas (con o sin envoltura data)
    probe = _vt_unwrap(raw) if "data" in raw else raw
    vt_keys = {"processes_tree", "ip_traffic", "dns_lookups", "command_executions",
               "registry_keys_set", "mitre_attack_techniques"}
    if vt_keys & set(probe.keys()):
        return "virustotal"
    if "targets" in raw or ("analysis" in raw and "score" in raw.get("analysis", {})):
        if "content" not in raw.get("analysis", {}):
            return "triage"
    return "any_run"


def _parse_by_format(raw: dict[str, Any], fmt: str) -> dict[str, Any]:
    """Despacha al parser correcto según el formato detectado."""
    if fmt == "triage":
        return parse_triage(raw)
    if fmt == "virustotal":
        return parse_virustotal(raw)
    return parse_any_run(raw)


def ingest(source: str, file_path: str | None = None,
           sample_name: str | None = None,
           sample_id: str | None = None,
           sample_hash: str | None = None) -> dict[str, Any]:
    """Punto de entrada de la Capa 1. Devuelve siempre un ReportModel.

    source: "any_run" | "triage" | "virustotal" | "fixture"
    """
    if source == "any_run":
        if not file_path:
            raise ValueError("--file es obligatorio con --source any_run")
        raw = json.loads(Path(file_path).read_text(encoding="utf-8"))
        return parse_any_run(raw)

    if source == "triage":
        if not sample_id:
            raise ValueError("--sample-id es obligatorio con --source triage")
        raw = fetch_triage_report(sample_id)
        return parse_triage(raw)

    if source == "virustotal":
        if not sample_hash:
            raise ValueError("--hash es obligatorio con --source virustotal")
        bundle = fetch_virustotal_report(sample_hash)
        return parse_virustotal(bundle["behaviour"], bundle["file_info"],
                                sha256=bundle["sha256"])

    if source == "fixture":
        if not sample_name:
            raise ValueError("--sample es obligatorio con --source fixture")
        fixture_path = config.FIXTURES_DIR / f"{sample_name}.json"
        if not fixture_path.exists():
            available = [p.stem for p in config.FIXTURES_DIR.glob("*.json")]
            raise FileNotFoundError(
                f"Fixture no encontrado: {fixture_path}. Disponibles: {available or 'ninguno'}"
            )
        raw = json.loads(fixture_path.read_text(encoding="utf-8"))
        fmt = _detect_format(raw)
        logger.info("Fixture %s detectado como formato %s", sample_name, fmt)
        report = _parse_by_format(raw, fmt)
        report["source"] = "fixture"
        return report

    raise ValueError(f"Fuente no soportada: {source}")
