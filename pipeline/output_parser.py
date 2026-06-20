"""Capa 5 — Parser de Respuesta.

Extrae el JSON estructurado, la narrativa y la tabla de IOCs de la respuesta
Markdown de Claude. Normaliza a AnalysisResult.
"""
import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n\s*```", re.DOTALL)
ANY_CODE_BLOCK_RE = re.compile(r"```\w*\s*\n(.*?)\n\s*```", re.DOTALL)
TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")


def extract_json_block(raw: str) -> dict[str, Any]:
    """Primer bloque ```json de la respuesta; fallback con regex de campos."""
    match = JSON_BLOCK_RE.search(raw)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            logger.warning("Bloque json malformado, intentando fallback")

    # Fallback 1: cualquier bloque de código que parezca JSON
    for m in ANY_CODE_BLOCK_RE.finditer(raw):
        candidate = m.group(1).strip()
        if candidate.startswith("{"):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

    # Fallback 2: regex de campos clave sueltos
    logger.warning("No se encontró bloque JSON válido; extrayendo campos con regex")
    result: dict[str, Any] = {}
    for field in ("behavior_summary", "malware_family", "threat_category"):
        m = re.search(rf'"{field}"\s*:\s*"([^"]*)"', raw)
        if m:
            result[field] = m.group(1)
    return result


def extract_narrative(raw: str) -> str:
    """Texto entre el cierre del bloque JSON y el inicio de la tabla de IOCs,
    limpiando separadores, encabezados markdown y rótulos de sección que Claude
    a veces incluye (## Narrativa, ## IOCs, SECCIÓN 2, ---)."""
    after_json = raw
    match = JSON_BLOCK_RE.search(raw)
    if match:
        after_json = raw[match.end():]

    lines = []
    for line in after_json.splitlines():
        if TABLE_ROW_RE.match(line):
            break  # empieza la tabla de IOCs
        stripped = line.strip()
        if stripped in ("---", "***", "___"):
            continue  # separador horizontal markdown
        if re.match(r"#{1,6}\s", stripped):
            continue  # encabezado markdown (## Narrativa Técnica, ## IOCs, ...)
        if re.match(r"SECCI[OÓ]N\s*\d", stripped, re.IGNORECASE):
            continue  # rótulo "SECCIÓN N"
        lines.append(line)

    narrative = "\n".join(lines).strip()
    narrative = re.sub(r"\n{3,}", "\n\n", narrative)  # colapsar líneas en blanco
    return narrative.strip()


def extract_ioc_table(raw: str) -> list[dict[str, str]]:
    """Parsea la tabla Markdown de IOCs usando | como delimitador."""
    iocs = []
    header: list[str] = []
    for line in raw.splitlines():
        match = TABLE_ROW_RE.match(line)
        if not match:
            continue
        cells = [c.strip() for c in match.group(1).split("|")]
        if not header:
            header = [c.lower() for c in cells]
            continue
        if all(set(c) <= {"-", ":", " "} for c in cells):
            continue  # fila separadora |---|---|
        if len(cells) != len(header):
            continue
        row = dict(zip(header, cells))
        iocs.append({
            "type": row.get("tipo", row.get("type", "")),
            "value": row.get("valor", row.get("value", "")),
            "confidence": row.get("confianza", row.get("confidence", "")),
            "context": row.get("contexto", row.get("context", "")),
        })
    return [i for i in iocs if i["value"]]


def parse(raw_response: str, metrics: dict[str, float] | None = None) -> dict[str, Any]:
    """Punto de entrada de la Capa 5. Respuesta cruda -> AnalysisResult."""
    metrics = metrics or {}
    data = extract_json_block(raw_response)

    result = {
        "sample": data.get("sample", {}),
        "behavior_summary": data.get("behavior_summary", ""),
        "malware_family": data.get("malware_family", "Unknown"),
        "threat_category": data.get("threat_category", "Other"),
        "ttps": data.get("ttps", []),
        "narrative": extract_narrative(raw_response),
        "iocs": extract_ioc_table(raw_response),
        "analysis_cost_usd": metrics.get("cost_usd", 0.0),
        "analysis_time_s": metrics.get("response_time_s", 0.0),
    }
    logger.info("Parseado: %d TTPs, %d IOCs", len(result["ttps"]), len(result["iocs"]))
    return result
