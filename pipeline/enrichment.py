"""Capa de Enriquecimiento — abuse.ch (MalwareBazaar + ThreatFox).

Se inserta entre la Capa 1 y la 2. No trae comportamiento crudo (eso ya lo da
VirusTotal); trae *inteligencia destilada*: atribución de familia, tags, reglas
YARA e IOCs/C2 conocidos. Esto reduce la especulación del LLM en la Capa 4.

Degrada con gracia: si no hay Auth-Key, si la muestra no está en abuse.ch, o si
la API falla, devuelve un enrichment vacío y el pipeline continúa sin problema.
"""
import logging
from typing import Any

import requests

import config

logger = logging.getLogger(__name__)

TIMEOUT = 20


def _empty_enrichment() -> dict[str, Any]:
    return {
        "malware_bazaar": {"found": False},
        "threatfox": {"found": False},
        "available": False,
    }


# --------------------------------------------------------- MalwareBazaar ---

def parse_malwarebazaar(raw: dict[str, Any]) -> dict[str, Any]:
    """Normaliza la respuesta de MalwareBazaar get_info."""
    if raw.get("query_status") != "ok" or not raw.get("data"):
        return {"found": False}
    entry = raw["data"][0]
    yara = entry.get("yara_rules") or []
    vendor = entry.get("vendor_intel") or {}
    vendor_names = sorted(vendor.keys()) if isinstance(vendor, dict) else []
    return {
        "found": True,
        "signature": entry.get("signature") or "",          # familia
        "tags": entry.get("tags") or [],
        "file_type": entry.get("file_type") or "",
        "delivery_method": entry.get("delivery_method") or "",
        "first_seen": entry.get("first_seen") or "",
        "yara_rules": [
            y.get("rule_name", "") for y in yara if isinstance(y, dict)
        ][:10],
        "vendor_intel": vendor_names[:10],
    }


def query_malwarebazaar(sha256: str) -> dict[str, Any]:
    """Consulta MalwareBazaar por hash. Devuelve dict normalizado."""
    try:
        resp = requests.post(
            config.MALWAREBAZAAR_API,
            data={"query": "get_info", "hash": sha256},
            headers={"Auth-Key": config.ABUSECH_AUTH_KEY},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return parse_malwarebazaar(resp.json())
    except (requests.RequestException, ValueError) as e:
        logger.warning("MalwareBazaar no disponible: %s", e)
        return {"found": False}


# -------------------------------------------------------------- ThreatFox ---

def parse_threatfox(raw: dict[str, Any]) -> dict[str, Any]:
    """Normaliza la respuesta de ThreatFox search_hash."""
    if raw.get("query_status") != "ok" or not raw.get("data"):
        return {"found": False}
    iocs = []
    families = set()
    for entry in raw["data"]:
        fam = entry.get("malware_printable") or entry.get("malware") or ""
        if fam:
            families.add(fam)
        iocs.append({
            "ioc": entry.get("ioc", ""),
            "ioc_type": entry.get("ioc_type", ""),
            "malware": fam,
            "threat_type": entry.get("threat_type", ""),
            "confidence": entry.get("confidence_level", 0),
        })
    return {
        "found": True,
        "iocs": iocs[:30],
        "malware_families": sorted(families),
    }


def query_threatfox(sha256: str) -> dict[str, Any]:
    """Consulta ThreatFox por hash. Devuelve dict normalizado."""
    try:
        resp = requests.post(
            config.THREATFOX_API,
            json={"query": "search_hash", "hash": sha256},
            headers={"Auth-Key": config.ABUSECH_AUTH_KEY},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return parse_threatfox(resp.json())
    except (requests.RequestException, ValueError) as e:
        logger.warning("ThreatFox no disponible: %s", e)
        return {"found": False}


# ------------------------------------------------------------- Entry point ---

def enrich(sha256: str) -> dict[str, Any]:
    """Punto de entrada de la capa de enriquecimiento.

    Devuelve un dict con sub-claves malware_bazaar/threatfox y un flag
    `available`. Si no hay Auth-Key o no hay hash, devuelve vacío sin fallar.
    """
    if not config.ABUSECH_AUTH_KEY:
        logger.debug("ABUSECH_AUTH_KEY no configurado; se omite enriquecimiento")
        return _empty_enrichment()
    if not sha256:
        return _empty_enrichment()

    mb = query_malwarebazaar(sha256)
    tf = query_threatfox(sha256)
    result = {
        "malware_bazaar": mb,
        "threatfox": tf,
        "available": bool(mb.get("found") or tf.get("found")),
    }
    logger.info("Enriquecimiento abuse.ch: MalwareBazaar=%s, ThreatFox=%s",
                "✓" if mb.get("found") else "✗",
                "✓" if tf.get("found") else "✗")
    return result
