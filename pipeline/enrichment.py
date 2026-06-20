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
        "ioc_pivot": {"found": False, "threatfox": [], "urlhaus": []},
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


# ------------------------------------------ Pivote de IOCs (red -> intel) ---

def parse_threatfox_ioc(raw: dict[str, Any]) -> dict[str, Any]:
    """Normaliza ThreatFox search_ioc (búsqueda por IP/dominio/URL)."""
    if raw.get("query_status") != "ok" or not raw.get("data"):
        return {"found": False}
    entry = raw["data"][0]
    return {
        "found": True,
        "malware": entry.get("malware_printable") or entry.get("malware") or "",
        "threat_type": entry.get("threat_type", ""),
        "confidence": entry.get("confidence_level", 0),
    }


def query_threatfox_ioc(ioc: str) -> dict[str, Any]:
    """Busca un IOC (IP/dominio/URL) en ThreatFox."""
    try:
        resp = requests.post(
            config.THREATFOX_API,
            json={"query": "search_ioc", "search_term": ioc},
            headers={"Auth-Key": config.ABUSECH_AUTH_KEY},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return parse_threatfox_ioc(resp.json())
    except (requests.RequestException, ValueError) as e:
        logger.debug("ThreatFox IOC %s no disponible: %s", ioc, e)
        return {"found": False}


def parse_urlhaus_host(raw: dict[str, Any]) -> dict[str, Any]:
    """Normaliza URLhaus host lookup (reputación de una IP/dominio)."""
    if raw.get("query_status") != "ok":
        return {"found": False}
    urls = raw.get("urls") or []
    threats = sorted({u.get("threat", "") for u in urls if u.get("threat")})
    tags = sorted({t for u in urls for t in (u.get("tags") or [])})
    return {
        "found": bool(urls),
        "url_count": int(raw.get("url_count") or len(urls)),
        "threats": threats[:5],
        "tags": tags[:10],
    }


def query_urlhaus_host(host: str) -> dict[str, Any]:
    """Consulta la reputación de una IP/dominio en URLhaus."""
    try:
        resp = requests.post(
            config.URLHAUS_API,
            data={"host": host},
            headers={"Auth-Key": config.ABUSECH_AUTH_KEY},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return parse_urlhaus_host(resp.json())
    except (requests.RequestException, ValueError) as e:
        logger.debug("URLhaus host %s no disponible: %s", host, e)
        return {"found": False}


def pivot_iocs(network: dict[str, Any] | None) -> dict[str, Any]:
    """Pivotea sobre los IOCs de red (IPs/dominios) para saber si la
    infraestructura es conocida. Esta es la alternativa de inteligencia a un
    segundo sandbox: en vez de re-detonar, pregunta '¿qué se sabe de este C2?'.
    """
    network = network or {}
    iocs = (network.get("ips") or [])[:config.PIVOT_MAX_IPS]
    iocs += (network.get("domains") or [])[:config.PIVOT_MAX_DOMAINS]

    threatfox_hits, urlhaus_hits = [], []
    for ioc in iocs:
        tf = query_threatfox_ioc(ioc)
        if tf.get("found"):
            threatfox_hits.append({
                "ioc": ioc, "malware": tf["malware"],
                "threat_type": tf["threat_type"], "confidence": tf["confidence"],
            })
        uh = query_urlhaus_host(ioc)
        if uh.get("found"):
            urlhaus_hits.append({
                "host": ioc, "threats": uh["threats"],
                "tags": uh["tags"], "url_count": uh["url_count"],
            })
    return {
        "found": bool(threatfox_hits or urlhaus_hits),
        "threatfox": threatfox_hits,
        "urlhaus": urlhaus_hits,
    }


# ------------------------------------------------------------- Entry point ---

def enrich(sha256: str, network: dict[str, Any] | None = None) -> dict[str, Any]:
    """Punto de entrada de la capa de enriquecimiento.

    Combina inteligencia por hash (MalwareBazaar + ThreatFox) con pivote sobre
    los IOCs de red. Si no hay Auth-Key o no hay hash, devuelve vacío sin fallar.
    """
    if not config.ABUSECH_AUTH_KEY:
        logger.debug("ABUSECH_AUTH_KEY no configurado; se omite enriquecimiento")
        return _empty_enrichment()
    if not sha256:
        return _empty_enrichment()

    mb = query_malwarebazaar(sha256)
    tf = query_threatfox(sha256)
    pivot = pivot_iocs(network) if network else {
        "found": False, "threatfox": [], "urlhaus": []
    }
    result = {
        "malware_bazaar": mb,
        "threatfox": tf,
        "ioc_pivot": pivot,
        "available": bool(mb.get("found") or tf.get("found") or pivot.get("found")),
    }
    logger.info(
        "Enriquecimiento abuse.ch: MalwareBazaar=%s, ThreatFox(hash)=%s, "
        "pivote IOCs=%d coincidencias",
        "ok" if mb.get("found") else "-",
        "ok" if tf.get("found") else "-",
        len(pivot.get("threatfox", [])) + len(pivot.get("urlhaus", [])),
    )
    return result
