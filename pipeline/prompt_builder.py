"""Capa 3 — Construcción de Prompt.

Construye el system_prompt (desde prompts/ versionados) y el user_message
con el ProcessedReport serializado. Verifica el token budget.
"""
import json
import logging
from typing import Any

import config

logger = logging.getLogger(__name__)

PROMPT_VERSION = "mitre_analyst_v1"


def load_system_prompt(version: str = PROMPT_VERSION) -> str:
    """Carga un system prompt versionado desde prompts/."""
    path = config.PROMPTS_DIR / f"{version}.txt"
    if not path.exists():
        raise FileNotFoundError(f"System prompt no encontrado: {path}")
    return path.read_text(encoding="utf-8")


def build_user_message(processed: dict[str, Any]) -> str:
    """Serializa el ProcessedReport en un mensaje estructurado para Claude."""
    summary = processed["summary_fields"]
    sections = [
        "Analiza el siguiente reporte preprocesado de sandbox y produce las "
        "tres secciones del formato obligatorio.",
        "",
        "## METADATA DE LA MUESTRA",
        f"- SHA256: {summary['hash'] or 'no disponible'}",
        f"- Archivo: {summary['filename'] or 'no disponible'}",
        f"- Score del sandbox: {summary['score']}/100",
        f"- Plataforma: {summary['platform'] or 'no disponible'}",
        "",
        "## FIRMAS DEL SANDBOX",
    ]
    if summary["sandbox_signatures"]:
        sections.extend(f"- {sig}" for sig in summary["sandbox_signatures"])
    else:
        sections.append("(ninguna)")

    sections += ["", "## ÁRBOL DE PROCESOS", processed["process_tree"] or "(sin procesos anómalos)"]

    sections += ["", "## ACTIVIDAD DE RED"]
    network = processed["network_activity"]
    if any(network.get(k) for k in ("dns", "http", "connections", "domains", "ips")):
        sections.append(json.dumps(network, indent=2, ensure_ascii=False))
    else:
        sections.append("(sin actividad de red registrada)")

    sections += ["", "## SYSCALLS DE ALTO VALOR"]
    if processed["high_value_syscalls"]:
        sections.extend(f"- {s}" for s in processed["high_value_syscalls"])
    else:
        sections.append("(no disponibles en esta fuente)")

    sections += ["", "## ARTEFACTOS DE FILESYSTEM"]
    if processed["filesystem_artifacts"]:
        sections.extend(f"- {a}" for a in processed["filesystem_artifacts"])
    else:
        sections.append("(ninguno relevante)")

    sections += ["", "## ARTEFACTOS DE REGISTRO"]
    if processed["registry_artifacts"]:
        sections.extend(f"- {r}" for r in processed["registry_artifacts"])
    else:
        sections.append("(ninguno relevante)")

    sections += _build_enrichment_section(processed.get("enrichment"))

    return "\n".join(sections)


def _build_enrichment_section(enrichment: dict | None) -> list[str]:
    """Bloque de inteligencia externa (abuse.ch). Vacío si no hay datos."""
    if not enrichment or not enrichment.get("available"):
        return []

    lines = ["", "## INTELIGENCIA DE AMENAZAS (fuentes externas)",
             "Datos de terceros para corroborar el análisis. Úsalos para "
             "confirmar familia e IOCs conocidos, no como sustituto de la "
             "evidencia del sandbox."]

    mb = enrichment.get("malware_bazaar", {})
    if mb.get("found"):
        lines.append("\n### MalwareBazaar (abuse.ch)")
        if mb.get("signature"):
            lines.append(f"- Familia atribuida: {mb['signature']}")
        if mb.get("tags"):
            lines.append(f"- Tags: {', '.join(mb['tags'])}")
        if mb.get("file_type"):
            lines.append(f"- Tipo de archivo: {mb['file_type']}")
        if mb.get("delivery_method"):
            lines.append(f"- Método de entrega: {mb['delivery_method']}")
        if mb.get("yara_rules"):
            lines.append(f"- Reglas YARA: {', '.join(mb['yara_rules'])}")
        if mb.get("vendor_intel"):
            lines.append(f"- Reportado por: {', '.join(mb['vendor_intel'])}")

    tf = enrichment.get("threatfox", {})
    if tf.get("found"):
        lines.append("\n### ThreatFox (abuse.ch) — IOCs conocidos")
        if tf.get("malware_families"):
            lines.append(f"- Familias asociadas: {', '.join(tf['malware_families'])}")
        for ioc in tf.get("iocs", [])[:15]:
            lines.append(
                f"- [{ioc['ioc_type']}] {ioc['ioc']} "
                f"(familia: {ioc['malware']}, confianza: {ioc['confidence']}%, "
                f"tipo: {ioc['threat_type']})"
            )

    return lines


def build_prompt(processed: dict[str, Any],
                 version: str = PROMPT_VERSION) -> tuple[str, str]:
    """Punto de entrada de la Capa 3. Devuelve (system_prompt, user_message).

    Si el reporte excede el token budget, trunca las secciones más largas
    (modo chunked simplificado para el PoC: los reportes típicos quedan
    entre 2K y 8K tokens, muy por debajo del límite).
    """
    if processed["token_count_estimate"] > config.TOKEN_BUDGET_LIMIT:
        logger.warning(
            "ProcessedReport (~%d tokens) excede el budget de %d; truncando",
            processed["token_count_estimate"], config.TOKEN_BUDGET_LIMIT,
        )
        processed = dict(processed)
        processed["high_value_syscalls"] = processed["high_value_syscalls"][:20]
        processed["filesystem_artifacts"] = processed["filesystem_artifacts"][:15]
        processed["registry_artifacts"] = processed["registry_artifacts"][:10]

    system_prompt = load_system_prompt(version)
    user_message = build_user_message(processed)
    logger.info("Prompt construido: ~%d tokens estimados en user_message",
                len(user_message) // 4)
    return system_prompt, user_message
