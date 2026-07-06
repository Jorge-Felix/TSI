"""Adjunto opcional: reporte de ANY.RUN como contexto de apoyo.

VirusTotal sigue siendo la fuente obligatoria; esto NO es una fuente, es un
documento que el analista adjunta para dar más contexto. Convierte el reporte
(PDF/HTML/texto) a texto plano, filtra solo las secciones relevantes para
malware, y lo recorta a un presupuesto de tokens para economizar.

El motor de extracción está desacoplado (_raw_text): hoy usa pypdf + BeautifulSoup;
cambiar a Docling u otra herramienta es reemplazar esa única función.
"""
import logging
import re
from pathlib import Path

import config

logger = logging.getLogger(__name__)

# Señales relevantes para malware: solo se conservan líneas que las contengan
RELEVANT_KEYWORDS = re.compile(
    r"(process|proces|network|red\b|dns|http|connection|conexi|tcp|udp|"
    r"registry|registro|file|archivo|mutex|persist|behavior|comportamiento|"
    r"malicious|malicio|threat|amenaza|mitre|att&ck|ttp|ioc|indicator|indicador|"
    r"command|comando|payload|dropper|c2\b|domain|dominio|url|hash|signature|firma|"
    r"inject|service|servicio|startup|autorun|scheduled|powershell|cmd\b|"
    r"malware|trojan|stealer|ransom|rat\b|botnet)",
    re.IGNORECASE,
)

# Patrones que parecen IOCs (se conservan aunque la línea no tenga keyword)
IOC_RE = re.compile(
    r"(\b\d{1,3}(?:\.\d{1,3}){3}\b"          # IPv4
    r"|https?://\S+"                          # URL
    r"|\b[a-fA-F0-9]{32,64}\b"                # MD5/SHA1/SHA256
    # nombre.tld con límite final para que .ru no matchee dentro de "ANY.RUN"
    r"|\b[\w-]+\.(?:exe|dll|bat|ps1|vbs|scr|sh|elf|com|net|org|ru|cn|info|xyz)\b)",
    re.IGNORECASE,
)


def _ocr_pdf(path: Path) -> str:
    """OCR para PDFs basados en imágenes (reportes ANY.RUN son capturas de la UI).

    Renderiza cada página con pypdfium2 y la pasa por rapidocr (ONNX, sin
    binarios del sistema, modelos incluidos en el paquete). Lento pero offline.
    """
    import numpy as np
    import pypdfium2 as pdfium
    from rapidocr_onnxruntime import RapidOCR

    engine = RapidOCR()
    pdf = pdfium.PdfDocument(str(path))
    texts: list[str] = []
    try:
        for i in range(len(pdf)):
            page = pdf[i]
            image = page.render(scale=2.0).to_pil().convert("RGB")
            result, _ = engine(np.array(image))
            if result:
                texts.extend(line[1] for line in result)
            page.close()
    finally:
        pdf.close()
    return "\n".join(texts)


def _extract_pdf(path: Path) -> str:
    """Texto de un PDF: primero texto seleccionable; si no hay, OCR."""
    from pypdf import PdfReader
    reader = PdfReader(str(path))
    text = "\n".join((page.extract_text() or "") for page in reader.pages)
    if len(text.strip()) >= 40:
        return text
    logger.info("PDF sin texto seleccionable; usando OCR (rapidocr)...")
    return _ocr_pdf(path)


def _extract_html(path: Path) -> str:
    from bs4 import BeautifulSoup
    html = path.read_text(encoding="utf-8", errors="ignore")
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header", "svg"]):
        tag.decompose()
    return soup.get_text("\n")


def _raw_text(path: Path) -> str:
    """Motor de extracción (desacoplado). Devuelve el texto crudo del reporte."""
    ext = path.suffix.lower()
    if ext == ".pdf":
        return _extract_pdf(path)
    if ext in (".html", ".htm"):
        return _extract_html(path)
    return path.read_text(encoding="utf-8", errors="ignore")  # .txt, .md, .json


def _filter_relevant(text: str) -> str:
    """Conserva solo líneas con señales de malware o IOCs; descarta boilerplate."""
    kept: list[str] = []
    prev_blank = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if kept and not prev_blank:
                kept.append("")  # colapsa líneas en blanco
                prev_blank = True
            continue
        prev_blank = False
        if RELEVANT_KEYWORDS.search(stripped) or IOC_RE.search(stripped):
            kept.append(stripped)
    return "\n".join(kept).strip()


def _cap_tokens(text: str, max_tokens: int) -> str:
    """Recorta a un presupuesto de tokens (~4 chars/token)."""
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return (text[:max_chars].rsplit("\n", 1)[0]
            + "\n[... reporte ANY.RUN truncado para ahorrar tokens ...]")


def extract_context(path_str: str) -> str | None:
    """Punto de entrada. Reporte ANY.RUN -> contexto condensado (o None si falla).

    Degrada con gracia: si el archivo no existe, no se puede leer o queda vacío
    tras el filtrado, devuelve None y el pipeline continúa solo con VirusTotal.
    """
    path = Path(path_str)
    if not path.exists():
        logger.warning("Reporte ANY.RUN no encontrado: %s", path)
        return None
    try:
        raw = _raw_text(path)
    except Exception as e:  # noqa: BLE001 — cualquier fallo del extractor es no-fatal
        logger.warning("No se pudo procesar el reporte ANY.RUN (%s): %s", path, e)
        return None

    if not raw.strip():
        logger.warning("Reporte ANY.RUN sin texto extraíble: %s", path)
        return None

    filtered = _filter_relevant(raw)
    condensed = _cap_tokens(filtered or raw.strip(), config.ANYRUN_MAX_CONTEXT_TOKENS)
    logger.info(
        "Contexto ANY.RUN: %d chars crudos -> %d chars (~%d tokens, %.0f%% menos)",
        len(raw), len(condensed), len(condensed) // 4,
        100 * (1 - len(condensed) / max(len(raw), 1)),
    )
    return condensed or None
