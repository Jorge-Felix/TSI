"""Capa 2 — Preprocesamiento.

La capa más importante del PoC: recibe el ReportModel completo y devuelve un
ProcessedReport con solo los campos de alta relevancia analítica, reduciendo
ruido antes de gastar tokens de Claude.
"""
import json
import logging
import re
from typing import Any

import config

logger = logging.getLogger(__name__)

# Syscalls de alto valor (inyección, persistencia, evasión)
HIGH_VALUE_SYSCALLS = {
    "createremotethread", "writeprocessmemory", "virtualallocex",
    "ntunmapviewofsection", "setwindowshookex", "createservice",
    "ntcreatethreadex", "queueuserapc", "setthreadcontext",
    "ntmapviewofsection", "regsetvalue", "regsetvalueex",
}

# Syscalls genéricos de runtime que se descartan siempre
NOISE_SYSCALLS = {
    "getsystemtime", "heapalloc", "heapfree", "getlasterror",
    "loadlibrary", "loadlibrarya", "loadlibraryw", "getprocaddress",
    "readfile", "closehandle", "createfilemapping", "getmodulehandle",
}

# Paths de filesystem relevantes para malware
SUSPICIOUS_PATH_PATTERNS = re.compile(
    r"(\\temp\\|\\appdata\\|\\startup\\|\\system32\\|%temp%|%appdata%|%startup%)",
    re.IGNORECASE,
)
EXECUTABLE_EXTENSIONS = re.compile(r"\.(exe|dll|bat|ps1|vbs|scr|cmd|js|hta)$", re.IGNORECASE)

# Claves de registro relevantes para persistencia
PERSISTENCE_KEY_PATTERNS = re.compile(
    r"(\\run\\|\\run$|\\runonce|\\services\\|\\winlogon|browser helper objects"
    r"|image file execution options|\\currentversion\\run)",
    re.IGNORECASE,
)

# Indicadores de ofuscación en líneas de comando
OBFUSCATION_PATTERNS = re.compile(
    r"(-enc\b|-encodedcommand|frombase64string|iex\b|invoke-expression"
    r"|downloadstring|hidden|bypass|/c\s+start)",
    re.IGNORECASE,
)

# Ubicaciones legítimas del sistema (un .exe aquí no es sospechoso por su ruta)
KNOWN_GOOD_DIRS = re.compile(
    r"(%windir%|%systemroot%|\\windows\\|program files|programfiles|%programfiles)",
    re.IGNORECASE,
)
# Ubicaciones escribibles por el usuario donde el malware suele ejecutarse
USER_WRITABLE_DIRS = re.compile(
    r"(%temp%|%appdata%|%localappdata%|\\temp\\|\\appdata\\|\\downloads\\"
    r"|\\desktop\\|\\users\\public|\\public\\|programdata)",
    re.IGNORECASE,
)

# Máximo de procesos a incluir en el árbol (evita inundar el prompt)
MAX_PROCESS_TREE = 25


def _is_suspicious_process_path(image: str) -> bool:
    """True si el ejecutable corre desde una ubicación inusual para un proceso.

    Invierte la lógica del filtro FS: en vez de marcar System32 (donde viven
    procesos legítimos de Windows), marca lo que NO está en una ubicación
    conocida del sistema — TEMP, AppData, Desktop, o carpetas raíz aleatorias
    como C:\\kxygogy\\khkbqroz.exe.
    """
    if not image:
        return False
    low = image.lower()
    if USER_WRITABLE_DIRS.search(low):
        return True
    if KNOWN_GOOD_DIRS.search(low):
        return False
    # No está en una ubicación conocida del sistema y es un ejecutable
    return bool(EXECUTABLE_EXTENSIONS.search(low))


def filter_syscalls(raw_syscalls: list[dict]) -> list[str]:
    """Conserva solo syscalls de alto valor, máx MAX_SYSCALLS entradas."""
    result = []
    for call in raw_syscalls:
        name = str(call.get("name", call.get("api", ""))).lower()
        if not name or name in NOISE_SYSCALLS:
            continue
        if name in HIGH_VALUE_SYSCALLS or _has_suspicious_args(call):
            detail = call.get("args") or call.get("details") or ""
            entry = call.get("name", call.get("api", ""))
            if detail:
                entry = f"{entry}({json.dumps(detail, default=str)[:120]})"
            result.append(entry)
        if len(result) >= config.MAX_SYSCALLS:
            break
    return result


def _has_suspicious_args(call: dict) -> bool:
    """RegSetValue u operaciones con paths sospechosos en los argumentos."""
    args = json.dumps(call.get("args", ""), default=str)
    return bool(SUSPICIOUS_PATH_PATTERNS.search(args) or PERSISTENCE_KEY_PATTERNS.search(args))


def filter_filesystem(filesystem: list[dict]) -> list[str]:
    """Artefactos FS en paths sospechosos o con extensiones ejecutables."""
    result = []
    for item in filesystem:
        path = item.get("path", "")
        if not path:
            continue
        if SUSPICIOUS_PATH_PATTERNS.search(path) or EXECUTABLE_EXTENSIONS.search(path):
            op = item.get("operation", "write")
            result.append(f"[{op}] {path}")
        if len(result) >= config.MAX_FS_ARTIFACTS:
            break
    return result


def filter_registry(registry: list[dict]) -> list[str]:
    """Claves de registro con relevancia de persistencia."""
    result = []
    for item in registry:
        key = item.get("key", "")
        if not key:
            continue
        if PERSISTENCE_KEY_PATTERNS.search(key):
            value = item.get("value", "")
            entry = f"{key} = {value}" if value else key
            result.append(entry)
        if len(result) >= config.MAX_REGISTRY_ARTIFACTS:
            break
    return result


def filter_network(network: dict) -> dict:
    """La red se incluye completa, truncada a MAX_NETWORK_ENTRIES por tipo."""
    limit = config.MAX_NETWORK_ENTRIES
    return {
        "dns": network.get("dns", [])[:limit],
        "http": network.get("http", [])[:limit],
        "connections": network.get("connections", [])[:limit],
        "domains": network.get("domains", [])[:limit],
        "ips": network.get("ips", [])[:limit],
    }


def build_process_tree(processes: list[dict]) -> str:
    """Árbol de procesos en texto, marcando los anómalos.

    Incluye procesos con inyección, paths inusuales o cmd/powershell ofuscado;
    descarta procesos del SO sin comportamiento anómalo.
    """
    by_pid = {p.get("pid"): p for p in processes}
    interesting = []
    for proc in processes:
        cmd = proc.get("command_line", "")
        image = proc.get("image", "")
        anomalous = (
            proc.get("injects")
            or proc.get("loads_suspicious")
            or _is_suspicious_process_path(image)
            or OBFUSCATION_PATTERNS.search(cmd)
        )
        if anomalous or proc.get("network"):
            interesting.append(proc)

    if not interesting:
        interesting = processes[:10]  # fallback: primeros procesos del árbol
    interesting = interesting[:MAX_PROCESS_TREE]

    lines = []
    for proc in interesting:
        flags = []
        if proc.get("injects"):
            flags.append("INJECTS")
        if proc.get("loads_suspicious"):
            flags.append("SUSP_MODULES")
        if proc.get("network"):
            flags.append("NETWORK")
        flag_str = f" <{','.join(flags)}>" if flags else ""
        ppid = proc.get("ppid")
        parent = by_pid.get(ppid, {}).get("image", "") if ppid is not None else ""
        parent_str = f" (parent: {parent.split(chr(92))[-1]})" if parent else ""
        lines.append(
            f"[{proc.get('pid')}] {proc.get('image', '?')}{flag_str}{parent_str}\n"
            f"    cmd: {proc.get('command_line', '')[:200]}"
        )
    return "\n".join(lines)


def estimate_tokens(data: Any) -> int:
    """Estimación burda: ~4 caracteres por token."""
    return len(json.dumps(data, default=str)) // 4


def preprocess(report: dict[str, Any]) -> dict[str, Any]:
    """Punto de entrada de la Capa 2. ReportModel -> ProcessedReport."""
    processed = {
        "summary_fields": {
            "hash": report.get("sample_hash", ""),
            "filename": report.get("filename", ""),
            "score": report.get("score", 0),
            "platform": report.get("platform", ""),
            "sandbox_signatures": [
                s.get("name", "") for s in report.get("signatures", []) if s.get("name")
            ],
        },
        "high_value_syscalls": filter_syscalls(report.get("raw_syscalls", [])),
        "network_activity": filter_network(report.get("network", {})),
        "filesystem_artifacts": filter_filesystem(report.get("filesystem", [])),
        "registry_artifacts": filter_registry(report.get("registry", [])),
        "process_tree": build_process_tree(report.get("processes", [])),
        # La inteligencia de abuse.ch pasa sin filtrar: ya viene destilada
        "enrichment": report.get("enrichment"),
    }
    processed["token_count_estimate"] = estimate_tokens(processed)

    original_estimate = estimate_tokens(report)
    logger.info(
        "Preprocesado: ~%d tokens -> ~%d tokens (%.0f%% reducción)",
        original_estimate,
        processed["token_count_estimate"],
        100 * (1 - processed["token_count_estimate"] / max(original_estimate, 1)),
    )
    return processed
