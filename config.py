"""Configuración global de Sandbox TL;DR.

Carga variables de entorno desde .env y expone la configuración
que consumen todas las capas del pipeline.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

# Raíz del proyecto (directorio donde vive este archivo)
PROJECT_ROOT = Path(__file__).resolve().parent

load_dotenv(PROJECT_ROOT / ".env")

# --- Claude API ---
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
# Nota: el documento de arquitectura v1.0 especificaba claude-sonnet-4-20250514,
# pero ese modelo está deprecado (se retira el 15-jun-2026). Reemplazo directo:
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "4096"))
API_TIMEOUT_SECONDS = int(os.getenv("API_TIMEOUT_SECONDS", "120"))

# --- Triage API (opcional, Fase 4) ---
TRIAGE_API_TOKEN = os.getenv("TRIAGE_API_TOKEN", "")
TRIAGE_API_BASE = "https://tria.ge/api/v0"

# --- VirusTotal API v3 (fuente principal gratuita) ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_API_BASE = "https://www.virustotal.com/api/v3"

# --- abuse.ch: MalwareBazaar + ThreatFox (enriquecimiento, un solo Auth-Key) ---
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"

# Máximo de IOCs a pivotear por tipo (respeta el fair-use de abuse.ch)
PIVOT_MAX_IPS = 5
PIVOT_MAX_DOMAINS = 5

# --- Fuentes y rutas ---
DEFAULT_SOURCE = os.getenv("DEFAULT_SOURCE", "fixture")  # any_run | triage | fixture
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", str(PROJECT_ROOT / "output")))
FIXTURES_DIR = PROJECT_ROOT / "fixtures"
PROMPTS_DIR = PROJECT_ROOT / "prompts"
ANALYSIS_LOG = PROJECT_ROOT / "analysis_log.jsonl"

# --- Logging ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# --- Límites del preprocesador (Capa 2) ---
MAX_SYSCALLS = 40
MAX_FS_ARTIFACTS = 30
MAX_REGISTRY_ARTIFACTS = 20
MAX_NETWORK_ENTRIES = 50

# --- Token budget (Capa 3) ---
TOKEN_BUDGET_LIMIT = 80_000

# --- Costos para estimación (USD por millón de tokens, claude-sonnet-4-6) ---
COST_INPUT_PER_MTOK = 3.00
COST_OUTPUT_PER_MTOK = 15.00


def validate_api_key() -> bool:
    """True si hay una API key configurada (no valida contra el servidor)."""
    return bool(ANTHROPIC_API_KEY)
