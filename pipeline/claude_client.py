"""Capa 4 — Llamada a Claude API.

Única capa con llamada externa. Encapsula la comunicación con Anthropic:
construcción del request, manejo de errores, reintentos y logging de consumo
en analysis_log.jsonl.
"""
import json
import logging
import random
import time
from datetime import datetime, timezone
from typing import Any

import anthropic

import config

logger = logging.getLogger(__name__)

MAX_RETRIES = 3


def _log_usage(sample_hash: str, usage: Any, elapsed: float) -> dict[str, float]:
    """Registra consumo de tokens y costo estimado en analysis_log.jsonl."""
    input_tokens = getattr(usage, "input_tokens", 0)
    output_tokens = getattr(usage, "output_tokens", 0)
    cost = (
        input_tokens * config.COST_INPUT_PER_MTOK
        + output_tokens * config.COST_OUTPUT_PER_MTOK
    ) / 1_000_000

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sample_hash": sample_hash,
        "model": config.CLAUDE_MODEL,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_usd": round(cost, 6),
        "response_time_s": round(elapsed, 2),
    }
    with open(config.ANALYSIS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    logger.info("Análisis: %d in / %d out tokens, $%.4f, %.1fs",
                input_tokens, output_tokens, cost, elapsed)
    return {"cost_usd": cost, "response_time_s": elapsed}


def analyze(system_prompt: str, user_message: str,
            sample_hash: str = "") -> tuple[str, dict[str, float]]:
    """Punto de entrada de la Capa 4.

    Devuelve (raw_response_text, metrics) donde metrics tiene cost_usd y
    response_time_s. Lanza RuntimeError con mensaje claro si falla.
    """
    if not config.validate_api_key():
        raise RuntimeError(
            "ANTHROPIC_API_KEY no está configurada. Copia .env.example a .env "
            "y añade tu clave de https://console.anthropic.com"
        )

    client = anthropic.Anthropic(
        api_key=config.ANTHROPIC_API_KEY,
        timeout=config.API_TIMEOUT_SECONDS,
        max_retries=0,  # reintentos manuales para controlar el backoff
    )

    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES):
        start = time.monotonic()
        try:
            response = client.messages.create(
                model=config.CLAUDE_MODEL,
                max_tokens=config.MAX_TOKENS,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}],
            )
            elapsed = time.monotonic() - start
            metrics = _log_usage(sample_hash, response.usage, elapsed)
            text = "".join(
                block.text for block in response.content if block.type == "text"
            )
            if not text.strip():
                raise RuntimeError("Claude devolvió una respuesta vacía")
            return text, metrics

        except anthropic.RateLimitError as e:
            last_error = e
            delay = min(2 ** attempt + random.uniform(0, 1), 30)
            logger.warning("Rate limit (intento %d/%d), esperando %.1fs",
                           attempt + 1, MAX_RETRIES, delay)
            time.sleep(delay)
        except anthropic.APIStatusError as e:
            last_error = e
            if e.status_code >= 500 and attempt == 0:
                logger.warning("Error %d del servidor, reintentando una vez",
                               e.status_code)
                continue
            raise RuntimeError(f"Error de la API de Claude ({e.status_code}): "
                               f"{e.message}") from e
        except anthropic.APIConnectionError as e:
            raise RuntimeError(
                "No se pudo conectar a la API de Anthropic. Verifica tu "
                "conexión a internet."
            ) from e

    raise RuntimeError(f"Falló tras {MAX_RETRIES} reintentos: {last_error}")
