# Sandbox TL;DR

**Automated Sandbox Report Summarization & TTP Extraction via LLM**
Proyecto Final de Grado TSI — ITLA · B5-LABS / Never Off

Pipeline Python de 6 capas que ingiere reportes JSON de plataformas de sandbox
(Any.run, Triage), filtra el ruido, y usa Claude API para extraer TTPs mapeadas
a MITRE ATT&CK e IOCs accionables. Reduce el triaje manual de 30-60 minutos a
menos de 3 minutos por muestra.

## Instalación

```bash
pip install -r requirements.txt
copy .env.example .env
# Editar .env y añadir:
#   ANTHROPIC_API_KEY   (https://console.anthropic.com)
#   VIRUSTOTAL_API_KEY  (https://www.virustotal.com — free tier)
```

Requiere Python 3.11+.

## Uso

```bash
# Fuente principal: VirusTotal por hash (free tier, 4 req/min)
python main.py --source virustotal --hash <sha256>

# Demo offline con fixture estático (JSON real guardado en fixtures/)
python main.py --source fixture --sample remcos_rat_sample

# Via API de tria.ge (requiere TRIAGE_API_TOKEN en .env)
python main.py --source triage --sample-id 240101-abc123

# JSON exportado desde la UI de Any.run (export ahora es de pago)
python main.py --source any_run --file C:/ruta/anyrun_export.json

# Ver el prompt generado sin gastar tokens (no requiere API key)
python main.py --source fixture --sample remcos_rat_sample --dry-run
```

## Fuentes de datos

| Fuente | `--source` | Estado | Notas |
|---|---|---|---|
| **VirusTotal v3** | `virustotal` | Gratis (free tier) | Principal. `behaviour_summary` por hash. 4 req/min |
| **Triage (tria.ge)** | `triage` | Gratis (cuenta Researcher) | Reporte JSON completo por sample ID |
| **Fixture estático** | `fixture` | Sin costo | JSON real guardado en `fixtures/` para demo offline |
| **Any.run** | `any_run` | Export de pago | Solo si tienes un JSON ya exportado |

Cada fuente se normaliza al mismo `ReportModel` en la Capa 1, así que el resto
del pipeline es idéntico para todas.

## Enriquecimiento de contexto (abuse.ch)

Entre la Capa 1 y la 2, el pipeline enriquece la muestra con inteligencia de
**MalwareBazaar** (atribución de familia, tags, reglas YARA, vendors) y
**ThreatFox** (IOCs/C2 conocidos) — ambos de abuse.ch con un solo Auth-Key
gratuito de [auth.abuse.ch](https://auth.abuse.ch). Esto se inyecta en el prompt
como una sección `## INTELIGENCIA DE AMENAZAS` para que Claude corrobore familia
e IOCs en vez de especular.

- Se activa solo si `ABUSECH_AUTH_KEY` está en `.env`; degrada con gracia si no.
- Desactívalo con `--no-enrich`.

## Outputs (en `output/`)

| Archivo | Propósito |
|---|---|
| `iocs_{hash}.csv` | Importación directa en SIEM |
| `report_{hash}.html` | Reporte autocontenido para presentación |
| `ttps_{hash}.json` | TTPs para MITRE ATT&CK Navigator |

El consumo de tokens y costo por análisis se registra en `analysis_log.jsonl`.

## Obtener fixtures reales

La forma más simple es guardar la respuesta de VirusTotal de un hash conocido:

1. Crear cuenta gratuita en [virustotal.com](https://www.virustotal.com) y copiar el API key
2. Buscar un hash de una familia conocida (ej. Remcos, RedLine) en VT o MalwareBazaar
3. Guardar el JSON de `GET /files/{sha256}/behaviour_summary` como
   `fixtures/remcos_rat_sample.json` (el ingestor autodetecta el formato VT)

> Los fixtures deben ser JSONs **reales** de VirusTotal o Triage. No usar datos
> sintéticos para la demostración.

## Tests

```bash
pytest tests/ -v
```

## Arquitectura

```
fuente (any_run | triage | fixture)
  → Capa 1: report_ingestor      (normaliza → ReportModel)
  → Capa 2: report_preprocessor  (filtra ruido → ProcessedReport)
  → Capa 3: prompt_builder       (system + user prompt con vocabulario ATT&CK)
  → Capa 4: claude_client        (única llamada externa, retry + logging)
  → Capa 5: output_parser        (extrae JSON/narrativa/IOCs → AnalysisResult)
  → Capa 6: output_generator     (CSV + HTML + JSON)
```

Ver `Sandbox_TLDR_Arquitectura_PoC.md` para el documento de arquitectura completo.

> **Nota de modelo:** el documento de arquitectura v1.0 especifica
> `claude-sonnet-4-20250514`, que está deprecado (retiro: 15-jun-2026).
> Este código usa su reemplazo directo `claude-sonnet-4-6` (configurable
> vía `CLAUDE_MODEL` en `.env`).
