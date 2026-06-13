# Sandbox TL;DR
## Automated Sandbox Report Summarization & TTP Extraction via LLM

**Documento de Arquitectura de PoC**
Proyecto Final de Grado TSI — ITLA
Versión 1.0 · B5-LABS / Never Off

---

> **Este documento es la fuente de verdad técnica para el desarrollo iterativo del PoC.**
> Cualquier instancia de LLM que lo reciba puede retomar el desarrollo desde cualquier punto.

---

## Tabla de Contenidos

1. [Visión General del Proyecto](#1-visión-general-del-proyecto)
2. [Restricciones y Decisiones de Diseño](#2-restricciones-y-decisiones-de-diseño)
3. [Arquitectura del Pipeline (6 Capas)](#3-arquitectura-del-pipeline-6-capas)
   - [Capa 1 — Ingesta](#capa-1--ingesta-report_ingestorpy)
   - [Capa 2 — Preprocesamiento](#capa-2--preprocesamiento-report_preprocessorpy)
   - [Capa 3 — Construcción de Prompt](#capa-3--construcción-de-prompt-prompt_builderpy)
   - [Capa 4 — Claude API](#capa-4--llamada-a-claude-api-claude_clientpy)
   - [Capa 5 — Parser de Respuesta](#capa-5--parser-de-respuesta-output_parserpy)
   - [Capa 6 — Generación de Outputs](#capa-6--generación-de-outputs-output_generatorpy)
4. [Estructura del Repositorio](#4-estructura-del-repositorio)
5. [Dependencias y Stack Técnico](#5-dependencias-y-stack-técnico)
6. [Flujo de Ejecución Completo](#6-flujo-de-ejecución-completo)
7. [Muestras de Malware para el PoC](#7-muestras-de-malware-para-el-poc)
8. [El Prompt de Análisis (Detalle Técnico)](#8-el-prompt-de-análisis-detalle-técnico)
9. [Plan de Desarrollo del PoC](#9-plan-de-desarrollo-del-poc)
10. [Referencia Rápida para Retomar el Desarrollo](#10-referencia-rápida-para-retomar-el-desarrollo)
11. [Criterios de Éxito del PoC](#11-criterios-de-éxito-del-poc)
- [Apéndice A — Estructura del JSON de Any.run](#apéndice-a--estructura-del-json-de-anyrun)
- [Apéndice B — Estructura del JSON de Triage API](#apéndice-b--estructura-del-json-de-triage-api)

---

## 1. Visión General del Proyecto

### 1.1 Problema que resuelve

Un analista de malware que trabaja con plataformas de sandbox como Any.run, Cuckoo Sandbox o Joe Sandbox enfrenta un problema consistente: un reporte típico de análisis dinámico puede contener entre 800 y 3,000 líneas de datos brutos, incluyendo llamadas a API del sistema operativo, eventos de red, cambios en el sistema de archivos y actividad del registro de Windows.

El proceso manual de triaje consume entre 30 y 60 minutos por muestra, en los que el analista extrae manualmente los 5 a 10 datos realmente accionables: comportamiento principal de la muestra, técnicas y tácticas de ataque (TTPs mapeadas a MITRE ATT&CK), e indicadores de compromiso (IOCs) concretos.

> **Impacto cuantificable del problema**
>
> - Tiempo de triaje manual por muestra: **30–60 minutos**
> - Volumen típico en un SOC activo: **10–30 muestras por turno**
> - Tiempo neto desperdiciado en lectura de ruido: **5–15 horas por analista por turno**
> - Objetivo del PoC: reducir el tiempo de triaje a **< 3 minutos** por muestra con un resumen accionable de una página

### 1.2 Propuesta de valor

Sandbox TL;DR es un pipeline de procesamiento local que ingiere el output JSON de plataformas de sandbox públicas y gratuitas, preprocesa el reporte para descartar ruido, construye un prompt estructurado usando el vocabulario de MITRE ATT&CK, y delega el análisis semántico a Claude (Anthropic API). El resultado es un resumen de una página en lenguaje natural más una tabla de IOCs lista para importar en un SIEM.

### 1.3 Alcance del PoC

El PoC no es un producto completo. Es una implementación funcional y demostrable que prueba la viabilidad técnica del pipeline completo.

| DENTRO del alcance del PoC | FUERA del alcance (producción futura) |
|---|---|
| Pipeline de análisis funcional end-to-end | Interfaz web o dashboard interactivo |
| Soporte para reportes de Any.run (export manual) | Base de datos de análisis histórico |
| Soporte para API gratuita de Triage (tria.ge) | Autenticación multi-usuario |
| Fixture JSON estático para demos sin conexión | Integración directa con SIEM vía API push |
| Extracción de TTPs con IDs de MITRE ATT&CK | Soporte para Joe Sandbox / Cuckoo cloud |
| Tabla de IOCs exportable como CSV | Análisis de tráfico PCAP o dumps de memoria |
| Reporte HTML legible para presentación | Modelo de IA local (Ollama / Llama) |
| Muestras reales de malware Windows | Ejecución paralela / procesamiento por lotes masivo |

---

## 2. Restricciones y Decisiones de Diseño

### 2.1 Restricciones no negociables del PoC

- Sin APIs de pago excepto **Claude API de Anthropic** (única integración externa con costo real).
- Sin infraestructura de servidores: todo el procesamiento corre **localmente** en la máquina del desarrollador (Windows o Linux).
- Sin modelos de IA locales (Ollama, llama.cpp): el análisis semántico está 100% delegado a Claude.
- Sin instalación de herramientas complejas de sandbox: el PoC consume reportes ya generados, no ejecuta malware directamente.
- El PoC debe ser ejecutable con **un comando simple desde la CLI** para demostración.

### 2.2 Justificación de fuentes de datos gratuitas

| Fuente | Cómo se obtiene el JSON | Costo | Limitación PoC |
|---|---|---|---|
| **Any.run** | Export manual desde la UI web (botón 'Export JSON') | Gratuito (cuenta free) | Manual, no automatizable sin API paid |
| **Triage (tria.ge)** | API REST pública con token gratuito. `GET /v0/samples/{id}/reports/triage` | Gratuito con registro | Rate limit generoso para PoC |
| **Fixture estático** | JSON pre-guardado de análisis reales (incluido en el repo) | Sin costo | No real-time, solo para demos |
| **Cuckoo local** | API local en `http://localhost:8090` si se despliega | Sin costo (open source) | Requiere VM Linux + instalación |

### 2.3 Justificación de Claude como motor de análisis

Se eligió Claude (Anthropic API) como el único componente de IA por las siguientes razones técnicas:

- **Ventana de contexto grande** (200K tokens en claude-sonnet): permite procesar reportes extensos sin fragmentación agresiva.
- **Capacidad de seguir instrucciones estructuradas de forma confiable**: el prompt builder puede forzar un formato de respuesta JSON + Markdown que el parser downstream espera.
- **Conocimiento embebido de ciberseguridad y MITRE ATT&CK**: el modelo reconoce patrones de comportamiento malicioso sin necesidad de fine-tuning.
- **Costo razonable para PoC**: un análisis típico consume 3,000–8,000 tokens, costando $0.01–$0.05 por muestra con el modelo Sonnet.

---

## 3. Arquitectura del Pipeline (6 Capas)

El pipeline está organizado en 6 capas modulares. Cada capa es un módulo Python independiente con una interfaz de entrada y salida bien definida. Esta separación permite escalar cada componente de forma independiente y swapear implementaciones sin romper el resto del sistema.

```
┌─────────────────────────────────────────────────────────────────┐
│  FUENTES (gratuitas / locales)                                  │
│  Any.run JSON  │  Triage API  │  Cuckoo local  │  Fixture       │
└───────────┬─────────┬──────────────┬───────────────┬────────────┘
            └─────────┴──────────────┴───────────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Capa 1: Ingesta       │
                    │  report_ingestor.py    │
                    │  → ReportModel         │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Capa 2: Preproceso    │
                    │  report_preprocessor  │
                    │  → ProcessedReport     │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Capa 3: Prompt        │
                    │  prompt_builder.py     │
                    │  → system_prompt +     │
                    │    user_message        │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Capa 4: Claude API    │  ← ÚNICO costo
                    │  claude_client.py      │
                    │  → raw_response        │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Capa 5: Parser        │
                    │  output_parser.py      │
                    │  → AnalysisResult      │
                    └───────────┬───────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
   ┌────────▼───────┐  ┌────────▼───────┐  ┌────────▼───────┐
   │  iocs_{h}.csv  │  │ report_{h}.html│  │  ttps_{h}.json │
   │  → SIEM import │  │  → Presentación│  │  → ATT&CK Nav  │
   └────────────────┘  └────────────────┘  └────────────────┘
```

---

### Capa 1 — Ingesta (`report_ingestor.py`)

**Responsabilidad:** Recibe el archivo de reporte desde cualquier fuente soportada y produce un modelo de datos interno normalizado (`ReportModel`) independiente de la fuente de origen. Esta es la capa de abstracción que aísla el resto del pipeline del formato específico de cada sandbox.

**Fuentes soportadas:**
- `any_run_json` — archivo JSON exportado manualmente desde la UI de Any.run
- `triage_api` — respuesta directa de la API REST de triage.community usando token gratuito
- `static_fixture` — archivo JSON pre-guardado en el directorio `fixtures/` del repositorio
- `[extensible] cuckoo_api` — respuesta de la API local de Cuckoo Sandbox en `localhost:8090`

**Estructura de salida (`ReportModel`):**

El ingestor produce siempre el mismo diccionario Python independiente de la fuente:

```python
report = {
    "source":       str,           # "any_run" | "triage" | "fixture"
    "sample_hash":  str,           # SHA256 de la muestra
    "filename":     str,           # nombre del archivo analizado
    "platform":     str,           # "windows10" | "windows11" | etc.
    "score":        int,           # 0-100 (maliciousness score del sandbox)
    "processes":    List[dict],    # árbol de procesos con PIDs y comandos
    "network":      dict,          # DNS queries, IPs, HTTP requests, domains
    "filesystem":   List[dict],    # archivos creados/modificados/eliminados
    "registry":     List[dict],    # claves de registro tocadas
    "signatures":   List[dict],    # firmas del sandbox con scores
    "raw_syscalls": List[dict],    # llamadas a API del SO (completo, sin filtrar)
}
```

---

### Capa 2 — Preprocesamiento (`report_preprocessor.py`)

**Responsabilidad:** Esta es la capa más importante del pipeline para el PoC. Recibe el `ReportModel` completo y devuelve un `ProcessedReport` con solo los campos de alta relevancia analítica. El objetivo es reducir el ruido antes de gastar tokens de Claude y mejorar la calidad del análisis al enfocarlo en lo que importa.

**Lógica de filtrado por categoría:**

| Categoría | Criterio de inclusión | Criterio de exclusión |
|---|---|---|
| **Syscalls** | `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`, `NtUnmapViewOfSection`, `SetWindowsHookEx`, `CreateService`, `RegSetValue` con paths sospechosos | Llamadas genéricas de runtime: `GetSystemTime`, `ReadFile` en paths del sistema, `HeapAlloc`, `GetLastError`, `LoadLibrary` de DLLs estándar |
| **Red** | Incluir todo: toda actividad de red es relevante para malware | N/A — se incluye completo pero se trunca si >50 entradas únicas |
| **Artefactos FS** | Archivos en: `%TEMP%`, `%APPDATA%`, `%STARTUP%`, `C:\Windows\System32`, rutas con extensiones ejecutables (`.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`) | Accesos de lectura a archivos del sistema existentes, operaciones en paths de Office/navegadores sin escritura |
| **Registro** | Claves en: `HKCU\Run`, `HKLM\Run`, `HKCU\RunOnce`, `Services`, `Winlogon`, `Browser Helper Objects`, `IFEO` | Claves de configuración de aplicaciones legítimas sin relevancia de persistencia |
| **Procesos** | Árboles con inyección detectada, procesos spawned desde paths inusuales, uso de `cmd.exe`/`powershell` con argumentos ofuscados | Procesos del sistema operativo sin comportamiento anómalo |

**Estructura de salida (`ProcessedReport`):**

```python
processed = {
    "summary_fields": {            # metadata concisa
        "hash":                str,
        "filename":            str,
        "score":               int,
        "platform":            str,
        "sandbox_signatures":  List[str],  # solo nombres/descripciones
    },
    "high_value_syscalls":  List[str],  # máx 40 entradas
    "network_activity":     dict,        # DNS, IPs, URLs, User-Agents
    "filesystem_artifacts": List[str],  # paths relevantes, máx 30
    "registry_artifacts":   List[str],  # claves relevantes, máx 20
    "process_tree":         str,         # árbol en formato texto
    "token_count_estimate": int,         # estimación para budget check
}
```

---

### Capa 3 — Construcción de Prompt (`prompt_builder.py`)

**Responsabilidad:** Construye el `system_prompt` y el `user_message` que se envían a Claude. Esta capa implementa la ingeniería de prompts que determina la calidad del análisis. El diseño del prompt es el componente más crítico del proyecto desde una perspectiva de resultados.

**Estructura del system prompt — cuatro secciones fijas:**

1. **Rol:** Analista senior de malware con expertise en Windows internals y MITRE ATT&CK. Tarea: analizar reportes preprocesados de sandbox y producir un resumen técnico accionable.

2. **Vocabulario:** Lista de todas las tácticas MITRE ATT&CK (TA0001–TA0043) y las técnicas más comunes. Esto guía al modelo a usar IDs correctos.

3. **Formato de respuesta forzado:** Instrucción explícita de responder con exactamente tres secciones: (1) bloque JSON con metadata y TTPs, (2) resumen en lenguaje natural de una sola página, (3) tabla Markdown de IOCs con columnas tipo/valor/confianza.

4. **Restricciones:** No inventar IOCs que no estén en el input. Si la evidencia es insuficiente para mapear un TTP con confianza, indicarlo explícitamente con `confidence: "low"`. No incluir texto especulativo sin base en los datos.

**Formato de respuesta esperado de Claude:**

```json
{
  "sample": { "hash": "...", "filename": "...", "score": 95 },
  "behavior_summary": "Una oración concisa del comportamiento principal",
  "ttps": [
    {
      "tactic":     "TA0003 Persistence",
      "technique":  "T1547.001 Registry Run Keys",
      "evidence":   "Escribe en HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "confidence": "high"
    }
  ],
  "malware_family":   "Remcos RAT (probable)",
  "threat_category":  "RAT | Spyware | Banker | Ransomware | Dropper | Other"
}
```

```
[RESUMEN EN LENGUAJE NATURAL — 200-300 palabras]
```

```markdown
| Tipo | Valor              | Confianza | Contexto             |
|------|--------------------|-----------|----------------------|
| IP   | 185.234.XX.XX      | Alta      | C2 communication     |
| Hash | SHA256:abc...      | Alta      | Sample hash          |
| URL  | http://evil.com/.. | Alta      | Payload download     |
| Path | C:\Users\...\m.exe | Alta      | Dropped executable   |
```

**Token budget enforcement:**

Si el `token_count_estimate` del `ProcessedReport` supera 80,000 tokens, el prompt builder activa el modo `chunked`: divide los syscalls y artefactos en dos llamadas consecutivas y combina las respuestas en el `output_parser`. Para el PoC, los reportes típicos de Any.run preprocesados quedan entre 2,000 y 8,000 tokens totales, bien dentro del límite.

---

### Capa 4 — Llamada a Claude API (`claude_client.py`)

**Responsabilidad:** Es la única capa que realiza una llamada externa. Encapsula toda la lógica de comunicación con la API de Anthropic: construcción del request, manejo de errores, reintentos con backoff exponencial, y logging del consumo de tokens.

**Configuración del cliente:**

```python
import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    system=system_prompt,
    messages=[{"role": "user", "content": user_message}]
)
```

**Manejo de errores:**

- `RateLimitError` — backoff exponencial con jitter, máximo 3 reintentos.
- `APIError 500/503` — reintento inmediato una vez, luego fallo con mensaje claro.
- Timeout — configurado en 120 segundos para reportes extensos.
- Respuesta vacía o malformada — se delega al `output_parser` que maneja el fallback.

**Logging de consumo:**

Cada llamada registra en `analysis_log.jsonl`: hash de la muestra, timestamp, `input_tokens`, `output_tokens`, costo estimado en USD, y tiempo de respuesta en segundos. Esto permite al presentador demostrar el costo real del PoC durante la defensa.

---

### Capa 5 — Parser de Respuesta (`output_parser.py`)

**Responsabilidad:** Extrae el JSON estructurado, el resumen en texto plano y la tabla de IOCs de la respuesta Markdown de Claude. Normaliza la salida a un formato `AnalysisResult` independiente del formato exacto de la respuesta.

**Algoritmo de extracción:**

1. Buscar el primer bloque delimitado por ` ```json ... ``` ` en la respuesta.
2. Parsear el bloque como JSON. Si falla, intentar extracción con regex de los campos clave.
3. Extraer el bloque de texto entre el cierre del JSON y el inicio de la tabla Markdown.
4. Parsear la tabla Markdown de IOCs usando el separador `|` como delimitador.
5. Construir el `AnalysisResult` combinando todos los campos extraídos.

**Estructura de salida (`AnalysisResult`):**

```python
result = {
    "sample":           dict,    # hash, filename, score
    "behavior_summary": str,     # resumen de una oración
    "malware_family":   str,     # familia detectada o "Unknown"
    "threat_category":  str,     # RAT | Banker | Ransomware | etc.
    "ttps":             List[dict],  # lista de TTPs con tactic/technique/evidence/confidence
    "narrative":        str,     # resumen completo en lenguaje natural
    "iocs":             List[dict],  # lista de IOCs con tipo/valor/confianza
    "analysis_cost_usd": float,  # costo estimado de la llamada API
    "analysis_time_s":  float,   # tiempo total de análisis en segundos
}
```

---

### Capa 6 — Generación de Outputs (`output_generator.py`)

**Responsabilidad:** A partir del `AnalysisResult`, genera los tres artefactos de salida del pipeline. Esta capa no realiza ningún análisis: solo transforma los datos estructurados en formatos consumibles.

| Output | Formato | Propósito |
|---|---|---|
| `iocs_{hash}.csv` | CSV con columnas: `type`, `value`, `confidence`, `context` | Importación directa en SIEM (Elasticsearch, Sentinel, Splunk) |
| `report_{hash}.html` | HTML autónomo con CSS embebido, tabla de TTPs, sección de IOCs, narrativa | Presentación en defensa, archivo de evidencia |
| `ttps_{hash}.json` | JSON limpio con array de TTPs mapeados a ATT&CK con IDs | Integración futura con MITRE ATT&CK Navigator |

> **Nota sobre el reporte HTML:** El archivo `report_{hash}.html` es el artefacto principal para la defensa del proyecto. Debe ser autocontenido (CSS embebido, sin dependencias externas) para poder abrirse en cualquier navegador sin conexión.

---

## 4. Estructura del Repositorio

```
sandbox-tldr/
├── main.py                    # Entry point del pipeline
├── config.py                  # Variables de entorno y configuración global
├── requirements.txt           # Dependencias del proyecto
├── .env.example               # Template para variables de entorno
├── README.md                  # Instrucciones de instalación y uso
│
├── pipeline/                  # Los 6 módulos del pipeline
│   ├── __init__.py
│   ├── report_ingestor.py     # Capa 1: Ingesta y normalización
│   ├── report_preprocessor.py # Capa 2: Filtrado y reducción de ruido
│   ├── prompt_builder.py      # Capa 3: Construcción de prompt ATT&CK
│   ├── claude_client.py       # Capa 4: Comunicación con Claude API
│   ├── output_parser.py       # Capa 5: Extracción de respuesta
│   └── output_generator.py    # Capa 6: Generación de CSV/HTML/JSON
│
├── fixtures/                  # JSONs estáticos para demos sin sandbox
│   ├── remcos_rat_sample.json
│   ├── redline_stealer_sample.json
│   └── ransomware_sample.json
│
├── prompts/                   # System prompts versionados
│   └── mitre_analyst_v1.txt
│
├── output/                    # Directorio de outputs generados (gitignored)
│   └── .gitkeep
│
└── tests/                     # Tests unitarios por capa
    ├── test_ingestor.py
    ├── test_preprocessor.py
    ├── test_prompt_builder.py
    └── test_output_parser.py
```

---

## 5. Dependencias y Stack Técnico

### 5.1 Dependencias Python (`requirements.txt`)

| Paquete | Versión mínima | Uso en el pipeline |
|---|---|---|
| `anthropic` | 0.25.0 | SDK oficial para Claude API (Capa 4) |
| `requests` | 2.31.0 | HTTP client para Triage API (Capa 1) |
| `beautifulsoup4` | 4.12.0 | Parsing de HTML si se ingesta reporte HTML de Any.run (Capa 1) |
| `pandas` | 2.0.0 | Generación del CSV de IOCs (Capa 6) |
| `jinja2` | 3.1.0 | Templates para el reporte HTML (Capa 6) |
| `python-dotenv` | 1.0.0 | Carga de variables de entorno desde `.env` |
| `pytest` | 7.0.0 | Framework de tests unitarios |
| `rich` | 13.0.0 | Output formateado en consola para el CLI |

### 5.2 Variables de entorno (`.env`)

```bash
ANTHROPIC_API_KEY=sk-ant-...   # Obligatorio: clave de Claude API
TRIAGE_API_TOKEN=...           # Opcional: token gratuito de tria.ge
DEFAULT_SOURCE=fixture         # "any_run" | "triage" | "fixture"
OUTPUT_DIR=./output            # Directorio de salida
LOG_LEVEL=INFO                 # DEBUG | INFO | WARNING
```

### 5.3 Versión de Python y compatibilidad

- Python **3.11 o superior** requerido.
- Desarrollado y probado en Windows 11 y Ubuntu 22.04.
- Sin dependencias de sistema operativo: corre en cualquier entorno con Python instalado.

---

## 6. Flujo de Ejecución Completo

### 6.1 Casos de uso del CLI

**Caso 1 — Análisis de fixture estático (demo offline):**
```bash
python main.py --source fixture --sample remcos_rat_sample
```
Carga `fixtures/remcos_rat_sample.json`, ejecuta el pipeline completo, y genera los tres outputs en `output/`. No requiere conexión a internet ni API keys del sandbox.

**Caso 2 — Análisis de JSON exportado de Any.run:**
```bash
python main.py --source any_run --file /path/to/anyrun_export.json
```
Ingesta el JSON exportado manualmente desde la interfaz de Any.run. El usuario descarga el archivo desde el panel de resultados después de ejecutar la muestra en el sandbox gratuito.

**Caso 3 — Análisis via Triage API (automático):**
```bash
python main.py --source triage --sample-id 240101-abc123
```
Consulta directamente la API de triage.community usando el sample ID. Requiere `TRIAGE_API_TOKEN` en el `.env`. El token es gratuito con registro en tria.ge.

### 6.2 Flujo interno paso a paso

| Paso | Módulo | Acción |
|---|---|---|
| 1 | `main.py` | Parsea argumentos CLI. Determina la fuente (`fixture`/`any_run`/`triage`). |
| 2 | `report_ingestor.py` | Carga el JSON crudo desde la fuente correspondiente. Normaliza al modelo `ReportModel`. |
| 3 | `report_preprocessor.py` | Filtra syscalls irrelevantes. Extrae red, artefactos, registro y árbol de procesos. Estima token count. |
| 4 | `prompt_builder.py` | Construye `system_prompt` con contexto MITRE ATT&CK. Construye `user_message` con el `ProcessedReport` serializado. Verifica token budget. |
| 5 | `claude_client.py` | Realiza la llamada a Claude API. Registra tokens consumidos y tiempo. Maneja errores con reintentos. |
| 6 | `output_parser.py` | Extrae el bloque JSON de la respuesta. Extrae narrativa y tabla de IOCs. Construye `AnalysisResult`. |
| 7 | `output_generator.py` | Genera `iocs_{hash}.csv`, `report_{hash}.html` y `ttps_{hash}.json` en el directorio `output/`. |
| 8 | `main.py` | Imprime resumen en consola con Rich: TTPs detectadas, IOCs extraídos, costo de análisis, paths de outputs. |

---

## 7. Muestras de Malware para el PoC

### 7.1 Muestras recomendadas para los fixtures

| Familia | Categoría | Por qué elegirla | Fuente de reporte sugerida |
|---|---|---|---|
| **Remcos RAT** | RAT / Spyware | Comportamiento rico: persistencia, keylogging, network C2. Muy común en el wild. | Any.run: buscar `remcos` en public tasks |
| **RedLine Stealer** | Infostealer | IOCs de red muy claros, acceso a credenciales y wallets. Excelente para demostrar extracción de IOCs. | Triage: buscar `redline` en reports recientes |
| **AsyncRAT** | RAT | Proceso de inyección bien documentado, uso de Run key para persistencia, comunicación cifrada. | Any.run: public tasks |
| **AgentTesla** | Infostealer/Keylogger | Múltiples TTPs demostrables, exfiltración via SMTP/FTP, alta prevalencia en campañas actuales. | Triage o Any.run |

### 7.2 Cómo obtener el JSON de Any.run

1. Ir a [app.any.run](https://app.any.run) y crear una cuenta gratuita.
2. En la barra de búsqueda pública, buscar por nombre de familia (ej. `remcos`) o por hash SHA256 conocido.
3. Abrir un análisis existente de acceso público.
4. En el panel de resultados, hacer clic en **Export → Export JSON report**. Guardar como `fixtures/nombre_muestra.json`.

> **Importante sobre el formato JSON de Any.run:**
>
> El JSON exportado de Any.run tiene una estructura diferente al JSON de Triage API. El `report_ingestor.py` debe manejar ambos formatos y normalizarlos al mismo `ReportModel` interno. Verificar siempre la estructura del JSON antes de programar el parser con las claves específicas.
>
> Las claves principales del JSON de Any.run son: `"analysis"`, `"processes"`, `"network"` (con sub-claves `"dns"`, `"http"`, `"connections"`), y `"modified"` para artefactos del sistema.

---

## 8. El Prompt de Análisis (Detalle Técnico)

### 8.1 System prompt completo (v1)

Guardar en `prompts/mitre_analyst_v1.txt`:

```
Eres un analista senior de malware especializado en Windows con profundo
conocimiento del framework MITRE ATT&CK. Tu rol es analizar reportes
preprocesados de sandbox y producir análisis técnicos accionables.

FORMATO DE RESPUESTA OBLIGATORIO:
Tu respuesta DEBE tener exactamente estas tres secciones en este orden:

SECCIÓN 1: Bloque JSON con la estructura exacta indicada por el usuario.
SECCIÓN 2: Narrativa técnica de 150-300 palabras en español describiendo el
comportamiento de la muestra, su impacto potencial, y el contexto de amenaza.
SECCIÓN 3: Tabla Markdown de IOCs con columnas: Tipo | Valor | Confianza | Contexto

REGLAS CRÍTICAS:
1. Solo extrae IOCs que estén explícitamente presentes en los datos del reporte.
2. Si la evidencia no es suficiente para asignar un TTP con certeza, usa
   confidence: "low" y explica la limitación en el campo "evidence".
3. Usa SIEMPRE los IDs exactos de MITRE ATT&CK (ej. T1055.001, no "injection").
4. La tactic debe incluir el ID y el nombre completo (ej. "TA0003 Persistence").
5. No incluyas texto especulativo ni suposiciones no respaldadas por los datos.
```

### 8.2 Tácticas MITRE ATT&CK incluidas en el system prompt

El prompt debe incluir la lista completa de tácticas y las técnicas más relevantes para malware Windows:

| ID Táctica | Nombre | Técnicas más comunes en malware Windows |
|---|---|---|
| TA0001 | Initial Access | T1566 Phishing, T1189 Drive-by Compromise |
| TA0002 | Execution | T1059 Command and Scripting, T1204 User Execution, T1053 Scheduled Task |
| TA0003 | Persistence | T1547 Boot Autostart (Run Keys), T1543 System Services, T1574 Hijack Execution |
| TA0004 | Privilege Escalation | T1055 Process Injection, T1134 Token Manipulation, T1548 Bypass UAC |
| TA0005 | Defense Evasion | T1027 Obfuscation, T1562 Impair Defenses, T1070 Indicator Removal |
| TA0006 | Credential Access | T1003 OS Credential Dumping, T1056 Input Capture (Keylogging), T1539 Steal Browser Cookies |
| TA0007 | Discovery | T1082 System Info Discovery, T1083 File and Dir Discovery, T1057 Process Discovery |
| TA0008 | Lateral Movement | T1021 Remote Services, T1080 Taint Shared Content |
| TA0010 | Exfiltration | T1041 Exfil Over C2, T1048 Exfil Over Alt Protocol, T1567 Exfil Over Web Service |
| TA0011 | Command and Control | T1071 App Layer Protocol, T1573 Encrypted Channel, T1095 Non-Standard Port |

---

## 9. Plan de Desarrollo del PoC

### 9.1 Fases de desarrollo

| Fase | Nombre | Entregable al finalizar | Estimado |
|---|---|---|---|
| **Fase 1** | Skeleton + Fixture | `main.py` funcional con fixture hardcoded, llama a Claude, imprime respuesta cruda en consola. | 1–2 días |
| **Fase 2** | Preprocesador + Prompt | Pipeline completo con `preprocessor` y `prompt_builder`. Output JSON en consola estructurado correctamente. | 2–3 días |
| **Fase 3** | Outputs + Any.run Parser | Generación de CSV y HTML funcionales. Ingestor de Any.run JSON testeado con muestra real. | 2–3 días |
| **Fase 4** | Triage API + Pulido | Integración con Triage API. CLI pulido con Rich. README con instrucciones completas. | 1–2 días |

### 9.2 Orden de desarrollo recomendado (dentro de Fase 1)

1. **`config.py` + `.env`** — Variables de entorno y configuración global. Base de todo lo demás.
2. **`fixtures/`** — Obtener y guardar 2–3 JSONs reales de Any.run para tener datos de prueba antes de escribir código.
3. **`claude_client.py`** — Verificar que la API key funciona con una llamada mínima antes de construir el pipeline.
4. **`report_ingestor.py`** — Parser del fixture para producir el `ReportModel`. Testear con print statements.
5. **`report_preprocessor.py`** — Filtros de syscalls y artefactos. Comparar token count antes/después.
6. **`prompt_builder.py`** — System prompt con MITRE ATT&CK. Iterar la ingeniería de prompts hasta obtener respuestas bien estructuradas.
7. **`output_parser.py` + `output_generator.py`** — Parsear la respuesta y generar los archivos de salida.
8. **`main.py`** — Integrar todo el pipeline con argparse y Rich.

---

## 10. Referencia Rápida para Retomar el Desarrollo

### 10.1 Checklist de estado del PoC

Actualizar este checklist conforme avanza el desarrollo. Al retomar el proyecto con un LLM, compartir el estado actual.

| # | Componente | Estado | Notas |
|---|---|---|---|
| 1 | `config.py` + `.env` configurado | `[ ]` Pendiente | |
| 2 | Fixture JSON de Any.run (remcos) | `[ ]` Pendiente | |
| 3 | Fixture JSON de Any.run (redline) | `[ ]` Pendiente | |
| 4 | `claude_client.py` — llamada base | `[ ]` Pendiente | |
| 5 | `report_ingestor.py` — parser any_run | `[ ]` Pendiente | |
| 6 | `report_ingestor.py` — parser triage | `[ ]` Pendiente | |
| 7 | `report_preprocessor.py` — filtros | `[ ]` Pendiente | |
| 8 | `prompt_builder.py` — system prompt v1 | `[ ]` Pendiente | |
| 9 | `output_parser.py` — extracción JSON | `[ ]` Pendiente | |
| 10 | `output_generator.py` — CSV + HTML | `[ ]` Pendiente | |
| 11 | `main.py` — CLI completo | `[ ]` Pendiente | |
| 12 | Test con muestra Remcos real | `[ ]` Pendiente | |
| 13 | Test con muestra RedLine real | `[ ]` Pendiente | |
| 14 | Integración Triage API | `[ ]` Pendiente | |
| 15 | Reporte HTML final pulido | `[ ]` Pendiente | |

### 10.2 Contexto clave para el LLM al retomar el proyecto

> **Instrucciones para LLM que retoma el desarrollo**
>
> Este es el proyecto final de grado TSI del ITLA (Instituto Tecnológico de Las Américas) de Jorge, estudiante de último semestre en transición a un rol de threat hunting en Never Off, partner de SentinelOne en República Dominicana.
>
> El proyecto se llama **Sandbox TL;DR**. Es un **pipeline Python de 6 capas** que automatiza la extracción de TTPs e IOCs de reportes de sandbox usando Claude API.
>
> **Restricciones clave:**
> - La ÚNICA API externa de pago es **Claude**. Todo lo demás es local o usa fuentes gratuitas.
> - El modelo a usar es `claude-sonnet-4-20250514` con `max_tokens=4096`.
> - Los fixtures deben ser JSONs **reales** de Any.run o Triage. NO usar datos sintéticos para la demostración.
>
> **Convenciones del proyecto:**
> - Seguir la estructura de módulos descrita en la Sección 4 de este documento.
> - El system prompt de MITRE ATT&CK está en `prompts/mitre_analyst_v1.txt`. Al iterar el prompt, crear versiones nuevas (`v2`, `v3`) sin sobreescribir.
> - Los diccionarios de datos internos (`ReportModel`, `ProcessedReport`, `AnalysisResult`) son contratos entre capas: no modificar las claves sin actualizar todos los módulos que las consumen.

---

## 11. Criterios de Éxito del PoC

### 11.1 Criterios técnicos mínimos

- El pipeline procesa un JSON de Any.run de extremo a extremo sin errores.
- El `output_parser` extrae correctamente al menos 3 TTPs con IDs de MITRE ATT&CK válidos de una muestra de Remcos RAT.
- La tabla de IOCs contiene al menos 3 entradas válidas (IP, URL o hash) extraídas del reporte.
- El archivo HTML generado se abre en un navegador sin errores y presenta la información de forma clara y profesional.
- El CSV de IOCs se importa correctamente en cualquier herramienta de SIEM o puede ser validado en VirusTotal.
- El tiempo total de análisis (desde input hasta outputs) es menor a **30 segundos** para un reporte típico.

### 11.2 Criterios para la defensa académica

- **Demo en vivo:** ejecutar el pipeline en tiempo real durante la presentación con un fixture de Remcos RAT o RedLine Stealer.
- **Comparación cuantificable:** mostrar el reporte crudo de Any.run (40+ páginas) vs el output del pipeline (1 página) para demostrar el problema que resuelve.
- **Explicación de la ingeniería de prompts:** demostrar cómo el system prompt guía al modelo a usar los IDs correctos de MITRE ATT&CK.
- **Costo real del análisis:** mostrar el log de tokens consumidos y el costo en USD de 2–3 análisis para demostrar viabilidad económica.
- **Escalabilidad:** explicar cómo el pipeline de 6 capas permite agregar nuevas fuentes de sandbox (Cuckoo, Joe Sandbox) solo modificando la Capa 1.

---

## Apéndice A — Estructura del JSON de Any.run

Referencia de las claves principales del JSON exportado por Any.run para facilitar la implementación del ingestor:

```json
{
  "analysis": {
    "content": {
      "mainObject": {
        "filename": "malware.exe",
        "hashes": { "sha256": "abc123..." }
      },
      "maliciousness": 100
    },
    "scores": {
      "verdict": { "threatLevel": 2, "score": 95 }
    }
  },
  "processes": [
    {
      "pid": 1234,
      "ppid": 5678,
      "image": "C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe",
      "commandLine": "malware.exe --config C2:port",
      "scores": {
        "specs": {
          "injects": true,
          "loadsSusp": true,
          "network": true
        }
      },
      "modules": [
        { "image": "C:\\Windows\\System32\\ntdll.dll", "status": "loaded" }
      ]
    }
  ],
  "network": {
    "dns": [
      { "domain": "evil-c2.com", "ips": ["185.234.XX.XX"] }
    ],
    "http": [
      {
        "url": "http://evil-c2.com/gate.php",
        "method": "POST",
        "status": 200,
        "data": "encrypted_blob"
      }
    ],
    "connections": [
      { "remoteIp": "185.234.XX.XX", "port": 4782, "protocol": "tcp" }
    ]
  },
  "incidents": [
    { "title": "Possible use of process hollowing", "threatlevel": 3 },
    { "title": "Connects to C2 server", "threatlevel": 3 }
  ]
}
```

---

## Apéndice B — Estructura del JSON de Triage API

Referencia de la respuesta de la API REST de tria.ge:

```
Endpoint: GET https://tria.ge/api/v0/samples/{sample_id}/reports/triage
Header:   Authorization: Bearer {TRIAGE_API_TOKEN}
```

```json
{
  "analysis": {
    "score": 10,
    "family": ["remcos"],
    "tags": ["rat", "keylogger", "persistence"]
  },
  "targets": [
    {
      "iocs": {
        "urls":    ["http://evil-c2.com/gate.php"],
        "domains": ["evil-c2.com"],
        "ips":     ["185.234.XX.XX"]
      },
      "signatures": [
        { "label": "persistence-registry", "score": 9 },
        { "label": "infostealer-clipboard", "score": 8 },
        { "label": "network-cnc-generic", "score": 10 }
      ]
    }
  ],
  "processes": [
    {
      "pid":  1234,
      "ppid": 5678,
      "name": "malware.exe",
      "cmd":  "malware.exe --config ...",
      "injected": true
    }
  ]
}
```

> **Diferencias clave entre Any.run y Triage que el ingestor debe manejar:**
>
> | Campo | Any.run | Triage |
> |---|---|---|
> | Score | `analysis.scores.verdict.score` (0–100) | `analysis.score` (0–10) |
> | SHA256 | `analysis.content.mainObject.hashes.sha256` | No incluido en el report (consultar endpoint separado) |
> | Familia | Detectada via `incidents` | Directa en `analysis.family[]` |
> | IOCs de red | Dentro de `network.dns`, `network.http`, `network.connections` | Consolidados en `targets[].iocs` |
> | Árbol de procesos | `processes[]` con `pid`/`ppid`/`image`/`commandLine` | `processes[]` con `pid`/`ppid`/`name`/`cmd` |

---

*Documento generado para B5-LABS / Never Off — Proyecto Final TSI ITLA*
*Versión 1.0 — Para uso interno del proyecto*
