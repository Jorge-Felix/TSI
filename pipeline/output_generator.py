"""Capa 6 — Generación de Outputs.

Transforma el AnalysisResult en los tres artefactos finales:
iocs_{hash}.csv (SIEM), report_{hash}.html (presentación, autocontenido)
y ttps_{hash}.json (ATT&CK Navigator).
"""
import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd
from jinja2 import Template

import config

logger = logging.getLogger(__name__)

HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Sandbox TL;DR — {{ filename }}</title>
<style>
  :root { --bg:#0f1419; --panel:#1a2129; --text:#e6e6e6; --muted:#8b98a5;
          --accent:#4fc3f7; --danger:#ef5350; --ok:#66bb6a; --warn:#ffa726; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text);
         font:15px/1.6 "Segoe UI",system-ui,sans-serif; padding:2rem; }
  .container { max-width:960px; margin:0 auto; }
  header { border-bottom:2px solid var(--accent); padding-bottom:1rem; margin-bottom:1.5rem; }
  h1 { font-size:1.5rem; } h1 small { color:var(--muted); font-weight:normal; }
  h2 { font-size:1.1rem; color:var(--accent); margin:1.5rem 0 .75rem;
       text-transform:uppercase; letter-spacing:.05em; }
  .meta { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
          gap:.75rem; margin-top:1rem; }
  .meta div { background:var(--panel); padding:.6rem .9rem; border-radius:6px; }
  .meta .label { color:var(--muted); font-size:.75rem; text-transform:uppercase; }
  .score { font-size:1.4rem; font-weight:bold;
           color:{{ '#ef5350' if score >= 70 else '#ffa726' if score >= 40 else '#66bb6a' }}; }
  .summary { background:var(--panel); border-left:4px solid var(--danger);
             padding:1rem; border-radius:0 6px 6px 0; font-size:1.05rem; }
  .narrative { background:var(--panel); padding:1.25rem; border-radius:6px;
               white-space:pre-wrap; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border-radius:6px; overflow:hidden; }
  th { background:#232d38; text-align:left; padding:.6rem .9rem; font-size:.8rem;
       text-transform:uppercase; color:var(--muted); }
  td { padding:.55rem .9rem; border-top:1px solid #2a3542; font-size:.9rem;
       word-break:break-all; }
  .conf-high { color:var(--ok); font-weight:bold; }
  .conf-medium { color:var(--warn); }
  .conf-low { color:var(--muted); }
  .ttp-id { color:var(--accent); font-family:Consolas,monospace; white-space:nowrap; }
  footer { margin-top:2rem; color:var(--muted); font-size:.8rem;
           border-top:1px solid #2a3542; padding-top:1rem; }
  .hash { font-family:Consolas,monospace; font-size:.8rem; word-break:break-all; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Sandbox TL;DR <small>— Automated Triage Report</small></h1>
    <div class="meta">
      <div><div class="label">Archivo</div>{{ filename }}</div>
      <div><div class="label">Score</div><span class="score">{{ score }}/100</span></div>
      <div><div class="label">Familia</div>{{ malware_family }}</div>
      <div><div class="label">Categoría</div>{{ threat_category }}</div>
    </div>
    <div class="meta" style="margin-top:.75rem">
      <div><div class="label">SHA256</div><span class="hash">{{ hash }}</span></div>
    </div>
  </header>

  <h2>Comportamiento principal</h2>
  <div class="summary">{{ behavior_summary }}</div>

  <h2>TTPs — MITRE ATT&amp;CK</h2>
  <table>
    <tr><th>Táctica</th><th>Técnica</th><th>Evidencia</th><th>Confianza</th></tr>
    {% for t in ttps %}
    <tr>
      <td class="ttp-id">{{ t.tactic }}</td>
      <td class="ttp-id">{{ t.technique }}</td>
      <td>{{ t.evidence }}</td>
      <td class="conf-{{ t.confidence }}">{{ t.confidence }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Análisis narrativo</h2>
  <div class="narrative">{{ narrative }}</div>

  <h2>Indicadores de Compromiso (IOCs)</h2>
  <table>
    <tr><th>Tipo</th><th>Valor</th><th>Confianza</th><th>Contexto</th></tr>
    {% for i in iocs %}
    <tr>
      <td>{{ i.type }}</td>
      <td class="hash">{{ i.value }}</td>
      <td class="conf-{{ i.confidence|lower }}">{{ i.confidence }}</td>
      <td>{{ i.context }}</td>
    </tr>
    {% endfor %}
  </table>

  <footer>
    Generado por Sandbox TL;DR (PoC) — B5-LABS / Never Off · Proyecto Final TSI ITLA<br>
    Costo del análisis: ${{ "%.4f"|format(cost) }} USD · Tiempo: {{ "%.1f"|format(time_s) }}s · Modelo: {{ model }}
  </footer>
</div>
</body>
</html>
""")


def _short_hash(result: dict[str, Any]) -> str:
    h = result.get("sample", {}).get("hash", "") or "sin_hash"
    return h[:16]


def generate_csv(result: dict[str, Any], out_dir: Path) -> Path:
    """iocs_{hash}.csv — importable en SIEM (Elastic, Sentinel, Splunk)."""
    path = out_dir / f"iocs_{_short_hash(result)}.csv"
    df = pd.DataFrame(result["iocs"], columns=["type", "value", "confidence", "context"])
    df.to_csv(path, index=False, encoding="utf-8")
    return path


def generate_html(result: dict[str, Any], out_dir: Path) -> Path:
    """report_{hash}.html — autocontenido (CSS embebido, sin dependencias)."""
    path = out_dir / f"report_{_short_hash(result)}.html"
    sample = result.get("sample", {})
    html = HTML_TEMPLATE.render(
        filename=sample.get("filename", "desconocido"),
        hash=sample.get("hash", "no disponible"),
        score=sample.get("score", 0),
        malware_family=result["malware_family"],
        threat_category=result["threat_category"],
        behavior_summary=result["behavior_summary"],
        ttps=result["ttps"],
        narrative=result["narrative"],
        iocs=result["iocs"],
        cost=result["analysis_cost_usd"],
        time_s=result["analysis_time_s"],
        model=config.CLAUDE_MODEL,
    )
    path.write_text(html, encoding="utf-8")
    return path


def generate_ttps_json(result: dict[str, Any], out_dir: Path) -> Path:
    """ttps_{hash}.json — TTPs limpios para MITRE ATT&CK Navigator."""
    path = out_dir / f"ttps_{_short_hash(result)}.json"
    payload = {
        "sample": result.get("sample", {}),
        "malware_family": result["malware_family"],
        "threat_category": result["threat_category"],
        "ttps": result["ttps"],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def generate_all(result: dict[str, Any]) -> dict[str, Path]:
    """Punto de entrada de la Capa 6. Genera los tres artefactos en output/."""
    out_dir = config.OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "csv": generate_csv(result, out_dir),
        "html": generate_html(result, out_dir),
        "json": generate_ttps_json(result, out_dir),
    }
    logger.info("Outputs generados en %s", out_dir)
    return paths
