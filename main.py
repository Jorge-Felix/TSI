"""Sandbox TL;DR — Entry point del pipeline.

Uso:
  python main.py --source fixture --sample remcos_rat_sample
  python main.py --source virustotal --hash <sha256>
  python main.py --source any_run --file C:/ruta/anyrun_export.json
  python main.py --source triage --sample-id 240101-abc123
"""
import argparse
import logging
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import config
from pipeline import (
    claude_client,
    enrichment,
    output_generator,
    output_parser,
    prompt_builder,
    report_ingestor,
    report_preprocessor,
)

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sandbox-tldr",
        description="Automated Sandbox Report Summarization & TTP Extraction via LLM",
    )
    parser.add_argument("--source", choices=["fixture", "virustotal", "any_run", "triage"],
                        default=config.DEFAULT_SOURCE,
                        help="Fuente del reporte (default: %(default)s)")
    parser.add_argument("--sample", help="Nombre del fixture (sin .json) para --source fixture")
    parser.add_argument("--hash", dest="sample_hash",
                        help="SHA256 de la muestra para --source virustotal")
    parser.add_argument("--file", help="Ruta al JSON exportado de Any.run para --source any_run")
    parser.add_argument("--sample-id", help="Sample ID de tria.ge para --source triage")
    parser.add_argument("--prompt-version", default=prompt_builder.PROMPT_VERSION,
                        help="Versión del system prompt en prompts/ (default: %(default)s)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Ejecuta capas 1-3 e imprime el prompt sin llamar a la API")
    parser.add_argument("--no-enrich", action="store_true",
                        help="Omite el enriquecimiento con abuse.ch (MalwareBazaar/ThreatFox)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Logging DEBUG")
    return parser.parse_args()


def print_summary(result: dict, paths: dict) -> None:
    sample = result.get("sample", {})
    console.print(Panel(
        f"[bold]{result['behavior_summary']}[/bold]\n\n"
        f"Familia: [red]{result['malware_family']}[/red] · "
        f"Categoría: [yellow]{result['threat_category']}[/yellow] · "
        f"Score: {sample.get('score', '?')}/100",
        title="Comportamiento principal", border_style="red",
    ))

    if result.get("narrative"):
        console.print(Panel(Text(result["narrative"].strip()),
                            title="Análisis narrativo", border_style="cyan"))

    ttp_table = Table(title=f"TTPs detectadas ({len(result['ttps'])})")
    ttp_table.add_column("Táctica", style="cyan")
    ttp_table.add_column("Técnica", style="cyan")
    ttp_table.add_column("Confianza")
    for t in result["ttps"]:
        conf = t.get("confidence", "?")
        style = {"high": "green", "medium": "yellow", "low": "dim"}.get(conf, "")
        ttp_table.add_row(t.get("tactic", ""), t.get("technique", ""),
                          f"[{style}]{conf}[/{style}]" if style else conf)
    console.print(ttp_table)

    ioc_table = Table(title=f"IOCs extraídos ({len(result['iocs'])})")
    ioc_table.add_column("Tipo")
    ioc_table.add_column("Valor", overflow="fold")
    ioc_table.add_column("Contexto")
    for i in result["iocs"]:
        ioc_table.add_row(i["type"], i["value"], i["context"])
    console.print(ioc_table)

    console.print(Panel(
        f"CSV:  {paths['csv']}\nHTML: {paths['html']}\nJSON: {paths['json']}\n\n"
        f"Costo: [green]${result['analysis_cost_usd']:.4f} USD[/green] · "
        f"Tiempo API: {result['analysis_time_s']:.1f}s",
        title="Outputs", border_style="green",
    ))


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else getattr(logging, config.LOG_LEVEL),
        format="%(levelname)s %(name)s: %(message)s",
    )
    start = time.monotonic()

    try:
        # Capa 1 — Ingesta
        console.print("[dim]\\[1/6] Ingestando reporte...[/dim]")
        report = report_ingestor.ingest(
            args.source, file_path=args.file,
            sample_name=args.sample, sample_id=args.sample_id,
            sample_hash=args.sample_hash,
        )

        # Enriquecimiento — abuse.ch (entre Capa 1 y 2, degrada con gracia)
        if not args.no_enrich and report.get("sample_hash"):
            console.print("[dim]\\[+] Enriqueciendo contexto (abuse.ch)...[/dim]")
            report["enrichment"] = enrichment.enrich(report["sample_hash"])

        # Capa 2 — Preprocesamiento
        console.print("[dim]\\[2/6] Preprocesando (filtrado de ruido)...[/dim]")
        processed = report_preprocessor.preprocess(report)

        # Capa 3 — Prompt
        console.print("[dim]\\[3/6] Construyendo prompt MITRE ATT&CK...[/dim]")
        system_prompt, user_message = prompt_builder.build_prompt(
            processed, version=args.prompt_version,
        )

        if args.dry_run:
            # Text() evita que Rich interprete corchetes del reporte como markup
            console.print(Panel(Text(user_message), title="user_message (dry-run)",
                                border_style="yellow"))
            console.print("[yellow]Dry-run: no se llamó a la API.[/yellow]")
            return 0

        # Capa 4 — Claude API
        console.print(f"[dim]\\[4/6] Analizando con {config.CLAUDE_MODEL}...[/dim]")
        raw_response, metrics = claude_client.analyze(
            system_prompt, user_message,
            sample_hash=report["sample_hash"],
        )

        # Capa 5 — Parser
        console.print("[dim]\\[5/6] Parseando respuesta...[/dim]")
        result = output_parser.parse(raw_response, metrics)

        # Capa 6 — Outputs
        console.print("[dim]\\[6/6] Generando outputs...[/dim]")
        paths = output_generator.generate_all(result)

        print_summary(result, paths)
        console.print(f"\n[bold green]Análisis completo en "
                      f"{time.monotonic() - start:.1f}s[/bold green]")
        return 0

    except (ValueError, FileNotFoundError, RuntimeError) as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
