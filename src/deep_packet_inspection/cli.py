"""Typer CLI for the deep packet inspection engine."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from deep_packet_inspection.engine.pipeline import DpiEngine
from deep_packet_inspection.engine.report import format_report
from deep_packet_inspection.flow.types import app_type_to_string
from deep_packet_inspection.rules.manager import RuleManager

app = typer.Typer(
    add_completion=False,
    help="Deep Packet Inspection — parse, classify, filter, and report on PCAP traffic.",
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.command()
def analyze(
    input_pcap: Annotated[Path, typer.Argument(help="Input PCAP capture file.")],
    output_pcap: Annotated[Path, typer.Argument(help="Output PCAP for forwarded packets.")],
    block_ip: Annotated[
        list[str] | None,
        typer.Option("--block-ip", help="Block traffic from this source IP (repeatable)."),
    ] = None,
    block_app: Annotated[
        list[str] | None,
        typer.Option(
            "--block-app",
            help="Block an application (e.g. YouTube, Facebook). Repeatable.",
        ),
    ] = None,
    block_domain: Annotated[
        list[str] | None,
        typer.Option(
            "--block-domain",
            help="Block domains containing this substring (repeatable).",
        ),
    ] = None,
) -> None:
    """Run offline DPI on INPUT_PCAP and write allowed packets to OUTPUT_PCAP."""

    if not input_pcap.exists():
        typer.secho(f"Error: input file not found: {input_pcap}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    rules = RuleManager()

    typer.echo("")
    typer.echo("╔══════════════════════════════════════════════════════════════╗")
    typer.echo("║              DPI ENGINE — Deep Packet Inspection             ║")
    typer.echo("╚══════════════════════════════════════════════════════════════╝")
    typer.echo("")

    for ip in block_ip or []:
        rules.block_ip(ip)
        typer.echo(f"[Rules] Blocked IP: {ip}")

    for name in block_app or []:
        try:
            app_type = rules.block_app(name)
        except ValueError as exc:
            typer.secho(f"[Rules] {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=1) from exc
        typer.echo(f"[Rules] Blocked app: {app_type_to_string(app_type)}")

    for domain in block_domain or []:
        rules.block_domain(domain)
        typer.echo(f"[Rules] Blocked domain: {domain}")

    typer.echo("[DPI] Processing packets...")
    engine = DpiEngine(rules=rules)
    stats = engine.process(input_pcap, output_pcap)

    for event in engine.blocked_events:
        typer.echo(f"[BLOCKED] {event}")

    typer.echo(format_report(stats))
    typer.echo(f"\nOutput written to: {output_pcap}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
