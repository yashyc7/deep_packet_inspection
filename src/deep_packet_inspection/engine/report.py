"""Format processing reports for CLI output."""

from __future__ import annotations

from deep_packet_inspection.flow.types import ProcessingStats, app_type_to_string


def format_report(stats: ProcessingStats) -> str:
    lines: list[str] = []
    lines.append("")
    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║                    PROCESSING REPORT                         ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    lines.append(f"║  Total Packets:  {stats.total_packets:>10}                           ║")
    lines.append(f"║  Forwarded:      {stats.forwarded_packets:>10}                           ║")
    lines.append(f"║  Dropped:        {stats.dropped_packets:>10}                           ║")
    lines.append(f"║  Active Flows:   {stats.flow_count:>10}                           ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    lines.append("║                  APPLICATION BREAKDOWN                       ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")

    total = max(stats.total_packets, 1)
    sorted_apps = sorted(
        stats.app_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    if not sorted_apps:
        lines.append("║  (no classified application traffic)                         ║")
    else:
        for app, count in sorted_apps:
            pct = 100.0 * count / total
            bar_len = int(pct / 5)
            bar = "#" * bar_len
            name = app_type_to_string(app)
            lines.append(f"║  {name:<15}{count:>8}  {pct:>5.1f}%  {bar:<20} ║")

    lines.append("╚══════════════════════════════════════════════════════════════╝")

    if stats.detected_domains:
        lines.append("")
        lines.append("[Detected Applications/Domains]")
        for domain, app in sorted(stats.detected_domains.items()):
            lines.append(f"  - {domain} -> {app_type_to_string(app)}")

    return "\n".join(lines)
