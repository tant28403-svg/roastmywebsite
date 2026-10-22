from __future__ import annotations

from pathlib import Path

from ..core.models import ScanResult


def render(result: ScanResult) -> str:
    lines = []
    lines.append(f"# Roast Report: {result.target}")
    lines.append("")
    lines.append(f"- Scan ID: `{result.id}`")
    lines.append(f"- Mode: `{result.mode}`")
    lines.append(f"- Started: {result.started_at.isoformat()}")
    lines.append("")
    lines.append("## Summary")
    for sev, count in result.counts.items():
        lines.append(f"- {sev.title()}: {count}")
    lines.append("")
    lines.append("## Findings")
    for f in sorted(result.findings, key=lambda x: x.severity.value):
        lines.append(f"### {f.title} ({f.severity.value.upper()})")
        lines.append(f"- Asset: `{f.asset}`")
        lines.append(f"- Module: `{f.module}`")
        lines.append(f"- Confidence: {f.confidence}")
        if f.description:
            lines.append(f"- Description: {f.description}")
        if f.remediation:
            lines.append(f"- Remediation: {f.remediation}")
        if f.references:
            lines.append(f"- References: {', '.join(f.references)}")
        lines.append("")
    return "\n".join(lines)


def write(result: ScanResult, path: Path) -> Path:
    path.write_text(render(result), encoding="utf-8")
    return path