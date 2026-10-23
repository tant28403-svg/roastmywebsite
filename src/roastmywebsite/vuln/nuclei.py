from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..core.models import Finding, Severity
from ..core.tools import run_tool, which

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


async def run(ctx) -> None:
    if not which("nuclei"):
        ctx.add_finding(Finding(
            id="nuclei-missing",
            title="Nuclei is not installed",
            severity=Severity.INFO,
            confidence=1.0,
            asset=ctx.target,
            module="nuclei",
            description="Install nuclei to enable template-based checks.",
            remediation="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            tags=["tooling"],
        ))
        return

    target_url = f"https://{ctx.target}"
    with tempfile.TemporaryDirectory() as td:
        out_file = Path(td) / "nuclei.jsonl"
        args = [
            "nuclei",
            "-u", target_url,
            "-jsonl",
            "-o", str(out_file),
            "-silent",
        ]
        # Custom templates
        if getattr(ctx.settings, "nuclei_templates", None):
            args += ["-t", ctx.settings.nuclei_templates]
        # Tag filtering
        if getattr(ctx.settings, "nuclei_tags", None):
            args += ["-tags", ctx.settings.nuclei_tags]
        # Severity filtering
        if getattr(ctx.settings, "nuclei_severity", None):
            args += ["-severity", ctx.settings.nuclei_severity]
        # Exclude tags
        if getattr(ctx.settings, "nuclei_exclude_tags", None):
            args += ["-exclude-tags", ctx.settings.nuclei_exclude_tags]
        if ctx.settings.rate_limit:
            args += ["-rl", str(int(ctx.settings.rate_limit))]
        rc, stdout, stderr = run_tool(args, timeout=300)
        text = ""
        if out_file.exists():
            text = out_file.read_text(encoding="utf-8", errors="ignore")
        if not text and stdout:
            text = stdout
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            sev = SEVERITY_MAP.get(str(obj.get("info", {}).get("severity", "info")).lower(), Severity.INFO)
            ctx.add_finding(Finding(
                id=obj.get("template-id", "nuclei-finding"),
                title=obj.get("info", {}).get("name", "Nuclei finding"),
                severity=sev,
                confidence=0.8,
                asset=obj.get("matched-at", target_url),
                module="nuclei",
                description=obj.get("info", {}).get("description", ""),
                evidence={"request": obj.get("request"), "response": obj.get("response", "")[:1000] if obj.get("response") else None},
                references=obj.get("info", {}).get("reference", []) or [],
                tags=obj.get("info", {}).get("tags", []) or [],
            ))