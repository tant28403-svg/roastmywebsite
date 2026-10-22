from __future__ import annotations

import json
from pathlib import Path

from ..core.models import ScanResult

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render(result: ScanResult) -> str:
    rules = []
    results = []
    seen_rules = set()
    for finding in result.findings:
        rule_id = finding.id
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "help": {"text": finding.remediation or ""},
                "properties": {"tags": finding.tags},
            })
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_LEVEL.get(finding.severity.value, "note"),
            "message": {"text": finding.description or finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.asset},
                    }
                }
            ],
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Roast My Website", "version": "0.2.0", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def write(result: ScanResult, path: Path) -> Path:
    path.write_text(render(result), encoding="utf-8")
    return path