from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..core.models import ScanResult

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}


def risk_score(result: ScanResult) -> int:
    score = 0
    for finding in result.findings:
        score += SEVERITY_WEIGHT.get(finding.severity.value, 1)
    return min(100, score)


def render(result: ScanResult) -> str:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report.html.j2")
    findings = sorted(result.findings, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value))
    return template.render(result=result, findings=findings, risk_score=risk_score(result))


def write(result: ScanResult, path: Path) -> Path:
    path.write_text(render(result), encoding="utf-8")
    return path