from __future__ import annotations

from pathlib import Path

import yaml

from .schema import Template


def load_template_file(path: Path) -> Template | None:
    try:
        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        if not isinstance(raw, dict):
            return None
        return Template.model_validate(raw)
    except Exception:
        return None


def load_templates_from_dir(directory: Path) -> list[Template]:
    templates: list[Template] = []
    if not directory.exists():
        return templates
    for path in directory.rglob("*.yaml"):
        template = load_template_file(path)
        if template is not None:
            templates.append(template)
    for path in directory.rglob("*.yml"):
        template = load_template_file(path)
        if template is not None:
            templates.append(template)
    return templates


def load_all_templates(extra_dirs: list[Path] | None = None) -> list[Template]:
    dirs = [Path("templates"), Path.home() / ".config" / "roastmywebsite" / "templates"]
    # Built-in
    builtin = Path(__file__).resolve().parents[1] / "data" / "templates"
    dirs.append(builtin)
    if extra_dirs:
        dirs.extend(extra_dirs)
    seen: set[str] = set()
    result: list[Template] = []
    for directory in dirs:
        for template in load_templates_from_dir(directory):
            if template.id in seen:
                continue
            seen.add(template.id)
            result.append(template)
    return result