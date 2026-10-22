from __future__ import annotations

from ..templating.loader import load_all_templates
from ..templating.runner import run_template


async def run(ctx) -> None:
    templates = load_all_templates()
    if not templates:
        return
    for template in templates:
        if not ctx.can_request():
            return
        try:
            await run_template(ctx, template)
        except Exception:
            continue