from __future__ import annotations

import re

from ..core.models import Finding, Severity
from .schema import Extractor, Matcher, Template

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _render(value: str, variables: dict[str, str]) -> str:
    for key, val in variables.items():
        value = value.replace(key, val)
    return value


def _part_text(response, part: str) -> str:
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    if part == "all":
        return response.text + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    return response.text or ""


def _matcher_ok(matcher: Matcher, response, variables: dict[str, str]) -> bool:
    text = _part_text(response, matcher.part)
    neg = matcher.negative
    result = False
    if matcher.type == "status":
        result = response.status_code in matcher.status
    elif matcher.type == "word":
        if matcher.condition == "and":
            result = all(w in text for w in matcher.words)
        else:
            result = any(w in text for w in matcher.words)
    elif matcher.type == "regex":
        result = any(re.search(p, text) for p in matcher.regex)
    elif matcher.type == "size":
        result = len(text) in matcher.size
    if neg:
        result = not result
    return result


def _extract(extractor: Extractor, response) -> list[str]:
    text = _part_text(response, extractor.part)
    values: list[str] = []
    if extractor.type == "regex":
        for pattern in extractor.regex:
            for match in re.finditer(pattern, text):
                if match.groups() and extractor.group <= len(match.groups()):
                    values.append(match.group(extractor.group))
                else:
                    values.append(match.group(0))
    elif extractor.type == "word":
        for word in extractor.regex:
            if word in text:
                values.append(word)
    return values


async def run_template(ctx, template: Template) -> None:
    variables = {
        "{{BaseURL}}": f"https://{ctx.target}",
        "{{Hostname}}": ctx.target,
    }
    variables.update(template.variables)
    for request in template.requests:
        for path in request.path:
            url = _render(path, variables)
            if not ctx.can_request():
                return
            ctx.increment()
            headers = {k: _render(v, variables) for k, v in request.headers.items()}
            body = _render(request.body, variables) if request.body else None
            if request.method.upper() == "GET":
                resp = await ctx.http.get(url, headers=headers, timeout=ctx.settings.timeout)
            elif request.method.upper() == "POST":
                resp = await ctx.http.post(url, headers=headers, data=body, timeout=ctx.settings.timeout)
            else:
                resp = await ctx.http.request(request.method.upper(), url, headers=headers, data=body, timeout=ctx.settings.timeout)
            # Evaluate matchers
            matched = True
            if request.matchers:
                results = [_matcher_ok(m, resp, variables) for m in request.matchers]
                if request.matchers_condition == "or":
                    matched = any(results)
                else:
                    matched = all(results)
            if not matched:
                continue
            extracted: list[str] = []
            for extractor in request.extractors:
                extracted.extend(_extract(extractor, resp))
            ctx.add_finding(Finding(
                id=f"template-{template.id}",
                title=template.info.name or template.id,
                severity=SEVERITY_MAP.get(template.severity, Severity.INFO),
                confidence=0.75,
                asset=url,
                module="templates",
                description=template.info.description,
                evidence={"response": (resp.text or "")[:1000], "extracted": extracted},
                references=template.info.reference,
                tags=template.info.tags + ["template"],
            ))