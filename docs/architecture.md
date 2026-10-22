# Architecture

The scanner is organized as a modular pipeline:

```
target -> recon modules -> vulnerability modules -> report
```

## Core components

- `core/engine.py`: module registry and execution
- `core/http.py`: async HTTP client with rate limiting
- `core/scope.py`: include/exclude scope rules
- `core/storage.py`: SQLite scan persistence
- `core/models.py`: findings, assets, scan results
- `templating/`: YAML template engine

## Modules

Modules implement `async def run(ctx)` and add assets/findings to the shared context. Modules are registered in `modules/registry.py`.

## Reporting

Reports are generated from saved `ScanResult` objects and support JSON, Markdown, SARIF, and HTML.