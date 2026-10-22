# Roast My Website

Roast My Website is an open-source Python tool for authorized website vulnerability assessment and OSINT reconnaissance.

## Features

- DNS, subdomain, port, technology, and endpoint discovery
- Passive and active vulnerability checks
- Template-based checks
- Optional browser, OOB, and external scanner integrations
- JSON, Markdown, SARIF, and HTML reports

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
roastmywebsite doctor
roastmywebsite recon example.com
```

## Safety

Only scan systems you own or have explicit written permission to test.