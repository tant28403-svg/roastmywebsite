# Roast My Website

Important

Please read this entire README before running the tool. It explains the required setup, scan modes, modules, proxy options, reporting, and a few things that commonly cause confusion or problems (for example the difference between safe and aggressive mode and when "errors" in the output are expected). Taking a couple of minutes to read it will save you a lot of guesswork.

Open Source Notice: This project is open source. The source code, documentation and README fully describe how every module, transport and check works. Anyone who clones this repository can read and understand the complete implementation. Please use it responsibly, and only against systems you own or have explicit written permission to test.

Capability Notice: This is a moderate-intensity vulnerability and OSINT assessment tool. It is designed for authorised security testing, bug bounty reconnaissance, and educational purposes. It does not represent advanced or sophisticated exploitation capabilities. The tool measures how services behave under controlled checks and is intended for lab, authorised testing, and defensive environments only.

⚠️ FOR EDUCATIONAL USE AND AUTHORISED SECURITY TESTING ONLY
Please use this tool only against systems you own or have explicit written permission to test. Unauthorised testing is illegal in most jurisdictions.

⚠️ The author cannot be held responsible for any misuse.

A website vulnerability and OSINT scanner for authorised testing: it measures how your services behave under controlled checks.

## Download

Python 3.10 or later is required. Linux is the primary supported platform.

Windows support: The tool can run on Windows for development, but Linux is recommended for production use and external scanner integrations.

```bash
git clone https://github.com/tant28403-svg/roastmywebsite.git
cd roastmywebsite
```

If any dependencies are missing:

```bash
pip install -e ".[dev]"
```

Optional dependencies (for browser-based checks):

```bash
pip install -e ".[browser]"
playwright install chromium
```

External tools (optional but recommended):

```bash
./scripts/install.sh
```

This checks for `nmap`, `nuclei`, `naabu`, `ffuf`, `subfinder`, and `amass`.

## Use

There is nothing to configure - clone the repository and you are ready to run.

1. Check your environment:

```bash
roastmywebsite doctor
```

2. Run reconnaissance:

```bash
roastmywebsite recon example.com
```

3. Run a safe vulnerability scan:

```bash
roastmywebsite scan example.com --mode safe --i-have-permission
```

4. Generate a report:

```bash
roastmywebsite report --format html
```

Please use authorised targets only. The tool performs real network requests, and scanning systems without permission may be illegal.

## Modes

- `recon`: passive and active reconnaissance only
- `safe`: recon plus non-destructive vulnerability checks
- `active`: safe plus injection, XSS, SSRF and IDOR probes
- `aggressive`: active plus auth, browser, DOM XSS, OOB and DNS OOB checks
- `roast`: full aggressive pipeline

```bash
roastmywebsite scan example.com --mode safe
roastmywebsite scan example.com --mode active
roastmywebsite scan example.com --mode aggressive
roastmywebsite roast example.com
```

## Modules

Reconnaissance:

- `dns`
- `subdomains`
- `ct`
- `wayback`
- `tech`
- `ports`
- `crawl`
- `js`
- `secrets`

Vulnerability checks:

- `headers`
- `exposed_files`
- `tls`
- `cve`
- `nuclei`
- `templates`
- `injection`
- `xss`
- `ssrf`
- `idor`
- `api`
- `cloud`
- `email_security`
- `auth` (aggressive)
- `browser` (aggressive)
- `dom_xss` (aggressive)
- `oob` (aggressive)
- `dns_oob` (aggressive)

## Templates

The tool includes a YAML template engine for custom checks.

```bash
roastmywebsite templates list
roastmywebsite templates validate --path templates/exposed-git.yaml
roastmywebsite templates run example.com --id exposed-git-directory
roastmywebsite templates update
```

Built-in templates include:

- Exposed `.git` directory
- Exposed `.env` file
- Exposed `phpinfo()`
- Exposed admin panels
- Exposed backup archives
- Exposed SQL dumps
- Exposed Swagger/OpenAPI
- Exposed Spring Boot actuator
- Exposed server status pages

## Out-of-band (OOB) testing

Run callback servers for blind vulnerability detection:

```bash
roastmywebsite callback --http-port 8989 --dns-port 5353
```

DNS OOB requires an `oob_domain` configured in `config.yaml`:

```yaml
oob_domain: your-callback-domain.com
oob_http_port: 8989
oob_dns_port: 5353
```

## Reporting

Reports can be generated from saved scans:

```bash
roastmywebsite report --format html
roastmywebsite report --format json
roastmywebsite report --format markdown
roastmywebsite report --format sarif
```

A sample HTML report is available at `examples/sample-report.html`.

## Common options

| Option | Default | Notes |
|---|---|---|
| `--rate` | `5.0` | Requests per second |
| `--concurrency` | `20` | Concurrent requests |
| `--timeout` | `15.0` | Request timeout in seconds |
| `--proxy` | none | HTTP proxy URL |
| `--i-have-permission` | off | Acknowledge authorisation |
| `--output` | none | Write JSON report to path |
| `--aggressive` | off | Enable aggressive checks |

Run `roastmywebsite --help` to see all commands and options.

## Configuration

Configuration is stored in:

```text
~/.config/roastmywebsite/config.yaml
```

Example:

```yaml
rate_limit: 5.0
max_requests: 5000
timeout: 15.0
concurrency: 20
verify_tls: true
aggressive: false
permission_acknowledged: false
oob_domain: null
```

## Docker

```bash
docker build -t roastmywebsite .
docker run --rm -it -v "$PWD/reports:/app/reports" roastmywebsite doctor
```

## Tests

The test suite can be run with:

```bash
python -m pytest tests/ -q
```

Linting:

```bash
ruff check src tests
```

## Reporting issues

If you run into a bug, or something in the tool does not behave the way this README describes, please feel free to report it. Issues are welcome at:

https://github.com/tant28403-svg/roastmywebsite/issues

A short description of what you ran, what you expected and what happened instead is usually enough to get started. Bug reports, feature requests and general feedback are all appreciated.

## License

MIT — see LICENSE.

Please only scan hosts you own or have written permission to test.