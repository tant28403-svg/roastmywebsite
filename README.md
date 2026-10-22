# Roast My Website

Roast My Website is an open-source Python tool for authorised website vulnerability assessment and OSINT reconnaissance.

Use it only on systems you own or have explicit written permission to test. Unauthorised scanning may be illegal.

## Download

Python 3.10 or later is required. Linux is the primary supported platform.

Windows support: The tool can run on Windows for development, but Linux is recommended for production use and external scanner integrations.

```bash
git clone https://github.com/tant28403-svg/roastmywebsite.git
cd roastmywebsite
```

Install the package and its dependencies:

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

The script installs `nmap`, installs the Python package, and reports which of the main external tools are available. Missing tools are optional; the related checks are skipped and a note is added to the scan output.

## Use

The default configuration works without any setup. Start with a quick environment check, then run recon or a scan:

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

If the `roastmywebsite` command is not on your `PATH` after installation, use `python -m roastmywebsite` instead.

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Check Python, configuration paths, and external tools. |
| `config` | Create or show the local configuration file. |
| `recon` | Run reconnaissance modules only. |
| `scan` | Run a scan in `safe`, `active`, or `aggressive` mode. |
| `roast` | Run the full recon plus aggressive pipeline. |
| `report` | Export the latest scan, or a specific `--scan-id`, as HTML, JSON, Markdown, or SARIF. |
| `templates` | List, validate, update, or run YAML templates. |
| `callback` | Start HTTP and DNS callback servers for out-of-band testing. |

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

### Reconnaissance

| Module | What it does |
|---|---|
| `dns` | Collects DNS records and resolver information. |
| `subdomains` | Enumerates subdomains through passive sources and DNS lookups. |
| `ct` | Finds subdomains in certificate transparency logs. |
| `wayback` | Pulls historical URLs from the Wayback Machine. |
| `tech` | Fingerprints servers, frameworks, and libraries from responses. |
| `ports` | Checks common TCP ports, using `nmap`/`naabu` when available. |
| `crawl` | Crawls same-origin pages and discovers links and endpoints. |
| `js` | Extracts endpoints and script references from JavaScript. |
| `secrets` | Looks for API keys, tokens, and other secret patterns. |

### Vulnerability checks

| Module | What it does |
|---|---|
| `headers` | Checks for missing or weak HTTP security headers. |
| `exposed_files` | Probes for exposed configuration, backup, and debug files. |
| `tls` | Checks certificate validity, expiry, and protocol settings. |
| `cve` | Maps disclosed software versions to known CVEs. |
| `nuclei` | Runs `nuclei` templates when the binary is installed. |
| `templates` | Runs the built-in YAML checks. |
| `injection` | Sends lightweight SQL and command injection probes. |
| `xss` | Checks for reflected cross-site scripting. |
| `ssrf` | Probes parameters for server-side request forgery. |
| `idor` | Tests predictable object identifiers for access-control issues. |
| `api` | Finds API documentation and checks common API exposure. |
| `cloud` | Checks for publicly readable cloud storage buckets. |
| `email_security` | Reviews SPF, DMARC, and related email controls. |
| `auth` | Tests common endpoints for weak or default credentials. |
| `browser` | Uses a headless browser for client-side checks. |
| `dom_xss` | Tests for DOM-based cross-site scripting. |
| `oob` | Listens for HTTP out-of-band callbacks. |
| `dns_oob` | Listens for DNS out-of-band callbacks. |

The `auth`, `browser`, `dom_xss`, `oob`, and `dns_oob` modules only run in `aggressive` or `roast` mode.

## Templates

The tool includes a YAML template engine for custom checks.

```bash
roastmywebsite templates list
roastmywebsite templates validate --path ./my-template.yaml
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
| `--output` | none | Write the scan result to a JSON file |
| `--scan-id` | latest | Select a scan for the `report` command |

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
docker run --rm -it -v "$PWD/.docker-data:/data" -e XDG_DATA_HOME=/data roastmywebsite doctor
```

Scan results and generated reports are stored under `.docker-data/roastmywebsite/` on the host.

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

Bug reports and feature requests are welcome at:

https://github.com/tant28403-svg/roastmywebsite/issues

Please include the command you ran, the target type (without any sensitive details), the expected result, and the actual output. Logs or tracebacks help narrow down problems faster.

## License

MIT — see LICENSE.

Please only scan hosts you own or have written permission to test.