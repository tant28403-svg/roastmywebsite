# Roast My Website

Roast My Website is an open-source Python tool for authorised website vulnerability assessment and OSINT reconnaissance.

Use it only on systems you own or have explicit written permission to test. Unauthorised scanning may be illegal.

## Requirements

- Python 3.10 or later
- Linux is the primary supported platform
- Windows and macOS can run the tool for development, but Linux is recommended for production use and external scanner integrations
- A virtual environment is recommended so the tool does not modify your system Python

## Download

```bash
git clone https://github.com/tant28403-svg/roastmywebsite.git
cd roastmywebsite
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the package and its dependencies:

```bash
pip install -e .
```

Add the development extra if you want to run tests and linting:

```bash
pip install -e ".[dev]"
```

Optional dependencies for browser-based checks:

```bash
pip install -e ".[browser]"
playwright install chromium
```

## External tools

External tools are optional but recommended. The built-in checks always run; modules that need a missing tool are skipped and the reason appears in the scan output.

Recommended for full coverage:

| Tool | Used by | Purpose |
|---|---|---|
| `nmap` | `ports` | Service and port discovery |
| `naabu` | `ports` | Fast port enumerator |
| `nuclei` | `nuclei` | Template-based vulnerability checks |
| `ffuf` | `crawl` | Content and endpoint brute force |
| `subfinder` | `subdomains` | Passive subdomain enumeration |
| `amass` | `subdomains` | Asset discovery |

On Kali:

```bash
sudo apt update
sudo apt install -y naabu subfinder ffuf
```

Install with Go (newest versions):

```bash
sudo apt install -y golang-go libpcap-dev
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

Check what is available at any time:

```bash
roastmywebsite doctor
```

`doctor` also works when tools are missing. It only reports what it finds.

## Use

The default configuration works without any setup. Start with a quick environment check, then run recon or a scan.

### The target format

Pass the hostname or IP address only. Do not include a scheme or path.

```bash
# Correct
roastmywebsite scan example.com
roastmywebsite scan 10.0.0.5

# Wrong
roastmywebsite scan https://example.com/
```

### Recommended first run

Start at a low request rate so you are not blocked:

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
roastmywebsite scan example.com --mode safe --rate 2 --timeout 10
```

4. Generate a report:

```bash
roastmywebsite report --format html
```

Please use authorised targets only. The tool performs real network requests, and scanning systems without permission may be illegal.

### If the command is not found

If `roastmywebsite` is not on your `PATH` after installation, use either of these:

```bash
python -m roastmywebsite doctor
rmw doctor
```

The `rmw` command is a shorter alias for the same tool.

## Verify your install

Run this after installing or after adding external tools:

```bash
roastmywebsite doctor
```

Example output on a fully equipped machine:

```text
Roast My Website doctor
python3: ok Python 3.12.3
nmap: ok Nmap version 7.99 ( https://nmap.org )
nuclei: ok Nuclei Engine Version: v3.11.1
naabu: ok naabu version 2.6.1
ffuf: ok Fuzz Faster U Fool - 2.1.0-dev
subfinder: ok subfinder version 2.16.0
amass: ok v4.x.x
Config dir: /home/user/.config/roastmywebsite
Database: /home/user/.local/share/roastmywebsite/roastmywebsite.db
```

Anything reported as `missing` is optional. The tool still runs.

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

| Mode | Command | What runs |
|---|---|---|
| `recon` | `roastmywebsite recon example.com` | DNS, subdomains, certificate transparency, Wayback, tech, ports, crawl, JS, secrets |
| `safe` | `roastmywebsite scan example.com --mode safe` | Recon plus headers, exposed files, TLS, CVEs, API, cloud, email security, templates |
| `active` | `roastmywebsite scan example.com --mode active --i-have-permission` | Safe plus injection, XSS, SSRF, IDOR probes |
| `aggressive` | `roastmywebsite scan example.com --mode aggressive --i-have-permission` | Active plus auth, browser, DOM XSS, HTTP OOB, DNS OOB |
| `roast` | `roastmywebsite roast example.com --i-have-permission` | Full aggressive pipeline |

For `active`, `aggressive`, and `roast`, the tool asks you to confirm you have permission unless you pass `--i-have-permission`.

```bash
roastmywebsite scan example.com --mode safe
roastmywebsite scan example.com --mode active --i-have-permission
roastmywebsite scan example.com --mode aggressive --i-have-permission
roastmywebsite roast example.com --i-have-permission
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

## Scan options

```bash
roastmywebsite scan example.com \
  --mode safe \
  --rate 3 \
  --concurrency 15 \
  --timeout 12 \
  --output example-results.json
```

| Option | Default | Notes |
|---|---|---|
| `--mode` | `safe` | `safe`, `active`, or `aggressive` |
| `--rate` | `5.0` | Requests per second |
| `--concurrency` | `20` | Concurrent requests |
| `--timeout` | `15.0` | Request timeout in seconds |
| `--proxy` | none | Optional HTTP proxy URL |
| `--i-have-permission` | off | Acknowledge authorisation and skip the prompt |
| `--output` | none | Write the scan result to a JSON file |

`recon` and `roast` accept the same tuning options (`--rate`, `--concurrency`, `--timeout`, `--proxy`, `--output`).

Run `roastmywebsite --help` or `roastmywebsite scan --help` to see every option.

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

Reports are generated from scans already saved in the local database.

```bash
# Latest scan
roastmywebsite report --format html

# A specific scan
roastmywebsite report --scan-id <scan-id> --format html

# A specific output file
roastmywebsite report --format html --output ~/report.html
```

Available formats:

```bash
roastmywebsite report --format html
roastmywebsite report --format json
roastmywebsite report --format markdown
roastmywebsite report --format sarif
```

Default report location:

```text
~/.local/share/roastmywebsite/reports/
```

The scan ID is printed at the end of every scan. Open the generated HTML report in a browser to review its findings, severity summary, evidence, and remediation guidance.

## Typical session

```bash
cd ~/roastmywebsite
source .venv/bin/activate

roastmywebsite doctor
roastmywebsite recon example.com
roastmywebsite scan example.com --mode safe --rate 2
roastmywebsite report --format html
```

Then, only with authorisation:

```bash
roastmywebsite scan example.com --mode active --i-have-permission --rate 2
roastmywebsite roast example.com --i-have-permission
```

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

The `Dockerfile` is not included in the clone. Create one in the project root if you want a container build:

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN python -m pip install --no-cache-dir -e .
ENTRYPOINT ["roastmywebsite"]
CMD ["--help"]
```

Then build and run:

```bash
docker build -t roastmywebsite .
docker run --rm -it -v "$PWD/.docker-data:/data" -e XDG_DATA_HOME=/data roastmywebsite doctor
```

Scan results and generated reports are stored under `.docker-data/roastmywebsite/` on the host.

## Troubleshooting

### `roastmywebsite: command not found`

The virtual environment is not active, or the script directory is not on `PATH`.

```bash
source .venv/bin/activate
```

Or run the module directly:

```bash
python -m roastmywebsite doctor
rmw doctor
```

### `doctor` reports tools as `missing`

That is expected if the tool is not installed. Install what you need:

```bash
sudo apt update
sudo apt install -y naabu subfinder ffuf
```

Then run `roastmywebsite doctor` again.

### A scan finds nothing

A clean result only means the configured checks found nothing. Try a higher mode or slower rate:

```bash
roastmywebsite scan example.com --mode active --rate 2 --i-have-permission
```

Some checks also need external tools or a configured OOB domain to work.

### Requests are timing out or being blocked

Lower the rate and raise the timeout:

```bash
roastmywebsite scan example.com --mode safe --rate 1 --timeout 30
```

### Running behind a proxy

Pass the proxy on the command line or set it in the config:

```bash
roastmywebsite scan example.com --proxy http://127.0.0.1:8080
```

Only HTTP traffic is proxied. DNS and TLS checks still run from your machine.

### Where are my results stored?

```text
~/.local/share/roastmywebsite/roastmywebsite.db
~/.local/share/roastmywebsite/reports/
```

The config lives at `~/.config/roastmywebsite/config.yaml`.

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