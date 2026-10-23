# Roast My Website

> [!IMPORTANT]
> This tool only finds *potential* issues. All findings must be verified manually. False positives are possible.

An open-source Python tool for authorised website vulnerability assessment and OSINT reconnaissance.

Use it only on systems you own or have explicit written permission to test. Unauthorised scanning may be illegal.

## Requirements

- Python 3.10 to 3.12 (do not use 3.13+)
- Linux is the primary supported platform
- A virtual environment so the tool does not modify your system Python
- Do not run as root

## Install these first

Missing prerequisites are the most common cause of errors on a fresh machine.

### Required

| Requirement | Why |
|---|---|
| Python 3.10+ | The tool is written in Python |
| pip | Installs Python dependencies |
| venv | Isolates dependencies from system Python |
| git | Clones the repository |
| Build tools | `lxml` and `cryptography` compile C extensions |

Install all of them on Debian, Ubuntu, or Kali:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git \
  build-essential libxml2-dev libxslt1-dev libffi-dev libssl-dev
```

If `python3 -m venv` fails with "ensurepip is not available":

```bash
sudo apt install python3-venv
```

### Optional

The tool runs without these. Modules that need a missing tool are skipped, and the reason is printed during the scan.

| Requirement | Enables |
|---|---|
| `nmap` | Deeper port and service discovery |
| `naabu` | Fast port scanning |
| `nuclei` | Template-based vulnerability checks |
| `ffuf` | Endpoint and content discovery |
| `subfinder` | Passive subdomain enumeration |
| `amass` | Extra asset discovery |
| Playwright + Chromium | `browser` and `dom_xss` checks |
| A domain you control | `dns_oob` out-of-band checks |

```bash
sudo apt install -y nmap naabu nuclei ffuf subfinder amass
```

If a package is missing from your repositories, install it with Go:

```bash
sudo apt install -y golang-go libpcap-dev
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

Browser checks need a separate Chromium download:

```bash
pip install -e ".[browser]"
playwright install chromium
```

## Install

```bash
git clone https://github.com/tant28403-svg/roastmywebsite.git
cd roastmywebsite

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

Verify the setup:

```bash
roastmywebsite doctor
```

Anything reported as `missing` is optional. The tool still runs.

If `roastmywebsite` is not found, the virtual environment is not active, or use one of:

```bash
python -m roastmywebsite doctor
rmw doctor
```

## Use

Pass the hostname or IP address only. Do not include a scheme or path.

```bash
# Correct
roastmywebsite scan example.com
roastmywebsite scan 10.0.0.5

# Wrong
roastmywebsite scan https://example.com/
```

Start with recon, then a safe scan at a low request rate so you are not blocked:

```bash
roastmywebsite recon example.com
roastmywebsite scan example.com --mode safe --rate 2 --timeout 10
roastmywebsite report --format html
```

## Modes

| Mode | Command | What runs |
|---|---|---|
| `recon` | `roastmywebsite recon example.com` | DNS, subdomains, certificate transparency, Wayback, tech, ports, crawl, JS, secrets |
| `safe` | `roastmywebsite scan example.com --mode safe` | Recon plus headers, exposed files, TLS, CVEs, API, cloud, email security, templates |
| `active` | `roastmywebsite scan example.com --mode active --i-have-permission` | Safe plus injection, XSS, SSRF, IDOR |
| `aggressive` | `roastmywebsite scan example.com --mode aggressive --i-have-permission` | Active plus auth, browser, DOM XSS, HTTP OOB, DNS OOB |
| `roast` | `roastmywebsite roast example.com --i-have-permission` | Full aggressive pipeline |

For `active`, `aggressive`, and `roast`, the tool asks you to confirm you have permission unless you pass `--i-have-permission`.

## Scan options

| Option | Default | Notes |
|---|---|---|
| `--mode` | `safe` | `safe`, `active`, or `aggressive` |
| `--rate` | `5.0` | Requests per second |
| `--concurrency` | `20` | Concurrent requests |
| `--timeout` | `15.0` | Request timeout in seconds |
| `--proxy` | none | Optional HTTP proxy for HTTP traffic only |
| `--i-have-permission` | off | Acknowledge authorisation and skip the prompt |
| `--output` | none | Write the scan result to a JSON file |

`recon` and `roast` accept the same tuning options. Run `roastmywebsite --help` to see everything.

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

## Modules

Reconnaissance: `dns`, `subdomains`, `ct`, `wayback`, `tech`, `ports`, `crawl`, `js`, `secrets`

Vulnerability checks: `headers`, `exposed_files`, `tls`, `cve`, `nuclei`, `templates`, `injection`, `xss`, `ssrf`, `idor`, `api`, `cloud`, `email_security`, `auth`, `browser`, `dom_xss`, `oob`, `dns_oob`

The `auth`, `browser`, `dom_xss`, `oob`, and `dns_oob` modules only run in `aggressive` or `roast` mode.

## Templates

Built-in YAML checks for exposed `.git`, `.env`, `phpinfo()`, admin panels, backup archives, SQL dumps, Swagger/OpenAPI, Spring Boot actuator, and server status pages.

```bash
roastmywebsite templates list
roastmywebsite templates validate --path ./my-template.yaml
roastmywebsite templates run example.com --id exposed-git-directory
roastmywebsite templates update
```

## Out-of-band (OOB) testing

```bash
roastmywebsite callback --http-port 8989 --dns-port 5353
```

DNS OOB also requires a domain you control, set in `~/.config/roastmywebsite/config.yaml`:

```yaml
oob_domain: your-callback-domain.com
oob_http_port: 8989
oob_dns_port: 5353
```

## Reporting

```bash
roastmywebsite report --format html      # latest scan
roastmywebsite report --scan-id <id> --format html
roastmywebsite report --format html --output ~/report.html
```

Formats: `html`, `json`, `markdown`, `sarif`.

Default location: `~/.local/share/roastmywebsite/reports/`

## Configuration

Stored at `~/.config/roastmywebsite/config.yaml`. Create it with `roastmywebsite config --init`.

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

See `config.example.yaml` in this repo for the full list of options.

## Troubleshooting

### `roastmywebsite: command not found`

Activate the virtual environment, or use `python -m roastmywebsite` or `rmw`.

### A scan finds nothing

A clean result only means the configured checks found nothing, not that the site is secure. Try a higher mode, and remember some checks need external tools or an OOB domain.

### Requests are timing out or being blocked

Lower the rate and raise the timeout:

```bash
roastmywebsite scan example.com --mode safe --rate 1 --timeout 30
```

### Where are my results stored?

```text
~/.local/share/roastmywebsite/roastmywebsite.db
~/.local/share/roastmywebsite/reports/
```

The config lives at `~/.config/roastmywebsite/config.yaml`.

## License

MIT — see LICENSE.
