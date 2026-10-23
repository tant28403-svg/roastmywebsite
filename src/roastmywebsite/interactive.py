from __future__ import annotations

from .config import load_config

RECON_MODULES = [
    ("dns", "DNS records"),
    ("subdomains", "Subdomain enumeration"),
    ("ct", "Certificate transparency"),
    ("wayback", "Wayback Machine URLs"),
    ("tech", "Technology detection"),
    ("ports", "Port scanning"),
    ("crawl", "Web crawling"),
    ("js", "JavaScript analysis"),
    ("secrets", "Secret detection"),
]

VULN_MODULES = [
    ("headers", "Security headers"),
    ("exposed_files", "Exposed files"),
    ("tls", "TLS/SSL configuration"),
    ("cve", "CVE lookup"),
    ("nuclei", "Nuclei templates"),
    ("templates", "YAML templates"),
    ("injection", "SQL injection"),
    ("xss", "Cross-site scripting"),
    ("ssrf", "Server-side request forgery"),
    ("idor", "Insecure direct object reference"),
    ("api", "API discovery"),
    ("cloud", "Cloud misconfiguration"),
    ("email_security", "Email security (SPF/DMARC/DKIM)"),
]

AGGRESSIVE_MODULES = [
    ("auth", "Default credentials"),
    ("browser", "Browser-rendered checks"),
    ("dom_xss", "DOM-based XSS"),
    ("oob", "HTTP out-of-band"),
    ("dns_oob", "DNS out-of-band"),
]

MODES = [
    ("recon", "Reconnaissance only"),
    ("safe", "Safe vulnerability scan"),
    ("active", "Active scan (injection, XSS, SSRF, IDOR)"),
    ("aggressive", "Aggressive scan (all modules)"),
    ("roast", "Full pipeline (recon + aggressive)"),
    ("custom", "Pick specific modules"),
]


def _prompt(text: str, default: str = "") -> str:
    try:
        value = input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)
    return value if value else default


def _prompt_choice(text: str, max_val: int, default: int = 1) -> int:
    while True:
        raw = _prompt(text, str(default))
        try:
            val = int(raw)
            if 1 <= val <= max_val:
                return val
        except ValueError:
            pass
        print(f"  Invalid choice. Enter a number between 1 and {max_val}.")


def _prompt_multi(text: str, max_val: int) -> list[int]:
    while True:
        raw = _prompt(text)
        if not raw:
            return []
        try:
            vals = [int(x.strip()) for x in raw.split(",")]
            if all(1 <= v <= max_val for v in vals):
                return vals
        except ValueError:
            pass
        print(f"  Invalid input. Enter comma-separated numbers between 1 and {max_val}.")


def run_interactive() -> None:
    print()
    print("=" * 50)
    print("  Roast My Website - Interactive Mode")
    print("=" * 50)
    print()

    # Target
    target = _prompt("Target (hostname or IP): ")
    if not target:
        print("No target provided. Exiting.")
        return

    # Mode selection
    print()
    print("Select scan type:")
    for i, (name, desc) in enumerate(MODES, 1):
        print(f"  {i}. {name:<12} - {desc}")
    print()
    mode_choice = _prompt_choice("Enter choice (1-6): ", 6, 1)
    mode_name, _ = MODES[mode_choice - 1]

    # Custom module selection
    selected_modules = None
    if mode_name == "custom":
        print()
        print("Reconnaissance modules:")
        for i, (name, desc) in enumerate(RECON_MODULES, 1):
            print(f"  {i:>2}. {name:<14} - {desc}")
        offset = len(RECON_MODULES)
        print()
        print("Vulnerability modules:")
        for i, (name, desc) in enumerate(VULN_MODULES, 1):
            print(f"  {i + offset:>2}. {name:<14} - {desc}")
        offset2 = offset + len(VULN_MODULES)
        print()
        print("Aggressive modules:")
        for i, (name, desc) in enumerate(AGGRESSIVE_MODULES, 1):
            print(f"  {i + offset2:>2}. {name:<14} - {desc}")
        print()
        total = len(RECON_MODULES) + len(VULN_MODULES) + len(AGGRESSIVE_MODULES)
        choices = _prompt_multi(f"Enter modules (comma-separated, 1-{total}): ", total)

        all_mods = RECON_MODULES + VULN_MODULES + AGGRESSIVE_MODULES
        selected_modules = [all_mods[i - 1][0] for i in choices]
        if not selected_modules:
            print("No modules selected. Exiting.")
            return

    # Port scanning tool
    print()
    print("Port scanning tool:")
    print("  1. auto   - Prefer naabu, fallback to nmap")
    print("  2. nmap   - Deeper service discovery (slower)")
    print("  3. naabu  - Fast port scanning")
    ports_choice = _prompt_choice("Select (1-3): ", 3, 1)
    ports_tools = ["auto", "nmap", "naabu"]
    ports_tool = ports_tools[ports_choice - 1]

    # Subdomain tool
    print()
    print("Subdomain enumeration tool:")
    print("  1. auto       - Prefer subfinder, then amass")
    print("  2. subfinder  - Passive enumeration")
    print("  3. amass      - Thorough enumeration")
    print("  4. both       - Run both tools")
    sub_choice = _prompt_choice("Select (1-4): ", 4, 1)
    sub_tools = ["auto", "subfinder", "amass", "both"]
    subdomain_tool = sub_tools[sub_choice - 1]

    # Nuclei configuration
    print()
    print("Nuclei severity filter:")
    print("  1. all (default)")
    print("  2. critical,high")
    print("  3. critical,high,medium")
    nuc_sev_choice = _prompt_choice("Select (1-3): ", 3, 1)
    nuc_severities = [None, "critical,high", "critical,high,medium"]
    nuclei_severity = nuc_severities[nuc_sev_choice - 1]

    nuclei_tags = _prompt("Nuclei tags (comma-separated, or Enter to skip): ")
    nuclei_tags = nuclei_tags if nuclei_tags else None

    nuclei_exclude = _prompt("Nuclei exclude tags (comma-separated, or Enter to skip): ")
    nuclei_exclude = nuclei_exclude if nuclei_exclude else None

    # Rate limit
    print()
    rate_input = _prompt("Request rate (req/s, default 5.0): ", "5.0")
    try:
        rate = float(rate_input)
    except ValueError:
        rate = 5.0

    # Permission check for active/aggressive modes
    aggressive = mode_name in ("active", "aggressive", "roast")
    permission = False
    if aggressive:
        print()
        if not _prompt("Do you own or have written permission to test this target? (y/n): ").lower().startswith("y"):
            print("Aborted.")
            return
        permission = True

    # Build settings
    settings = load_config()
    settings.rate_limit = rate
    settings.aggressive = aggressive or settings.aggressive
    settings.permission_acknowledged = permission or settings.permission_acknowledged
    settings.ports_tool = ports_tool
    settings.subdomain_tool = subdomain_tool
    if nuclei_severity:
        settings.nuclei_severity = nuclei_severity
    if nuclei_tags:
        settings.nuclei_tags = nuclei_tags
    if nuclei_exclude:
        settings.nuclei_exclude_tags = nuclei_exclude

    # Determine mode for _run_scan
    run_mode = "roast" if mode_name == "roast" else mode_name
    if mode_name == "custom":
        run_mode = "safe"

    modules_str = ",".join(selected_modules) if selected_modules else None

    print()
    print(f"Starting scan on {target} (mode={run_mode})...")
    if selected_modules:
        print(f"Modules: {', '.join(selected_modules)}")
    print()

    from .cli import _run_scan

    _run_scan(target, run_mode, settings, None, modules_str)