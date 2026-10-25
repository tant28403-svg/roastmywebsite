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

    # Concurrency
    print()
    conc_input = _prompt("Concurrency (parallel requests, default 20; lower for WAF-protected targets): ", "20")
    try:
        concurrency = int(conc_input)
        if not (1 <= concurrency <= 100):
            print("  Invalid range, using default 20.")
            concurrency = 20
    except ValueError:
        print("  Invalid input, using default 20.")
        concurrency = 20

    # Proxy
    print()
    proxy_input = _prompt("HTTP proxy URL (or Enter to skip): ")
    proxy = proxy_input if proxy_input else None

    # Stealth mode (on by default in interactive mode)
    print()
    print("Stealth mode (hide scanner identity):")
    print("  1. on (default)  - Use a browser User-Agent")
    print("  2. off           - Identify as RoastMyWebsite")
    stealth_choice = _prompt_choice("Select (1-2): ", 2, 1)
    stealth = stealth_choice == 1

    # WAF evasion
    print()
    print("WAF evasion (advanced):")
    print("  1. off (default)")
    print("  2. on  - jitter + UA rotation + header randomization + human timing")
    print("  3. custom - configure each option")
    waf_choice = _prompt_choice("Select (1-3): ", 3, 1)
    waf_evasion = False
    jitter = 0.0
    rotate_ua = False
    randomize_headers = False
    rotate_referer = False
    human_timing = False
    proxy_pool_str = None
    payload_encoding_str = None
    waf_adapt_flag = False
    auto_backoff_flag = False
    rotate_protocol_flag = False
    chunked_flag = False
    pad_requests_flag = False
    param_pollution_flag = False
    normalize_paths_flag = False
    if waf_choice == 2:
        waf_evasion = True
        payload_encoding_str = "url,case"
        waf_adapt_flag = True
        auto_backoff_flag = True
        rotate_protocol_flag = True
        chunked_flag = True
        pad_requests_flag = True
        param_pollution_flag = True
        normalize_paths_flag = True
    elif waf_choice == 3:
        print()
        if _prompt("Enable jitter (random delay per request)? (y/n): ").lower().startswith("y"):
            jit_input = _prompt("Jitter max (seconds, default 1.5): ", "1.5")
            try:
                jitter = float(jit_input)
            except ValueError:
                jitter = 1.5
        if _prompt("Rotate User-Agent per request? (y/n): ").lower().startswith("y"):
            rotate_ua = True
        if _prompt("Randomize request headers? (y/n): ").lower().startswith("y"):
            randomize_headers = True
        if _prompt("Rotate Referer header? (y/n): ").lower().startswith("y"):
            rotate_referer = True
        if _prompt("Human-like timing patterns? (y/n): ").lower().startswith("y"):
            human_timing = True
        pp_input = _prompt("Proxy pool (comma-separated URLs, or Enter to skip): ")
        if pp_input:
            proxy_pool_str = pp_input
        # Phase 2 options
        if _prompt("Enable payload encoding? (y/n): ").lower().startswith("y"):
            pe_input = _prompt("Encoding types (comma-separated: url,case,double_url,comments,unicode,hex,all; default url,case): ", "url,case")
            payload_encoding_str = pe_input if pe_input else "url,case"
        else:
            payload_encoding_str = None
        if _prompt("Enable WAF-specific payload adaptation? (y/n): ").lower().startswith("y"):
            waf_adapt_flag = True
        else:
            waf_adapt_flag = False
        if _prompt("Enable auto-backoff on block detection? (y/n): ").lower().startswith("y"):
            auto_backoff_flag = True
        else:
            auto_backoff_flag = False
        # Phase 3 options
        if _prompt("Enable protocol switching (HTTP/1.1 <-> HTTP/2)? (y/n): ").lower().startswith("y"):
            rotate_protocol_flag = True
        else:
            rotate_protocol_flag = False
        if _prompt("Enable chunked transfer encoding? (y/n): ").lower().startswith("y"):
            chunked_flag = True
        else:
            chunked_flag = False
        if _prompt("Enable request body padding? (y/n): ").lower().startswith("y"):
            pad_requests_flag = True
        else:
            pad_requests_flag = False
        if _prompt("Enable parameter pollution? (y/n): ").lower().startswith("y"):
            param_pollution_flag = True
        else:
            param_pollution_flag = False
        if _prompt("Enable path normalization? (y/n): ").lower().startswith("y"):
            normalize_paths_flag = True
        else:
            normalize_paths_flag = False

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
    settings.concurrency = concurrency
    settings.proxy = proxy or settings.proxy
    settings.stealth = stealth or settings.stealth
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

    # WAF evasion settings
    if waf_evasion:
        if jitter == 0.0:
            jitter = 1.5
        rotate_ua = True
        randomize_headers = True
        rotate_referer = True
        settings.use_cookies = True
        human_timing = True
        settings.payload_encoding = "url,case"
        settings.auto_backoff = True
        settings.waf_adapt = True

    settings.waf_evasion = waf_evasion or settings.waf_evasion
    if jitter > 0:
        settings.jitter = jitter
    settings.rotate_user_agent = rotate_ua or settings.rotate_user_agent
    if proxy_pool_str:
        settings.proxy_pool = [p.strip() for p in proxy_pool_str.split(",") if p.strip()]
    settings.randomize_headers = randomize_headers or settings.randomize_headers
    settings.rotate_referer = rotate_referer or settings.rotate_referer
    settings.human_timing = human_timing or settings.human_timing
    # Phase 2
    if payload_encoding_str:
        settings.payload_encoding = payload_encoding_str
    settings.waf_adapt = waf_adapt_flag or settings.waf_adapt
    settings.auto_backoff = auto_backoff_flag or settings.auto_backoff
    # Phase 3
    settings.rotate_protocol = rotate_protocol_flag or settings.rotate_protocol
    settings.chunked_encoding = chunked_flag or settings.chunked_encoding
    settings.pad_requests = pad_requests_flag or settings.pad_requests
    settings.param_pollution = param_pollution_flag or settings.param_pollution
    settings.normalize_paths = normalize_paths_flag or settings.normalize_paths

    # Determine mode for _run_scan
    run_mode = "roast" if mode_name == "roast" else mode_name
    if mode_name == "custom":
        run_mode = "safe"

    modules_str = ",".join(selected_modules) if selected_modules else None

    print()
    print(f"Starting scan on {target} (mode={run_mode}, rate={rate}, concurrency={concurrency})...")
    if selected_modules:
        print(f"Modules: {', '.join(selected_modules)}")
    print()

    import asyncio

    from .cli import _run_scan

    asyncio.run(_run_scan(target, run_mode, settings, None, modules_str))