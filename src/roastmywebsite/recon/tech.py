from __future__ import annotations

from ..core.models import Asset

SIGNATURES = {
    # CMS
    "wordpress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
    "drupal": ["drupal", "sites/all", "sites/default", "Drupal.settings"],
    "joomla": ["joomla", "/components/com_", "Joomla!"],
    "magento": ["magento", "Mage.Cookies", "skin/frontend"],
    "shopify": ["shopify", "cdn.shopify.com", "Shopify.theme"],
    "ghost": ["ghost", "ghost-url", "content/themes"],
    # Frameworks
    "react": ["react", "__NEXT_DATA__", "react-dom", "react-root"],
    "vue": ["vue.js", "vue.min.js", "__VUE__", "Vue.component", "v-cloak"],
    "angular": ["angular", "ng-version", "angular.min.js", "ng-app"],
    "nextjs": ["__NEXT_DATA__", "_next/static", "next/router"],
    "nuxt": ["__NUXT__", "_nuxt/", "nuxt-link"],
    "svelte": ["svelte", "__svelte"],
    "laravel": ["laravel", "csrf-token", "XSRF-TOKEN"],
    "django": ["django", "csrfmiddlewaretoken", "Django"],
    "rails": ["rails", "authenticity_token", "X-CSRF-Token"],
    "express": ["express", "X-Powered-By: Express"],
    "spring": ["spring", "JSESSIONID", "X-Application-Context"],
    "aspnet": ["asp.net", "__VIEWSTATE", "__EVENTVALIDATION", "X-AspNet-Version"],
    # Servers
    "nginx": ["nginx", "Server: nginx"],
    "apache": ["apache", "Server: Apache"],
    "iis": ["iis", "asp.net", "X-Powered-By: ASP.NET"],
    "litespeed": ["litespeed", "Server: LiteSpeed"],
    "caddy": ["caddy", "Server: Caddy"],
    # CDN/WAF
    "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "fastly": ["fastly", "X-Served-By", "Fastly"],
    "akamai": ["akamai", "X-Akamai-Transformed"],
    "aws_cloudfront": ["cloudfront", "X-Amz-Cf-Id", "X-Cache: Hit from cloudfront"],
    "incapsula": ["incapsula", "X-Iinfo", "visid_incap"],
    "sucuri": ["sucuri", "X-Sucuri-ID", "X-Sucuri-Cache"],
    "modsecurity": ["mod_security", "ModSecurity", "NOYB"],
    # Libraries
    "jquery": ["jquery", "jQuery"],
    "bootstrap": ["bootstrap", "Bootstrap"],
    "tailwind": ["tailwind", "tailwindcss"],
    "fontawesome": ["font-awesome", "fontawesome"],
    # Analytics
    "google_analytics": ["google-analytics", "gtag", "UA-", "G-"],
    "google_tag_manager": ["googletagmanager", "GTM-"],
    "hotjar": ["hotjar", "hjSettings"],
    "mixpanel": ["mixpanel", "mixpanel.init"],
    # Languages
    "php": ["php", "X-Powered-By: PHP", ".php"],
    "python": ["python", "django", "flask", "fastapi"],
    "nodejs": ["node", "express", "next"],
    "java": ["java", "jsessionid", "spring"],
    "ruby": ["ruby", "rails", "passenger"],
    "go": ["go", "gin", "echo"],
}


async def run(ctx) -> None:
    if not ctx.can_request():
        return
    ctx.increment()
    resp = await ctx.http.get(f"https://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok:
        ctx.increment()
        resp = await ctx.http.get(f"http://{ctx.target}", timeout=ctx.settings.timeout)
    if not resp.ok and resp.error:
        return
    haystack = (resp.text + "\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())).lower()
    detected = []
    for name, sigs in SIGNATURES.items():
        if any(sig.lower() in haystack for sig in sigs):
            detected.append(name)
            ctx.add_asset(Asset(value=name, asset_type="technology", source="tech", metadata={"target": ctx.target}))
    # Server header
    server = resp.headers.get("server") or resp.headers.get("Server")
    if server:
        ctx.add_asset(Asset(value=server, asset_type="server", source="tech"))
    powered = resp.headers.get("x-powered-by") or resp.headers.get("X-Powered-By")
    if powered:
        ctx.add_asset(Asset(value=powered, asset_type="powered_by", source="tech"))
    # Detect WAF
    waf_headers = ["cf-ray", "x-sucuri-id", "x-iinfo", "x-akamai-transformed"]
    for h in waf_headers:
        if h in haystack:
            ctx.add_asset(Asset(value=h, asset_type="waf", source="tech"))