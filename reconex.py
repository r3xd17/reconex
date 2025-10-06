from __future__ import annotations

import argparse
import asyncio
import aiohttp
import re
import json
import random
import os
import logging
import time
import sys
from logging.handlers import RotatingFileHandler
from typing import List, Set, Dict, Optional, Any
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network
import contextlib

import dns.resolver
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)

# =====================================
# Constants / Branding
# =====================================

TOOL_VERSION = "1.1"
TOOL_NAME = "Reconex"

console = Console()

# =====================================
# Logging
# =====================================

logger = logging.getLogger("reconex")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = RotatingFileHandler("reconex.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.propagate = False

# =====================================
# UI / Banner
# =====================================

def render_banner(version: str, name: str, author: str = "R3XD17") -> str:
    # SubLyze-style banner with proper right-side border on all lines
    inner = 34  # inner width between the frame borders
    indent = "    "

    # Build visible strings for width calculations (no markup)
    # Line 2: name inside inner box
    l2_core_len = len(indent) + len("╭─[ ") + len(name) + len(" ]") + 1  # +1 for the '╮'
    dashes_l2 = max(0, inner - l2_core_len)

    # Line 3: title + version
    title_txt = "│  Subdomain Intel  │"
    l3_core_len = len(indent) + len(title_txt) + len("  v") + len(version)
    pad_l3 = max(0, inner - l3_core_len)

    # Line 4: author + closing inner box
    gap = 1  # space between author and the closing corner
    l4_core_len = len(indent) + len("│  by ") + len(author) + gap + 2  # +2 for '╰' and '╯'
    dashes_l4 = max(0, inner - l4_core_len)

    # Build lines with markup
    top = f"[bold cyan]╔{'═'*inner}╗[/bold cyan]"

    line2 = (
        f"[bold cyan]║[/bold cyan]"
        f"{indent}[bold yellow]╭─[ [/bold yellow][bold white]{name}[/bold white]"
        f"[bold yellow] ]{'─'*dashes_l2}╮[/bold yellow]"
        f"[bold cyan]║[/bold cyan]"
    )

    line3 = (
        f"[bold cyan]║[/bold cyan]"
        f"{indent}[bold white]{title_txt}[/bold white]  [bold magenta]v{version}[/bold magenta]"
        f"{' ' * pad_l3}[bold cyan]║[/bold cyan]"
    )

    line4 = (
        f"[bold cyan]║[/bold cyan]"
        f"{indent}[bold white]│  by [/bold white][bold green]{author}[/bold green]"
        f"{' ' * gap}[bold yellow]╰{'─'*dashes_l4}╯[/bold yellow]"
        f"[bold cyan]║[/bold cyan]"
    )

    bottom = f"[bold cyan]╚{'═'*inner}╝[/bold cyan]"

    return f"\n{top}\n{line2}\n{line3}\n{line4}\n{bottom}\n"

def render_legend() -> str:
    return (
        "\n[bold]Legend:[/bold]\n"
        "[cyan][Passive][/cyan]  [green][Active][/green]  "
        "[yellow][Takeover Risk][/yellow]  [magenta][Recursive][/magenta]  [blue][WAF][/blue]\n"
    )

# =====================================
# HTTP session helper
# =====================================

def _make_http_session(limit: int = 100, verify_ssl: bool = True, tool_name: str = TOOL_NAME) -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(
        limit=limit,
        ssl=None if verify_ssl else False,
        limit_per_host=20,
        ttl_dns_cache=300
    )
    headers = {
        "User-Agent": f"Mozilla/5.0 ({tool_name})",
        "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
    }
    return aiohttp.ClientSession(connector=connector, headers=headers, trust_env=True)

# =====================================
# Enhanced WAF/CDN Detection
# =====================================

# Expanded IP ranges for various WAF/CDN providers
WAF_NETWORKS = {
    "Cloudflare": [
        # IPv4
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
        "172.64.0.0/13", "131.0.72.0/22",
        # IPv6
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "Akamai": [
        "23.0.0.0/12", "95.100.0.0/15", "184.24.0.0/13", "2.16.0.0/13",
        "23.32.0.0/11", "72.246.0.0/15", "88.221.0.0/16", "96.6.0.0/15",
        "104.64.0.0/10", "184.50.0.0/15", "184.84.0.0/14",
    ],
    "AWS CloudFront": [
        "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "34.195.252.0/24",
        "35.162.63.192/26", "52.46.0.0/18", "52.84.0.0/15", "54.182.0.0/16",
        "54.192.0.0/16", "64.252.64.0/18", "71.152.0.0/17", "99.84.0.0/16",
        "120.52.22.96/27", "130.176.0.0/16", "143.204.0.0/16",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "140.248.64.0/18", "146.75.0.0/16", "151.101.0.0/16",
        "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/17", "199.27.72.0/21",
        # Note: removed Cloudflare ranges 108.162.192.0/18 and 131.0.72.0/22
    ],
    "Sucuri": [
        "192.124.249.0/24", "192.161.0.0/24", "192.88.134.0/24", "185.93.228.0/24",
        "66.248.200.0/24", "66.248.201.0/24", "66.248.202.0/24", "66.248.203.0/24",
    ],
    "Imperva/Incapsula": [
        "45.60.0.0/16", "45.223.0.0/16", "199.83.128.0/21", "198.143.32.0/19",
        "149.126.72.0/21", "103.28.248.0/22", "45.64.64.0/22", "185.11.124.0/22",
    ],
    "Google Cloud CDN": [
        "8.34.208.0/20", "8.35.192.0/21", "108.59.80.0/20", "173.255.112.0/20",
        "204.246.160.0/20", "204.246.164.0/22", "204.246.168.0/22", "204.246.172.0/24",
    ]
}

# Compile all networks for quick lookup
WAF_NETS = {}
for provider, networks in WAF_NETWORKS.items():
    WAF_NETS[provider] = [ip_network(net) for net in networks]

# Provider aliasing to normalize labels
PROVIDER_ALIASES = {
    "Amazon CloudFront": "CloudFront",
    "AWS CloudFront": "CloudFront",
    "Imperva/Incapsula": "Imperva",
}

def _alias(provider: Optional[str]) -> Optional[str]:
    return PROVIDER_ALIASES.get(provider, provider)

# Enhanced CNAME patterns
CNAME_HINTS = {
    "Cloudflare": ["cloudflare.net", "cdn.cloudflare.net", "cloudflare.com"],
    "Akamai": ["akamai.net", "akamaiedge.net", "edgesuite.net", "edgekey.net", "akamaitechnologies.com"],
    "Amazon CloudFront": ["cloudfront.net"],
    "Fastly": ["fastly.net", "fastlylb.net"],
    "StackPath": ["stackpathdns.com", "stackpathcdn.com", "netdna-cdn.com"],
    "Imperva/Incapsula": ["incapdns.net", "impervadns.net"],
    "Azure Front Door": ["azureedge.net", "azurefd.net", "trafficmanager.net"],
    "Google Cloud CDN": ["c.docs.google.com", "googleusercontent.com", "gstatic.com"],
    "Sucuri": ["sucuri.net", "sucuriscan.com"],
    "WordPress.com": ["wordpress.com", "wp.com"],
    "GitHub Pages": ["github.io", "github.com"],
    "Heroku": ["herokuapp.com", "herokussl.com"],
    "AWS ELB": ["elb.amazonaws.com"],
    "Azure Websites": ["azurewebsites.net"],
}

def _detect_waf_by_ip(ip: str) -> Optional[str]:
    """Enhanced WAF detection by IP address"""
    try:
        ip_obj = ip_address(ip)
        for provider, networks in WAF_NETS.items():
            if any(ip_obj in network for network in networks):
                return provider
    except Exception:
        pass
    return None

def _classify_by_headers_enhanced(headers: dict) -> Optional[str]:
    h = {k.lower(): v for k, v in headers.items()}
    server = h.get("server", "").lower()
    via = h.get("via", "").lower()

    # Cloudflare
    if any(key in h for key in ["cf-ray", "cf-cache-status", "cf-request-id", "cf-worker"]):
        return "Cloudflare"
    if "cloudflare" in server:
        return "Cloudflare"

    # Akamai
    if any(key.startswith("x-akamai") for key in h):
        return "Akamai"
    if "akamai" in server or "akamaighost" in server:
        return "Akamai"

    # AWS CloudFront
    if any(key in h for key in ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-cf-country"]):
        return "Amazon CloudFront"
    if "cloudfront" in server or "cloudfront" in via:
        return "Amazon CloudFront"

    # Fastly
    if any(key in h for key in ["x-served-by", "x-timer", "fastly-debug-digest", "x-fastly-request-id"]):
        return "Fastly"
    if "fastly" in server or "fastly" in via:
        return "Fastly"

    # Imperva/Incapsula
    if any(key in h for key in ["x-iinfo", "x-cdn", "incap-su", "x-cdn-forward"]):
        cdn_value = h.get("x-cdn", "").lower()
        if "incap" in cdn_value:
            return "Imperva/Incapsula"

    # Sucuri
    if any(key in h for key in ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"]):
        return "Sucuri"
    if "sucuri" in server:
        return "Sucuri"

    # Azure
    if "x-azure-ref" in h or "azure" in server:
        return "Azure Front Door"

    # Google Cloud
    if any(key in h for key in ["x-gfe-request-trace", "x-google-backends", "x-google-gfe-backend"]):
        return "Google Cloud CDN"
    if "gws" in server or "gse" in server:
        return "Google Cloud CDN"

    # StackPath
    if "x-sp-server" in h:
        return "StackPath"

    # Generic server header (redundant but harmless guard)
    if "cloudflare" in server:
        return "Cloudflare"
    elif "akamai" in server:
        return "Akamai"
    elif "cloudfront" in server:
        return "Amazon CloudFront"
    elif "fastly" in server:
        return "Fastly"
    elif "incapsula" in server:
        return "Imperva/Incapsula"

    return None

async def _detect_by_fingerprint(host: str, session: aiohttp.ClientSession, timeout: int) -> Optional[str]:
    """Additional fingerprint-based detection"""
    try:
        test_urls = [
            f"https://{host}/",
            f"https://{host}/?test=waf_detection_123",
        ]

        for url in test_urls:
            try:
                async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                    content = (await resp.text())[:50000].lower()
                    # Cloudflare
                    if any(p in content for p in ["cf-browser-verification", "challenge-platform", "cloudflare"]):
                        return "Cloudflare"
                    # Akamai
                    if "akamai" in content or "akamaighost" in content:
                        return "Akamai"
                    # AWS WAF
                    if "aws" in content and "waf" in content:
                        return "AWS WAF"

                    waf_indicators = {
                        "Cloudflare": ["cloudflare", "cf-"],
                        "Akamai": ["akamai", "akamaighost"],
                        "Imperva": ["incapsula", "imperva"],
                        "Sucuri": ["sucuri", "sucuri website firewall"],
                        "AWS WAF": ["aws", "amazon", "request blocked"],
                    }
                    for provider, indicators in waf_indicators.items():
                        if any(indicator in content for indicator in indicators):
                            return provider
            except Exception:
                continue
    except Exception:
        pass
    return None

# =====================================
# Takeover detection (DNS + optional HTTP)
# =====================================

def detect_takeover(subdomain: str, nameserver: Optional[str] = None, timeout: int = 5, require_http_signature: bool = True) -> Optional[str]:
    known_services = {
        "Amazon S3": "s3.amazonaws.com",
        "GitHub Pages": "github.io",
        "Heroku": "herokuapp.com",
        "Bitbucket": "bitbucket.io",
        "Cargo": "cargocollective.com",
        "Fastly": "fastly.net",
        "Shopify": "myshopify.com",
        "Squarespace": "squarespace.com",
        "Tumblr": "tumblr.com",
        "WordPress": "wordpress.com",
        "Wix": "wixsite.com",
        "Zendesk": "zendesk.com",
        "Readthedocs": "readthedocs.io",
        "Tilda": "tilda.ws",
        "Webflow": "webflow.io",
        "Helpjuice": "helpjuice.com",
        "Surge": "surge.sh",
        "Ghost": "ghost.io",
    }

    takeover_signatures: Dict[str, List[str]] = {
        "Amazon S3": ["NoSuchBucket", "The specified bucket does not exist", "BucketNotFound"],
        "GitHub Pages": ["There isn't a GitHub Pages site here.", "404 There isn't a GitHub Pages site here"],
        "Heroku": ["no such app", "There's nothing here, yet.", "heroku", "Heroku | No such app"],
        "Shopify": ["Sorry, this shop is currently unavailable", "Only one step left!"],
        "Tumblr": ["There's nothing here.", "Whatever you were looking for doesn't currently exist at this address"],
        "Readthedocs": ["is not a registered project of Read the Docs", "Read the Docs"],
        "Webflow": ["The page you are looking for doesn't exist or has been moved"],
        "Ghost": ["Publication not found", "The thing you were looking for is no longer here"],
    }

    def _http_probe(sig_list: List[str]) -> bool:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": f"Mozilla/5.0 ({TOOL_NAME} TakeoverProbe)", "Accept-Encoding": "identity"}
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx if scheme == "https" else None) as resp:
                    body = resp.read(4096).decode("utf-8", errors="ignore")
                    if any(sig.lower() in body.lower() for sig in sig_list):
                        return True
            except Exception:
                continue
        return False

    try:
        res = dns.resolver.Resolver()
        if nameserver:
            res.nameservers = [nameserver]
        res.timeout = timeout
        res.lifetime = timeout
        answers = res.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).lower().rstrip(".")
            for service_name, indicator in known_services.items():
                if indicator in cname:
                    sigs = takeover_signatures.get(service_name)
                    if sigs:
                        if _http_probe(sigs):
                            return service_name
                        if require_http_signature:
                            continue
                    if not require_http_signature:
                        return service_name
    except Exception:
        pass
    return None

def recursive_enum(subdomain: str) -> List[str]:
    return [f"test.{subdomain}"]

# =====================================
# Helpers for passive enumeration
# =====================================

def _normalize_name(name: str, root: str) -> Optional[str]:
    s = (name or "").strip().lower()
    if not s:
        return None
    if s.startswith("http://") or s.startswith("https://"):
        s = s.split("://", 1)[1]
    if s.startswith("*."):
        s = s[2:]
    s = s.strip(".")
    if not re.match(r"^[a-z0-9._\-]+(\.[a-z0-9._\-]+)*$", s):
        return None
    if s == root or s.endswith("." + root):
        return s
    return None

def _host_from_url(u: str) -> str:
    try:
        h = urlparse(u).netloc
        if not h:
            h = urlparse("http://" + u).netloc
        h = h.split("@")[-1]
        h = h.split(":")[0]
        return h.lower().strip(".")
    except Exception:
        return ""

def _backoff_sleep(attempt: int) -> float:
    return min(10.0, 1.5 ** attempt) + random.uniform(0, 0.5)

def _parse_crtsh_text(text: str):
    items = []
    t = (text or "").lstrip()
    if not t:
        return items
    if t.startswith("<"):
        return items
    try:
        obj = json.loads(t)
        if isinstance(obj, list):
            return obj
        elif isinstance(obj, dict):
            return [obj]
    except Exception:
        pass
    for line in t.splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith("<"):
            continue
        try:
            items.append(json.loads(line))
        except Exception:
            continue
    return items

# =====================================
# Passive sources (no keys)
# =====================================

async def _query_crtsh(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json", "deduplicate": "Y"}
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, params=params) as resp:
                text = await resp.text(errors="ignore")
                if resp.status != 200:
                    logger.info(f"crt.sh responded {resp.status} (attempt {attempt}/{retries}).")
                rows = _parse_crtsh_text(text)
                if not rows:
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay: await asyncio.sleep(delay)
                        continue
                    break
                for row in rows:
                    for val in (row.get("name_value") or "").split("\n"):
                        s = _normalize_name(val, domain)
                        if s:
                            out.add(s)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.info(f"crt.sh error: {e.__class__.__name__}: {e} (attempt {attempt}/{retries}).")
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay: await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_certspotter(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = "https://api.certspotter.com/v1/issuances"
    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names",
        "match_wildcards": "true",
    }
    next_after = None
    pages = 0
    max_pages = 5
    while pages < max_pages:
        if next_after:
            params["after"] = next_after
        else:
            params.pop("after", None)
        for attempt in range(1, retries + 1):
            try:
                async with session.get(url, params=params) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json(content_type=None)
                        except Exception:
                            text = await resp.text(errors="ignore")
                            data = json.loads(text)
                        for item in data or []:
                            for dn in item.get("dns_names", []) or []:
                                s = _normalize_name(dn, domain)
                                if s:
                                    out.add(s)
                        link = resp.headers.get("Link", "")
                        m = re.search(r'<[^>]*[?&]after=([^&>]+)[^>]*>;\s*rel="next"', link)
                        if m:
                            next_after = m.group(1)
                            pages += 1
                            break
                        return out
                    elif resp.status == 429:
                        ra = resp.headers.get("Retry-After")
                        sleep_for = float(ra) if ra and re.match(r"^\d+(\.\d+)?$", ra) else _backoff_sleep(attempt)
                        logger.info(f"CertSpotter 429. Sleeping {sleep_for:.1f}s.")
                        await asyncio.sleep(sleep_for)
                    elif 500 <= resp.status < 600:
                        logger.info(f"CertSpotter {resp.status} (attempt {attempt}/{retries}).")
                        if attempt < retries:
                            await asyncio.sleep(_backoff_sleep(attempt))
                        else:
                            return out
                    else:
                        return out
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < retries:
                    await asyncio.sleep(_backoff_sleep(attempt))
                else:
                    return out
            finally:
                if delay: await asyncio.sleep(delay)
    return out

async def _query_omnisint(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = f"https://sonar.omnisint.io/subdomains/{domain}"
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay: await asyncio.sleep(delay)
                        continue
                    break
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    text = await resp.text(errors="ignore")
                    data = json.loads(text)
                for n in data or []:
                    cand = n if n.endswith("." + domain) or n == domain else f"{n}.{domain}"
                    s = _normalize_name(cand, domain)
                    if s:
                        out.add(s)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay: await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_bufferover(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = "https://dns.bufferover.run/dns"
    params = {"q": f".{domain}"}
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay: await asyncio.sleep(delay)
                        continue
                    break
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    text = await resp.text(errors="ignore")
                    data = json.loads(text)
                for key in ("FDNS_A", "RDNS", "FDNS_CNAME"):
                    for rec in data.get(key, []) or []:
                        parts = rec.split(",", 1)
                        cand = parts[1] if len(parts) > 1 else parts[0]
                        s = _normalize_name(cand, domain)
                        if s:
                            out.add(s)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay: await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_rapiddns(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, headers=headers) as resp:
                html = await resp.text(errors="ignore")
                if resp.status != 200 or "<html" not in html.lower():
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay: await asyncio.sleep(delay)
                        continue
                    break
                soup = BeautifulSoup(html, "html.parser")
                for td in soup.find_all("td"):
                    s = _normalize_name(td.get_text(strip=True), domain)
                    if s:
                        out.add(s)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay: await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_threatcrowd(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = "https://www.threatcrowd.org/searchApi/v2/domain/report/"
    params = {"domain": domain}
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay: await asyncio.sleep(delay)
                        continue
                    break
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    text = await resp.text(errors="ignore")
                    data = json.loads(text)
                for n in data.get("subdomains", []) or []:
                    s = _normalize_name(n, domain)
                    if s:
                        out.add(s)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay: await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_threatminer(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = "https://api.threatminer.org/v2/domain.php"
    params = {"q": domain, "rt": "5"}
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay: await asyncio.sleep(delay)
                        continue
                    break
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    text = await resp.text(errors="ignore")
                    data = json.loads(text)
                for n in data.get("results", []) or []:
                    s = _normalize_name(n, domain)
                    if s:
                        out.add(s)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay: await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_sublist3r_api(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = "https://api.sublist3r.com/search.php"
    params = {"domain": domain}
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay: await asyncio.sleep(delay)
                        continue
                    break
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    text = await resp.text(errors="ignore")
                    try:
                        data = json.loads(text)
                    except Exception:
                        data = []
                for n in data or []:
                    s = _normalize_name(n, domain)
                    if s:
                        out.add(s)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay: await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_wayback(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
    }
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay: await asyncio.sleep(delay)
                        continue
                    break
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    text = await resp.text(errors="ignore")
                    data = json.loads(text)
                for row in data[1:] if isinstance(data, list) and data else []:
                    if isinstance(row, list) and row:
                        host = _host_from_url(row[0])
                        s = _normalize_name(host, domain)
                        if s:
                            out.add(s)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay: await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_urlscan(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    base = "https://urlscan.io/api/v1/search/"
    max_pages = 3
    for page in range(1, max_pages + 1):
        params = {"q": f"domain:{domain}", "page": str(page)}
        for attempt in range(1, retries + 1):
            try:
                async with session.get(base, params=params) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json(content_type=None)
                        except Exception:
                            text = await resp.text(errors="ignore")
                            data = json.loads(text)
                        for item in data.get("results", []) or []:
                            for key in ("page", "task"):
                                if key in item and isinstance(item[key], dict):
                                    dn = item[key].get("domain")
                                    s = _normalize_name(dn, domain)
                                    if s:
                                        out.add(s)
                            u = item.get("page", {}).get("url") or item.get("task", {}).get("url")
                            if u:
                                s = _normalize_name(_host_from_url(u), domain)
                                if s:
                                    out.add(s)
                        break
                    elif resp.status in (429,):
                        ra = resp.headers.get("Retry-After")
                        sleep_for = float(ra) if ra and re.match(r"^\d+(\.\d+)?$", ra) else _backoff_sleep(attempt)
                        logger.info(f"urlscan 429. Sleeping {sleep_for:.1f}s.")
                        await asyncio.sleep(sleep_for)
                        continue
                    elif resp.status in (502, 503, 504):
                        if attempt < retries:
                            await asyncio.sleep(_backoff_sleep(attempt))
                            if delay: await asyncio.sleep(delay)
                            continue
                        break
                    else:
                        break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < retries:
                    await asyncio.sleep(_backoff_sleep(attempt))
                    if delay: await asyncio.sleep(delay)
                    continue
                break
        if delay:
            await asyncio.sleep(delay)
    return out

async def _query_anubis(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    if attempt < retries:
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay:
                            await asyncio.sleep(delay)
                        continue
                    break
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    data = []
                for n in data or []:
                    s = _normalize_name(n, domain)
                    if s:
                        out.add(s)
                break
        except Exception:
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay:
                    await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_hackertarget_hostsearch(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url = "https://api.hackertarget.com/hostsearch/"
    params = {"q": domain}
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, params=params) as resp:
                text = await resp.text(errors="ignore")
                if resp.status != 200 or "error" in text.lower():
                    if attempt < retries and "exceeded" not in text.lower():
                        await asyncio.sleep(_backoff_sleep(attempt))
                        if delay:
                            await asyncio.sleep(delay)
                        continue
                    break
                for line in text.splitlines():
                    parts = line.split(",")
                    if parts:
                        s = _normalize_name(parts[0].strip(), domain)
                        if s:
                            out.add(s)
                break
        except Exception:
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay:
                    await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_otx(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    url_subs = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/subdomains"
    url_pdns = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url_subs) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json(content_type=None)
                    except Exception:
                        data = {}
                    for n in data.get("subdomains", []) or []:
                        s = _normalize_name(n, domain)
                        if s:
                            out.add(s)
                elif resp.status in (429,):
                    ra = resp.headers.get("Retry-After")
                    sleep_for = float(ra) if ra and re.match(r"^\d+(\.\d+)?$", ra) else _backoff_sleep(attempt)
                    await asyncio.sleep(sleep_for)
            async with session.get(url_pdns) as resp2:
                if resp2.status == 200:
                    try:
                        data2 = await resp2.json(content_type=None)
                    except Exception:
                        data2 = {}
                    for rec in data2.get("passive_dns", []) or []:
                        s = _normalize_name(rec.get("hostname", ""), domain)
                        if s:
                            out.add(s)
                elif resp2.status in (429,):
                    ra = resp2.headers.get("Retry-After")
                    sleep_for = float(ra) if ra and re.match(r"^\d+(\.\d+)?$", ra) else _backoff_sleep(attempt)
                    await asyncio.sleep(sleep_for)
            break
        except Exception:
            if attempt < retries:
                await asyncio.sleep(_backoff_sleep(attempt))
                if delay:
                    await asyncio.sleep(delay)
                continue
            break
    return out

async def _query_sitedossier(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    urls = [
        f"http://www.sitedossier.com/parentdomain/{domain}",
        f"https://www.sitedossier.com/parentdomain/{domain}",
    ]
    for url in urls:
        for attempt in range(1, retries + 1):
            try:
                async with session.get(url) as resp:
                    html = await resp.text(errors="ignore")
                    if resp.status != 200 or not html:
                        if attempt < retries:
                            await asyncio.sleep(_backoff_sleep(attempt))
                            if delay:
                                await asyncio.sleep(delay)
                            continue
                        break
                    soup = BeautifulSoup(html, "html.parser")
                    texts = [html]
                    for a in soup.find_all("a"):
                        texts.append(a.get_text(" ", strip=True))
                        href = a.get("href")
                        if href:
                            texts.append(href)
                    blob = " ".join(texts)
                    pattern = re.compile(rf"[a-z0-9._-]+\.{re.escape(domain)}", re.I)
                    for m in pattern.findall(blob):
                        s = _normalize_name(m, domain)
                        if s:
                            out.add(s)
                    break
            except Exception:
                if attempt < retries:
                    await asyncio.sleep(_backoff_sleep(attempt))
                    if delay:
                        await asyncio.sleep(delay)
                    continue
                break
    return out

async def _query_virustotal_ui(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    base = f"https://www.virustotal.com/ui/domains/{domain}/subdomains"
    cursor = None
    pages = 0
    max_pages = 5
    headers = {"x-app-locale": "en-US"}
    while pages < max_pages:
        params = {"limit": "40"}
        if cursor:
            params["cursor"] = cursor
        for attempt in range(1, retries + 1):
            try:
                async with session.get(base, params=params, headers=headers) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json(content_type=None)
                        except Exception:
                            text = await resp.text(errors="ignore")
                            try:
                                data = json.loads(text)
                            except Exception:
                                data = {}
                        for item in data.get("data", []) or []:
                            dn = item.get("id") or item.get("value") or (item.get("attributes", {}) or {}).get("id")
                            s = _normalize_name(dn or "", domain)
                            if s:
                                out.add(s)
                        cursor = (data.get("meta") or {}).get("cursor")
                        pages += 1
                        if not cursor:
                            return out
                        break
                    elif resp.status in (401, 403):
                        return out
                    elif resp.status == 429:
                        ra = resp.headers.get("Retry-After")
                        sleep_for = float(ra) if ra and re.match(r"^\d+(\.\d+)?$", ra) else _backoff_sleep(attempt)
                        await asyncio.sleep(sleep_for)
                    elif 500 <= resp.status < 600:
                        if attempt < retries:
                            await asyncio.sleep(_backoff_sleep(attempt))
                            continue
                        return out
                    else:
                        return out
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < retries:
                    await asyncio.sleep(_backoff_sleep(attempt))
                    continue
                return out
        if delay:
            await asyncio.sleep(delay)
    return out

async def _query_c99_web(session: aiohttp.ClientSession, domain: str, retries: int, delay: float) -> Set[str]:
    out: Set[str] = set()
    base = "https://www.c99.nl/tools/subdomain-finder"
    attempts = [
        ("GET", {"domain": domain}, None),
        ("POST", None, {"domain": domain}),
    ]
    for method, params, data in attempts:
        for attempt in range(1, retries + 1):
            try:
                if method == "GET":
                    async with session.get(base, params=params) as resp:
                        html = await resp.text(errors="ignore")
                        if resp.status != 200:
                            if attempt < retries:
                                await asyncio.sleep(_backoff_sleep(attempt))
                                if delay:
                                    await asyncio.sleep(delay)
                                continue
                            break
                        pattern = re.compile(rf"[a-z0-9._-]+\.{re.escape(domain)}", re.I)
                        for m in pattern.findall(html or ""):
                            s = _normalize_name(m, domain)
                            if s:
                                out.add(s)
                        break
                else:
                    async with session.post(base, data=data) as resp:
                        html = await resp.text(errors="ignore")
                        if resp.status != 200:
                            if attempt < retries:
                                await asyncio.sleep(_backoff_sleep(attempt))
                                if delay:
                                    await asyncio.sleep(delay)
                                continue
                            break
                        pattern = re.compile(rf"[a-z0-9._-]+\.{re.escape(domain)}", re.I)
                        for m in pattern.findall(html or ""):
                            s = _normalize_name(m, domain)
                            if s:
                                out.add(s)
                        break
            except Exception:
                if attempt < retries:
                    await asyncio.sleep(_backoff_sleep(attempt))
                    if delay:
                        await asyncio.sleep(delay)
                    continue
                break
    return out

# =====================================
# Passive enumeration orchestrator
# =====================================

async def passive_enum(
    domain: str,
    timeout: int = 10,
    retries: int = 5,
    delay: float = 0.0,
    silent: bool = False,
    verify_ssl: bool = True,
    experimental_sources: bool = False,
    tool_name: str = TOOL_NAME,
) -> List[str]:
    headers = {
        "User-Agent": f"Mozilla/5.0 ({tool_name})",
        "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
    }
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    results: Set[str] = set()

    base_sources = "crt.sh, CertSpotter, Omnisint, BufferOver, RapidDNS, ThreatCrowd, ThreatMiner, Sublist3r, Wayback, urlscan, Anubis, OTX, HackerTarget, SiteDossier"
    extra = ", VirusTotal UI, c99.nl" if experimental_sources else ""
    status_text = f"[cyan]Querying passive sources ({base_sources}{extra})...[/cyan]"
    status_cm = console.status(status_text) if not silent else contextlib.nullcontext()
    with status_cm:
        async with aiohttp.ClientSession(
            headers=headers,
            timeout=client_timeout,
            connector=aiohttp.TCPConnector(limit=12, ssl=None if verify_ssl else False),
            trust_env=True,
        ) as session:
            tasks = [
                _query_crtsh(session, domain, retries, delay),
                _query_certspotter(session, domain, retries, delay),
                _query_omnisint(session, domain, retries, delay),
                _query_bufferover(session, domain, retries, delay),
                _query_rapiddns(session, domain, retries, delay),
                _query_threatcrowd(session, domain, retries, delay),
                _query_threatminer(session, domain, retries, delay),
                _query_sublist3r_api(session, domain, retries, delay),
                _query_wayback(session, domain, retries, delay),
                _query_urlscan(session, domain, retries, delay),
                _query_anubis(session, domain, retries, delay),
                _query_otx(session, domain, retries, delay),
                _query_hackertarget_hostsearch(session, domain, retries, delay),
                _query_sitedossier(session, domain, retries, delay),
            ]
            if experimental_sources:
                tasks.extend([
                    _query_virustotal_ui(session, domain, retries, delay),
                    _query_c99_web(session, domain, retries, delay),
                ])
            gathered = await asyncio.gather(*tasks, return_exceptions=True)

    for idx, r in enumerate(gathered, start=1):
        if isinstance(r, Exception):
            logger.info(f"Passive source #{idx} failed: {r}")
        else:
            results.update(r)

    return sorted(results)

# =====================================
# Enhanced WAF/CDN detection
# =====================================

async def _resolve_records(name: str, nameserver: Optional[str], timeout: int):
    ips, cnames = set(), set()
    try:
        from dns import asyncresolver as dns_asyncresolver
        resolver = dns_asyncresolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                ans = await resolver.resolve(name, rtype)
                if rtype == "CNAME":
                    cnames.update([str(r.target).rstrip(".").lower() for r in ans])
                else:
                    ips.update([str(r) for r in ans])
            except Exception:
                pass
        return ips, cnames
    except Exception:
        res = dns.resolver.Resolver()
        if nameserver:
            res.nameservers = [nameserver]
        res.timeout = timeout
        res.lifetime = timeout
        def sync_res():
            _ips, _cn = set(), set()
            for rtype in ("A", "AAAA", "CNAME"):
                try:
                    ans = res.resolve(name, rtype)
                    if rtype == "CNAME":
                        _cn.update([str(r.target).rstrip(".").lower() for r in ans])
                    else:
                        _ips.update([str(r) for r in ans])
                except Exception:
                    pass
            return _ips, _cn
        return await asyncio.to_thread(sync_res)

async def _fetch_headers_for_host(host: str, session: aiohttp.ClientSession, timeout: int) -> dict:
    ct = aiohttp.ClientTimeout(total=timeout)
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            async with session.request("HEAD", url, allow_redirects=True, timeout=ct) as resp:
                if resp.status in (405, 403, 501):
                    try:
                        async with session.get(url, allow_redirects=True, timeout=ct) as resp2:
                            return dict(resp2.headers)
                    except Exception:
                        continue
                return dict(resp.headers)
        except Exception:
            continue
    return {}

async def enhanced_waf_detect(host: str, nameserver: Optional[str], timeout: int, verify_ssl: bool = True, tool_name: str = TOOL_NAME) -> Dict[str, Any]:
    """Enhanced WAF detection with multiple methods"""
    ips, cnames = await _resolve_records(host, nameserver, timeout)

    reasons = []
    detected_providers = set()

    # IP-based detection
    for ip in ips:
        provider = _detect_waf_by_ip(ip)
        if provider:
            provider = _alias(provider)
            detected_providers.add(provider)
            reasons.append(f"IP {ip} in {provider} netblock")

    # CNAME-based detection
    for cname in cnames:
        cname_lower = cname.lower()
        for provider, patterns in CNAME_HINTS.items():
            if any(pattern in cname_lower for pattern in patterns):
                provider = _alias(provider)
                detected_providers.add(provider)
                reasons.append(f"CNAME {cname} matches {provider} pattern")
                break

    # Header-based detection
    headers = {}
    try:
        async with _make_http_session(limit=20, verify_ssl=verify_ssl, tool_name=tool_name) as session:
            headers = await _fetch_headers_for_host(host, session, timeout=min(10, max(3, timeout)))
    except Exception as e:
        reasons.append(f"Header fetch failed: {e}")

    header_provider = _classify_by_headers_enhanced(headers) if headers else None
    if header_provider:
        header_provider = _alias(header_provider)
        detected_providers.add(header_provider)
        reasons.append(f"Headers indicate {header_provider}")

    # Fingerprint-based detection
    if not detected_providers:
        try:
            async with _make_http_session(limit=20, verify_ssl=verify_ssl, tool_name=tool_name) as session:
                fingerprint_provider = await _detect_by_fingerprint(host, session, timeout)
                if fingerprint_provider:
                    fingerprint_provider = _alias(fingerprint_provider)
                    detected_providers.add(fingerprint_provider)
                    reasons.append(f"Fingerprint matches {fingerprint_provider}")
        except Exception as e:
            reasons.append(f"Fingerprint detection failed: {e}")

    # Final provider with confidence
    if detected_providers:
        if "Cloudflare" in detected_providers:
            final_provider = "Cloudflare"
            confidence = "high"
        elif "Akamai" in detected_providers:
            final_provider = "Akamai"
            confidence = "high"
        elif "CloudFront" in detected_providers:
            final_provider = "CloudFront"
            confidence = "high"
        elif "Fastly" in detected_providers:
            final_provider = "Fastly"
            confidence = "high"
        else:
            final_provider = sorted(detected_providers)[0]
            confidence = "medium"
    else:
        final_provider = "Unknown"
        confidence = "low"
        reasons.append("No WAF/CDN signals detected")

    return {
        "host": host,
        "provider": final_provider,
        "confidence": confidence,
        "detected_providers": sorted(detected_providers),
        "ips": sorted(ips),
        "cnames": sorted(cnames),
        "reasons": reasons,
        "headers_sample": dict(list({k: v for k, v in headers.items()}.items())[:8]) if headers else {},
    }

async def waf_detect_single(host: str, nameserver: Optional[str], timeout: int, verify_ssl: bool = True, tool_name: str = TOOL_NAME) -> Dict[str, Any]:
    """Enhanced WAF detection - uses the new detection engine"""
    return await enhanced_waf_detect(host, nameserver, timeout, verify_ssl, tool_name)

# =====================================
# Enhanced Technology Detection with Formatted Output
# =====================================

def format_tech_output(tech_results: Dict[str, List[str]]) -> str:
    """Format technology detection results in a structured way"""
    if not tech_results:
        return "[yellow]No technologies detected[/yellow]"

    output_lines = []

    for host, techs in sorted(tech_results.items()):
        if not techs:
            output_lines.append(f"[dim]{host} → No technologies detected[/dim]")
            continue

        categories = {
            "🌐 Web Server": [],
            "⚙️ Backend Framework": [],
            "🎨 Frontend Framework": [],
            "📱 CMS/Platform": [],
            "🛡️ CDN/WAF": [],
            "📊 Analytics/Tracking": [],
            "🔧 Development Tools": [],
            "📦 Other Technologies": []
        }

        tech_mapping = {
            "Nginx": "🌐 Web Server",
            "Apache": "🌐 Web Server",
            "LiteSpeed": "🌐 Web Server",
            "Gunicorn": "🌐 Web Server",
            "uWSGI": "🌐 Web Server",
            "Tomcat": "🌐 Web Server",

            "PHP": "⚙️ Backend Framework",
            "ASP.NET": "⚙️ Backend Framework",
            "Express": "⚙️ Backend Framework",
            "Laravel": "⚙️ Backend Framework",
            "Node.js": "⚙️ Backend Framework",

            "React": "🎨 Frontend Framework",
            "Vue.js": "🎨 Frontend Framework",
            "Angular": "🎨 Frontend Framework",
            "jQuery": "🎨 Frontend Framework",
            "Bootstrap": "🎨 Frontend Framework",
            "Tailwind CSS": "🎨 Frontend Framework",
            "Next.js": "🎨 Frontend Framework",
            "Nuxt.js": "🎨 Frontend Framework",
            "Foundation": "🎨 Frontend Framework",
            "Bulma": "🎨 Frontend Framework",

            "WordPress": "📱 CMS/Platform",
            "Drupal": "📱 CMS/Platform",
            "Joomla": "📱 CMS/Platform",
            "Ghost": "📱 CMS/Platform",
            "Shopify": "📱 CMS/Platform",
            "Wix": "📱 CMS/Platform",
            "Squarespace": "📱 CMS/Platform",
            "Webflow": "📱 CMS/Platform",
            "Magento": "📱 CMS/Platform",

            "Cloudflare CDN": "🛡️ CDN/WAF",
            "Cloudflare": "🛡️ CDN/WAF",
            "Akamai CDN": "🛡️ CDN/WAF",
            "Akamai": "🛡️ CDN/WAF",
            "Fastly CDN": "🛡️ CDN/WAF",
            "Fastly": "🛡️ CDN/WAF",
            "CloudFront": "🛡️ CDN/WAF",

            "Google Analytics / GTM": "📊 Analytics/Tracking",
            "Matomo": "📊 Analytics/Tracking",
            "Hotjar": "📊 Analytics/Tracking",
            "HubSpot": "📊 Analytics/Tracking",
            "Facebook Pixel": "📊 Analytics/Tracking",
            "Google Ads": "📊 Analytics/Tracking",

            "Vercel": "🔧 Development Tools",
            "Netlify": "🔧 Development Tools",
            "Heroku": "🔧 Development Tools",
            "Azure App Service": "🔧 Development Tools",
        }

        for tech in techs:
            category = tech_mapping.get(tech, "📦 Other Technologies")
            categories[category].append(tech)

        output_lines.append(f"[bold cyan]{host}[/bold cyan]")

        for category, tech_list in categories.items():
            if tech_list:
                tech_list = sorted(set(tech_list))
                tech_string = ", ".join(tech_list)
                output_lines.append(f"  {category}: [white]{tech_string}[/white]")

        output_lines.append("")

    return "\n".join(output_lines)

async def _fetch_page_with_session(host: str, session: aiohttp.ClientSession, timeout: int):
    ct = aiohttp.ClientTimeout(total=timeout)
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            async with session.get(url, allow_redirects=True, timeout=ct) as resp:
                final_url = str(resp.url)
                headers = dict(resp.headers)
                try:
                    set_cookies = resp.headers.getall("Set-Cookie", [])
                except Exception:
                    v = resp.headers.get("Set-Cookie")
                    set_cookies = [v] if v else []
                text = await resp.text(errors="ignore")
                return final_url, headers, set_cookies, text[:1_000_000]
        except Exception:
            continue
    return None, {}, [], ""

def _parse_set_cookie_names(set_cookie_list):
    names = set()
    for c in set_cookie_list or []:
        try:
            name = c.split("=", 1)[0].strip()
            if name:
                names.add(name)
        except Exception:
            continue
    return names

def _heuristic_tech(headers: dict, html: str, final_url: Optional[str]) -> list[str]:
    """Enhanced technology detection with better categorization"""
    techs = set()
    h = {k.lower(): v for k, v in (headers or {}).items()}
    server = h.get("server", "").lower()
    xpb = h.get("x-powered-by", "").lower()
    via = h.get("via", "").lower()
    set_cookie_list = h.get("set-cookie", []) if isinstance(h.get("set-cookie"), list) else []
    cookies = _parse_set_cookie_names(set_cookie_list)

    if "nginx" in server:
        techs.add("Nginx")
    if "apache" in server:
        techs.add("Apache")
        if "coyote" in server:
            techs.add("Tomcat")
    if "litespeed" in server:
        techs.add("LiteSpeed")

    if "vercel" in server or "x-vercel-id" in h:
        techs.add("Vercel")
    if "netlify" in server or "x-nf-request-id" in h:
        techs.add("Netlify")

    if "cloudflare" in server:
        techs.add("Cloudflare CDN")
    if "akamai" in server:
        techs.add("Akamai CDN")
    if "fastly" in server:
        techs.add("Fastly CDN")
    if "cloudfront" in server or "cloudfront" in via:
        techs.add("CloudFront")

    if "express" in xpb or "express" in server:
        techs.add("Express")
    if "php" in xpb or "php" in server or "x-php-version" in h:
        techs.add("PHP")
        if "laravel" in (html or "").lower():
            techs.add("Laravel")
    if "asp.net" in xpb or "microsoft-iis" in server or h.get("x-aspnet-version"):
        techs.add("ASP.NET")
    if "gunicorn" in server:
        techs.add("Gunicorn")
    if "uwsgi" in server:
        techs.add("uWSGI")
    if "nodejs" in server or "node.js" in server:
        techs.add("Node.js")

    cookie_str = " ".join(list(cookies))
    if "PHPSESSID" in cookie_str:
        techs.add("PHP")
    if "ASP.NET_SessionId" in cookie_str:
        techs.add("ASP.NET")
    if "laravel_session" in cookie_str or "XSRF-TOKEN" in cookie_str:
        techs.add("Laravel")
    if "wordpress_logged_in" in cookie_str or "wp-settings" in cookie_str:
        techs.add("WordPress")

    html_l = (html or "").lower()
    try:
        soup = BeautifulSoup(html, "html.parser") if html else None
    except Exception:
        soup = None

    if soup:
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            g = gen["content"].lower()
            if "wordpress" in g:
                techs.add("WordPress")
                if "wp-rocket" in html_l:
                    techs.add("WP Rocket")
                if "yoast" in html_l:
                    techs.add("Yoast SEO")
            if "drupal" in g:
                techs.add("Drupal")
            if "joomla" in g:
                techs.add("Joomla")
            if "ghost" in g:
                techs.add("Ghost")
            if "shopify" in g:
                techs.add("Shopify")
            if "wix" in g:
                techs.add("Wix")
            if "squarespace" in g:
                techs.add("Squarespace")
            if "webflow" in g:
                techs.add("Webflow")

        if soup.find(attrs={"ng-version": True}):
            techs.add("Angular")

        vue_indicators = [
            soup.find("script", src=re.compile(r"vue(\.runtime)?(\.global)?(\.min)?\.js")),
            soup.find("script", src=re.compile(r"vue@[\d.]")),
            'data-v-' in html_l,
            '__vue__' in html_l,
            'v-bind' in html_l or 'v-model' in html_l
        ]
        if any(vue_indicators):
            techs.add("Vue.js")

        react_indicators = [
            soup.find("script", src=re.compile(r"react(\.min)?\.js")),
            soup.find("script", src=re.compile(r"react@[\d.]")),
            "data-reactroot" in html_l,
            "reactdom" in html_l,
            "react-root" in html_l,
            "__reactInternalInstance" in html_l
        ]
        if any(react_indicators):
            techs.add("React")

        if soup.find("script", src=re.compile(r"jquery(-\d|\.|/|@)[\d.]*\.js")):
            techs.add("jQuery")

        if soup.find("link", href=re.compile(r"bootstrap(\.min)?\.css")) or soup.find("script", src=re.compile(r"bootstrap(\.min)?\.js")):
            techs.add("Bootstrap")
        if soup.find("link", href=re.compile(r"tailwind(\.min)?\.css")):
            techs.add("Tailwind CSS")
        if soup.find("link", href=re.compile(r"foundation(\.min)?\.css")):
            techs.add("Foundation")
        if soup.find("link", href=re.compile(r"bulma(\.min)?\.css")):
            techs.add("Bulma")

        assets = " ".join(
            [tag.get("src","") for tag in soup.find_all("script")] +
            [tag.get("href","") for tag in soup.find_all("link")]
        ).lower()

        if "wp-content" in html_l or "wp-includes" in html_l or "wp-json" in html_l:
            techs.add("WordPress")
        if "/sites/default/" in html_l or "drupal.js" in html_l or "drupalSettings" in html_l:
            techs.add("Drupal")
        if "/components/com_" in html_l or "joomla" in html_l or "media/jui/" in html_l:
            techs.add("Joomla")
        if "x-magento" in " ".join(h.keys()) or "mage" in html_l or "/static/frontend/" in html_l or "Magento_" in html_l:
            techs.add("Magento")
        if "cdn.shopify.com" in assets or "shopify" in html_l or "var Shopify" in html_l:
            techs.add("Shopify")
        if "wixstatic.com" in assets or "x-wix-renderer-server" in " ".join(h.keys()).lower() or "wix-warmup-data" in html_l:
            techs.add("Wix")
        if "webflow.js" in assets or "w-embed" in html_l or "webflow.com" in assets:
            techs.add("Webflow")
        if "/_next/" in assets or "window.__next_data__" in html_l or "next/router" in html_l:
            techs.add("Next.js")
        if "/_nuxt/" in assets or "window.$nuxt" in html_l:
            techs.add("Nuxt.js")
        if "squarespace" in assets or "sqs-" in html_l or "static1.squarespace.com" in assets:
            techs.add("Squarespace")

        if "googletagmanager.com" in assets or "gtag(" in html_l or "ga('create'" in html_l or "google-analytics.com" in assets:
            techs.add("Google Analytics / GTM")
        if "matomo.js" in assets or "piwik.js" in assets or "matomo.php" in assets:
            techs.add("Matomo")
        if "hotjar" in assets or "static.hotjar.com" in assets:
            techs.add("Hotjar")
        if "hs-scripts.com" in assets or "hubspot" in html_l:
            techs.add("HubSpot")
        if "facebook.com/tr/" in html_l or "fbq('init'" in html_l:
            techs.add("Facebook Pixel")
        if "doubleclick.net" in assets or "googleadservices.com" in assets:
            techs.add("Google Ads")

    if final_url:
        if ".vercel.app" in final_url:
            techs.add("Vercel")
        if ".netlify.app" in final_url:
            techs.add("Netlify")
        if ".herokuapp.com" in final_url:
            techs.add("Heroku")
        if ".azurewebsites.net" in final_url:
            techs.add("Azure App Service")
        if ".cloudflare.com" in final_url or ".cloudflareaccess.com" in final_url:
            techs.add("Cloudflare CDN")

    return sorted(techs)

async def tech_detect_single_host(host: str, session: aiohttp.ClientSession, timeout: int) -> dict:
    final_url, headers, set_cookies, html = await _fetch_page_with_session(host, session, timeout)
    if set_cookies:
        headers = {**headers, "Set-Cookie": set_cookies}
    techs = _heuristic_tech(headers, html, final_url)
    return {"host": host, "tech": techs}

async def tech_detect_batch(hosts: List[str], timeout: int, concurrency: int, verify_ssl: bool, silent: bool, tool_name: str) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    sem = asyncio.Semaphore(max(1, concurrency))
    async with _make_http_session(limit=concurrency, verify_ssl=verify_ssl, tool_name=tool_name) as session:
        if not silent:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Tech Detection:[/bold blue]"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("Analyzing technologies", total=len(hosts))
                async def wrapped(h):
                    async with sem:
                        try:
                            res = await tech_detect_single_host(h, session, timeout)
                            results[h] = res.get("tech", [])
                        finally:
                            progress.advance(task)
                await asyncio.gather(*(wrapped(h) for h in hosts))
        else:
            async def wrapped(h):
                async with sem:
                    res = await tech_detect_single_host(h, session, timeout)
                    results[h] = res.get("tech", [])
            await asyncio.gather(*(wrapped(h) for h in hosts))
    return results

# =====================================
# DNS resolution filter
# =====================================

async def resolve_dns_filter(subdomains: List[str], nameserver: Optional[str], timeout: int, concurrency: int, silent: bool = False) -> Dict[str, Dict[str, List[str]]]:
    resolved: Dict[str, Dict[str, List[str]]] = {}
    try:
        from dns import asyncresolver as dns_asyncresolver
        use_async = True
    except Exception:
        dns_asyncresolver = None
        use_async = False

    async def resolve_a_aaaa(resolver, host: str) -> Dict[str, List[str]]:
        details = {"A": [], "AAAA": []}
        for rtype in ("A", "AAAA"):
            try:
                ans = await resolver.resolve(host, rtype)
                if ans:
                    details[rtype].extend([str(r) for r in ans])
            except Exception:
                pass
        return details

    if use_async:
        resolver = dns_asyncresolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        sem = asyncio.Semaphore(max(1, concurrency))

        async def do_one(name: str):
            async with sem:
                details = {"A": [], "AAAA": [], "CNAME": []}
                for rtype in ("A", "AAAA", "CNAME"):
                    try:
                        ans = await resolver.resolve(name, rtype)
                        if ans:
                            if rtype == "CNAME":
                                details["CNAME"].extend([str(r.target).rstrip(".") for r in ans])
                            else:
                                details[rtype].extend([str(r) for r in ans])
                    except Exception:
                        pass

                if not details["A"] and not details["AAAA"] and details["CNAME"]:
                    target = details["CNAME"][0]
                    chased = await resolve_a_aaaa(resolver, target)
                    if chased["A"] or chased["AAAA"]:
                        details["A"].extend(chased["A"])
                        details["AAAA"].extend(chased["AAAA"])

                if details["A"] or details["AAAA"] or details["CNAME"]:
                    if details["A"] or details["AAAA"] or (details["CNAME"] and (details["A"] or details["AAAA"])):
                        resolved[name] = details

        if not silent:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]Resolving DNS:[/bold green]"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task_id = progress.add_task("resolve", total=len(subdomains))
                async def runner():
                    async def wrapped(n):
                        try:
                            await do_one(n)
                        finally:
                            progress.advance(task_id)
                    await asyncio.gather(*(wrapped(s) for s in subdomains))
                await runner()
        else:
            await asyncio.gather(*(do_one(s) for s in subdomains))

    else:
        res = dns.resolver.Resolver()
        if nameserver:
            res.nameservers = [nameserver]
        res.timeout = timeout
        res.lifetime = timeout

        sem = asyncio.Semaphore(max(1, concurrency))

        def sync_resolve(name: str) -> Optional[Dict[str, List[str]]]:
            details = {"A": [], "AAAA": [], "CNAME": []}
            for rtype in ("A", "AAAA", "CNAME"):
                try:
                    ans = res.resolve(name, rtype)
                    if ans:
                        if rtype == "CNAME":
                            details["CNAME"].extend([str(r.target).rstrip(".") for r in ans])
                        else:
                            details[rtype].extend([str(r) for r in ans])
                except Exception:
                    pass

            if not details["A"] and not details["AAAA"] and details["CNAME"]:
                target = details["CNAME"][0]
                chased = {"A": [], "AAAA": []}
                for rtype in ("A", "AAAA"):
                    try:
                        ans = res.resolve(target, rtype)
                        if ans:
                            chased[rtype].extend([str(r) for r in ans])
                    except Exception:
                        pass
                if chased["A"] or chased["AAAA"]:
                    details["A"].extend(chased["A"])
                    details["AAAA"].extend(chased["AAAA"])

            if details["A"] or details["AAAA"] or details["CNAME"]:
                if details["A"] or details["AAAA"] or (details["CNAME"] and (details["A"] or details["AAAA"])):
                    return details
            return None

        async def do_one_thread(name: str):
            async with sem:
                try:
                    details = await asyncio.to_thread(sync_resolve, name)
                    if details:
                        resolved[name] = details
                except Exception:
                    pass

        if not silent:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]Resolving DNS:[/bold green]"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task_id = progress.add_task("resolve", total=len(subdomains))
                async def runner():
                    async def wrapped(n):
                        try:
                            await do_one_thread(n)
                        finally:
                            progress.advance(task_id)
                    await asyncio.gather(*(wrapped(s) for s in subdomains))
                await runner()
        else:
            await asyncio.gather(*(do_one_thread(s) for s in subdomains))

    return resolved

# =====================================
# Active enum (dnspython + concurrency)
# =====================================

async def active_enum(domain: str, wordlist_path: str, nameserver: Optional[str] = None, concurrency: int = 100, timeout: int = 5, silent: bool = False) -> List[str]:
    subdomains = set()
    try:
        from dns import asyncresolver, exception
        resolver = asyncresolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        sem = asyncio.Semaphore(max(1, concurrency))

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f_count:
                total = sum(1 for _ in f_count)
        except Exception:
            total = None

        async def try_resolve(host: str):
            async with sem:
                try:
                    try:
                        await resolver.resolve(host, "A")
                        subdomains.add(host)
                    except exception.DNSException:
                        await resolver.resolve(host, "AAAA")
                        subdomains.add(host)
                except Exception:
                    pass

        if not silent:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Scanning:[/bold blue]"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("scan", total=total if total is not None else 0)
                pending: List[asyncio.Task] = []
                scanned = 0
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        w = line.strip()
                        if not w:
                            continue
                        host = f"{w}.{domain}"
                        pending.append(asyncio.create_task(try_resolve(host)))
                        scanned += 1
                        if len(pending) >= concurrency * 5:
                            await asyncio.gather(*pending)
                            pending.clear()
                            progress.update(task, completed=scanned)
                    if pending:
                        await asyncio.gather(*pending)
                        progress.update(task, completed=scanned)
        else:
            pending: List[asyncio.Task] = []
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    w = line.strip()
                    if not w:
                        continue
                    host = f"{w}.{domain}"
                    pending.append(asyncio.create_task(try_resolve(host)))
                    if len(pending) >= concurrency * 5:
                        await asyncio.gather(*pending)
                        pending.clear()
                if pending:
                    await asyncio.gather(*pending)

    except Exception as e:
        console.print(f"[red]Error in active enumeration: {e}")
    return sorted(subdomains)

# =====================================
# Takeover check from file
# =====================================

def takeover_check_from_file(file_path: str, nameserver: Optional[str], timeout: int):
    if not os.path.exists(file_path):
        console.print(f"[red]Input file not found: {file_path}")
        return

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        domains = [line.strip() for line in f if line.strip()]

    console.print("\n[bold]🔐 Subdomain Takeover Check:[/bold]\n")
    for domain in domains:
        service = detect_takeover(domain, nameserver=nameserver, timeout=timeout, require_http_signature=True)
        if service:
            console.print(f"[yellow][Takeover Risk][/yellow] {domain} ➜ {service}")
        else:
            console.print(f"[green][Safe][/green] {domain}")

# =====================================
# Live check (HTTP/HTTPS)
# =====================================

async def check_live_from_file(file_path: str, concurrency: int = 100, verify_ssl: bool = True, silent: bool = False, tool_name: str = TOOL_NAME):
    try:
        with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[bold red]❌ File not found: {file_path}[/bold red]")
        return

    console.print(f"\n[cyan]📡 Checking live subdomains (HTTP/HTTPS) from [bold]{file_path}[/bold][/cyan]\n")
    results = []
    sem = asyncio.Semaphore(max(1, concurrency))

    async with _make_http_session(limit=concurrency, verify_ssl=verify_ssl, tool_name=tool_name) as session:
        async def is_live(host: str) -> Optional[str]:
            async with sem:
                for proto in ("https", "http"):
                    url = f"{proto}://{host}"
                    try:
                        async with session.get(url, allow_redirects=True) as resp:
                            if resp.status < 400:
                                return url
                    except Exception:
                        continue
                return None

        if not silent:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]Probing:[/bold green]"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("probe", total=len(subdomains))
                async def runner():
                    async def wrapped(h):
                        try:
                            live = await is_live(h)
                            if live:
                                console.print(f"[bold green][Live][/bold green] {live} ✅")
                                results.append(live)
                            else:
                                console.print(f"[bold red][Dead][/bold red] {h} ❌")
                        finally:
                            progress.advance(task)
                    await asyncio.gather(*(wrapped(h) for h in subdomains))
                await runner()
        else:
            async def wrapped(h):
                live = await is_live(h)
                if live:
                    console.print(live)
            await asyncio.gather(*(wrapped(h) for h in subdomains))

    if results:
        with open("live_subdomains.txt", "w", encoding='utf-8') as out:
            out.write("\n".join(results) + "\n")
        console.print(f"\n[bold green]📄 Saved live subdomains to live_subdomains.txt[/bold green]\n")

# =====================================
# Main
# =====================================

async def main():
    parser = argparse.ArgumentParser(description="Reconex — Advanced Subdomain Recon")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-dL", "--domains-list", dest="domains_list", metavar="FILE", help="File with domains to enumerate (one per line)")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for brute-forcing")
    parser.add_argument("-o", "--output", help="Save results to file; with -dL, treat as directory for per-domain files")
    parser.add_argument("--json-output", "-J", help="Save structured JSON results to file")

    parser.add_argument("--passive", action="store_true", help="Enable passive enumeration")
    parser.add_argument("--active", action="store_true", help="Enable active enumeration")
    parser.add_argument("--all", action="store_true", help="Run passive and active enumeration")

    parser.add_argument("--experimental-sources", action="store_true",
                        help="Include experimental scraping sources (VirusTotal UI, c99.nl)")

    parser.add_argument("--live", "-L", dest="live", metavar="FILE", help="Check live subdomains from a file")
    parser.add_argument("-live", dest="live", help=argparse.SUPPRESS)

    parser.add_argument("--concurrency", "--threads", type=int, default=100, dest="concurrency",
                        help="Number of concurrent requests (default: 100). '--threads' alias for backward compatibility.")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds for network requests (default: 10)")
    parser.add_argument("--delay", type=float, default=0, help="Delay in seconds between requests (default: 0)")
    parser.add_argument("--silent", action="store_true", help="Run in silent mode (no banners/progress UIs)")
    parser.add_argument("--dns-resolver", help="Custom DNS resolver (e.g., 8.8.8.8)")
    parser.add_argument("--takeover", help="Check for potential subdomain takeovers (single domain or file path)")
    parser.add_argument("--recursive", action="store_true", help="Perform recursive subdomain enumeration")
    parser.add_argument("--waf-check", action="store_true", help="Detect WAF/CDN on the target domain(s)")
    parser.add_argument("--tech-detect", action="store_true", help="Detect web technologies (heuristic)")
    parser.add_argument("--mode", choices=["light", "aggressive"], help="Scan mode presets")
    parser.add_argument("--resolve", action="store_true", help="Resolve and keep only DNS-valid subdomains (A/AAAA or CNAME→A/AAAA)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification for HTTP requests")

    parser.add_argument("--name", help="Override tool name shown in the banner and User-Agent")

    args = parser.parse_args()

    if args.mode:
        if args.mode == "light":
            args.concurrency = 50
            args.timeout = 5
            args.delay = 0.1
        elif args.mode == "aggressive":
            args.concurrency = 200
            args.timeout = 15
            args.delay = 0

    tool_name = args.name or TOOL_NAME

    # Build target domain list
    target_domains: List[str] = []
    if args.domain:
        target_domains.append(args.domain.strip())
    if args.domains_list:
        if not os.path.isfile(args.domains_list):
            console.print(f"[bold red]❌ Domains list file not found: {args.domains_list}[/bold red]")
            return
        with open(args.domains_list, "r", encoding="utf-8", errors="ignore") as df:
            for line in df:
                d = line.strip()
                if d:
                    target_domains.append(d)
        # Deduplicate while preserving order
        seen = set()
        target_domains = [d for d in target_domains if not (d in seen or seen.add(d))]

    # Default to passive if domain(s) provided without other mode flags
    if target_domains and not any([args.passive, args.active, args.all, args.live, args.takeover, args.waf_check, args.tech_detect]):
        args.passive = True
        if not args.silent:
            console.print("[italic cyan]No mode flags provided; defaulting to passive enumeration.[/italic cyan]")

    if not args.silent:
        console.print(render_banner(TOOL_VERSION, name=tool_name, author="R3XD17"))
        console.print(render_legend())

    # Early actions that use external files
    if args.live:
        await check_live_from_file(args.live, concurrency=args.concurrency, verify_ssl=not args.no_verify, silent=args.silent, tool_name=tool_name)
        return

    if args.takeover:
        if os.path.isfile(args.takeover):
            takeover_check_from_file(args.takeover, nameserver=args.dns_resolver, timeout=args.timeout)
            return
        else:
            target = args.takeover.strip()
            console.print("\n[bold]🔐 Subdomain Takeover Check (single domain):[/bold]\n")
            service = detect_takeover(target, nameserver=args.dns_resolver, timeout=args.timeout, require_http_signature=True)
            if service:
                console.print(f"[yellow][Takeover Risk][/yellow] {target} ➜ {service}")
            else:
                console.print(f"[green][Safe][/green] {target}")
            return

    # Nothing to do?
    if not target_domains:
        console.print("[red]Error: Please specify a domain using -d or a domains list with -dL; or use --live/--takeover with file.[/red]")
        return

    # Prepare holders so we can include in JSON
    batch_mode = bool(args.domains_list)
    waf_result_single: Optional[Dict[str, Any]] = None
    waf_results_map: Dict[str, Dict[str, Any]] = {}

    # WAF check (single or batch)
    if args.waf_check:
        if not args.silent:
            console.print("[bold blue]WAF/CDN detection[/bold blue]")
        for d in target_domains:
            result = await enhanced_waf_detect(
                d,
                nameserver=args.dns_resolver,
                timeout=args.timeout,
                verify_ssl=not args.no_verify,
                tool_name=tool_name,
            )
            waf_results_map[d] = result
            if len(target_domains) == 1:
                waf_result_single = result

            confidence_color = {
                "high": "green",
                "medium": "yellow",
                "low": "red"
            }.get(result["confidence"], "white")

            console.print(f"[blue][WAF][/blue] {result['host']} ➜ [{confidence_color}]{result['provider']} ({result['confidence']} confidence)[/{confidence_color}]")
            if result["ips"]:
                console.print(f"  IPs: {', '.join(result['ips'])}")
            if result["cnames"]:
                console.print(f"  CNAMEs: {', '.join(result['cnames'])}")
            if result["reasons"]:
                console.print("  Detection Signals:")
                for r in result["reasons"]:
                    console.print(f"   • {r}")
            if result["headers_sample"]:
                console.print("  Sample Headers:")
                for k, v in list(result["headers_sample"].items())[:4]:
                    console.print(f"   • {k}: {v}")

    # Tech-detect only (no enumeration flags)
    tech_roots_map: Optional[Dict[str, List[str]]] = None
    if args.tech_detect and not any([args.passive, args.active, args.all]):
        tech_roots_map = {}
        async with _make_http_session(limit=min(20, args.concurrency), verify_ssl=not args.no_verify, tool_name=tool_name) as session:
            tasks = [tech_detect_single_host(d, session, timeout=args.timeout) for d in target_domains]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    continue
                tech_roots_map[r["host"]] = r.get("tech", [])
        console.print("\n[bold green]🔧 Technology Stack Analysis (roots)[/bold green]")
        console.print("=" * 60)
        console.print(format_tech_output(tech_roots_map))
        console.print("=" * 60)
        # Continue: they may also want enumeration below if flags were passed; here they weren't, so we return
        if not (args.passive or args.active or args.all):
            # If only tech-detect on roots, we can still emit JSON if requested
            if args.json_output:
                out_obj: Dict[str, Any] = {
                    "tool": tool_name,
                    "version": TOOL_VERSION,
                    "domains": {k: {"tech_root": v} for k, v in (tech_roots_map or {}).items()},
                    "waf": waf_results_map or {},
                }
                with open(args.json_output, "w", encoding="utf-8") as jf:
                    json.dump(out_obj, jf, indent=2, sort_keys=True)
                console.print(f"[green]Saved JSON results to {args.json_output}[/green]")
            return

    # Enumeration (single or batch)
    # Decide output directory if -dL and -o looks like directory
    per_domain_output_dir: Optional[str] = None
    if args.output and batch_mode:
        outp = args.output
        if outp.endswith(os.sep) or (os.path.exists(outp) and os.path.isdir(outp)):
            per_domain_output_dir = outp if outp.endswith(os.sep) else outp + os.sep
            os.makedirs(per_domain_output_dir, exist_ok=True)

    # Accumulators
    aggregate_all_subdomains: Set[str] = set()
    domains_data: Dict[str, Dict[str, Any]] = {}

    for d in target_domains:
        all_subdomains = set()
        passive_subs: List[str] = []
        active_subs: List[str] = []
        resolved_details: Optional[Dict[str, Dict[str, List[str]]]] = None

        if args.passive:
            subs = await passive_enum(
                d,
                timeout=args.timeout,
                retries=5,
                delay=args.delay,
                silent=args.silent,
                verify_ssl=not args.no_verify,
                experimental_sources=args.experimental_sources,
                tool_name=tool_name,
            )
            passive_subs = subs
            all_subdomains.update(subs)
            for sub in subs:
                console.print(f"{sub}")

        if args.active and args.wordlist:
            subs = await active_enum(d, args.wordlist, nameserver=args.dns_resolver, concurrency=args.concurrency, timeout=args.timeout, silent=args.silent)
            active_subs = subs
            all_subdomains.update(subs)
            for sub in subs:
                console.print(f"{sub}")

        if args.resolve:
            if not all_subdomains:
                console.print(f"[yellow]No subdomains collected to resolve for {d}.[/yellow]")
            else:
                resolved_details = await resolve_dns_filter(
                    sorted(all_subdomains),
                    nameserver=args.dns_resolver,
                    timeout=args.timeout,
                    concurrency=args.concurrency,
                    silent=args.silent
                )
                before = len(all_subdomains)
                all_subdomains = set(resolved_details.keys())
                after = len(all_subdomains)
                console.print(f"\n[bold green]DNS validation complete ({d}):[/bold green] Kept {after} of {before} subdomains.\n")
                for sub in sorted(all_subdomains):
                    console.print(sub)

        if (args.passive or args.active) and not all_subdomains:
            console.print(f"[yellow]No subdomains found for {d}. Try increasing --timeout, adding --delay (e.g., 0.2), or using --resolve with --dns-resolver 1.1.1.1.[/yellow]")

        # Save per-domain plain text if requested as directory
        if per_domain_output_dir is not None:
            out_path = os.path.join(per_domain_output_dir, f"{d}.txt")
            with open(out_path, "w", encoding="utf-8") as f:
                for sub in sorted(all_subdomains):
                    f.write(sub + "\n")
            console.print(f"[green]Saved {d} results to {out_path}[/green]")

        # Store per-domain data for JSON
        domains_data[d] = {
            "passive": passive_subs,
            "active": active_subs,
            "resolved": resolved_details or {},
            "tech": {},  # filled later if tech-detect on subdomains
            "waf": waf_results_map.get(d, {}),
            "total_unique": len(all_subdomains),
        }

        # Recursive enumeration (print only)
        if args.recursive:
            for sub in sorted(all_subdomains):
                recursed = recursive_enum(sub)
                for r in recursed:
                    console.print(f"[magenta][Recursive][/magenta] {r}")

        aggregate_all_subdomains.update(all_subdomains)

    # Batch Technology Detection for subdomains (if requested)
    if args.tech_detect and aggregate_all_subdomains:
        tech_map_all = await tech_detect_batch(
            sorted(aggregate_all_subdomains),
            timeout=args.timeout,
            concurrency=args.concurrency,
            verify_ssl=not args.no_verify,
            silent=args.silent,
            tool_name=tool_name
        )
        console.print("\n[bold green]🔧 Technology Stack Analysis (subdomains)[/bold green]")
        console.print("=" * 60)
        console.print(format_tech_output(tech_map_all))
        console.print("=" * 60)

        # Split tech_map back per domain
        for d in target_domains:
            per_domain_hosts = {h: t for h, t in tech_map_all.items() if h == d or h.endswith("." + d)}
            domains_data[d]["tech"] = per_domain_hosts

    # Combined outputs if single-file paths are provided
    if args.output and not batch_mode:
        with open(args.output, 'w', encoding='utf-8') as f:
            # Single domain mode: write only that domain's subdomains
            d = target_domains[0]
            subs = set(domains_data[d]["resolved"].keys()) if args.resolve else set(domains_data[d]["passive"]) | set(domains_data[d]["active"])
            for sub in sorted(subs):
                f.write(sub + '\n')
        console.print(f"\n[green]Saved results to {args.output}[/green]")
    elif args.output and batch_mode and per_domain_output_dir is None:
        # Combined aggregated subdomains to a single file
        with open(args.output, "w", encoding="utf-8") as f:
            for sub in sorted(aggregate_all_subdomains):
                f.write(sub + "\n")
        console.print(f"\n[green]Saved aggregated results to {args.output}[/green]")

    # JSON output (single vs batch)
    if args.json_output:
        if batch_mode:
            out_obj: Dict[str, Any] = {
                "tool": tool_name,
                "version": TOOL_VERSION,
                "domains": domains_data,
                "waf": waf_results_map,
                "aggregate": {
                    "total_unique_subdomains": len(aggregate_all_subdomains),
                }
            }
        else:
            d = target_domains[0]
            out_obj = {
                "tool": tool_name,
                "version": TOOL_VERSION,
                "domain": d,
                "passive": domains_data[d]["passive"],
                "active": domains_data[d]["active"],
                "resolved": domains_data[d]["resolved"],
                "tech": domains_data[d]["tech"],
                "waf": waf_result_single or {},
                "total_unique": domains_data[d]["total_unique"],
            }
        with open(args.json_output, "w", encoding="utf-8") as jf:
            json.dump(out_obj, jf, indent=2, sort_keys=True)
        console.print(f"[green]Saved JSON results to {args.json_output}[/green]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        logger.exception("Fatal error in main")
        sys.exit(1)
