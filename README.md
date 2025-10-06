
Reconex
Advanced subdomain reconnaissance tool with passive/active enumeration, DNS validation, WAF/CDN fingerprinting, tech stack detection, live probes, and subdomain takeover checks. 



✨ Features
Passive enum from many sources: crt.sh, CertSpotter, BufferOver, Omnisint, RapidDNS, ThreatCrowd, ThreatMiner, Sublist3r API, Wayback, urlscan, OTX, SiteDossier (+ optional VirusTotal UI, c99.nl)
Active brute-force enum with concurrency
DNS validation: keep only A/AAAA or CNAME→A/AAAA
WAF/CDN detection: Cloudflare, Akamai, CloudFront, Fastly, Imperva, Sucuri, Azure Front Door, Google Cloud CDN
Technology heuristics: servers, frameworks, CMS, analytics, DevOps platforms
Live probe (HTTP/HTTPS) and subdomain takeover checks
Batch mode (-dL) for multiple root domains; per-domain or aggregated outputs
Rich CLI UX: color output, progress bars, JSON export
📦 Install
Bash

git clone https://github.com/r3xd17/reconex.git
cd reconex
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
🚀 Quick start
Single domain (defaults to passive if no mode flags):
Bash

python3 reconex.py -d example.com
Passive + resolve (DNS-valid only), save JSON:
Bash

python3 reconex.py -d example.com --passive --resolve -J results.json
Active + passive with a wordlist:
Bash

python3 reconex.py -d example.com --all -w words.txt --resolve
Batch mode from a list of roots; save per-domain files into a directory:
Bash

python3 reconex.py -dL domains.txt --passive --resolve -o out_dir/
WAF/CDN detection:
Bash

python3 reconex.py -d example.com --waf-check
Tech stack detection (on subdomains if enumerated, on roots only if no enumeration flags):
Bash

python3 reconex.py -d example.com --tech-detect
Live check (HTTP/HTTPS) from a file of subdomains:
Bash

python3 reconex.py --live subdomains.txt
Subdomain takeover check for a single domain or a list file:
Bash

python3 reconex.py --takeover docs.example.com
python3 reconex.py --takeover subs.txt
🧰 Command reference
Flag	Description
-d, --domain DOMAIN	Target root domain
-dL, --domains-list FILE	File of root domains (one per line)
-w, --wordlist FILE	Wordlist for active brute-force
--passive	Enable passive enumeration
--active	Enable active enumeration
--all	Passive + active
--experimental-sources	Include VT UI and c99.nl scrapers
--resolve	Keep only DNS-valid hosts (A/AAAA or CNAME→A/AAAA)
--dns-resolver IP	Custom DNS resolver (e.g., 1.1.1.1)
--tech-detect	Technology fingerprinting
--waf-check	WAF/CDN detection on root domains
--takeover TARGET_OR_FILE	Subdomain takeover check (single or file)
--live FILE	Probe HTTP/HTTPS liveness from list
-o, --output PATH	Output file; with -dL, if PATH ends with “/” or is a directory, write per-domain files inside
-J, --json-output FILE	Save structured JSON
--concurrency/--threads N	Concurrency (default 100)
--timeout SECONDS	Timeout per request (default 10)
--delay SECONDS	Delay between requests (default 0)
--mode light/aggressive	Presets (light lowers timeouts and concurrency)
--silent	Minimal console/UI
--no-verify	Disable TLS certificate verification
--name NAME	Override tool name in banner/User-Agent
📄 Output examples
Plain text: one subdomain per line
JSON: structured output. Example (single domain):
JSON

{
  "tool": "Reconex",
  "version": "1.1",
  "domain": "example.com",
  "passive": ["a.example.com", "b.example.com"],
  "active": ["c.example.com"],
  "resolved": {
    "a.example.com": {"A": ["93.184.216.34"], "AAAA": [], "CNAME": []}
  },
  "tech": {
    "a.example.com": ["Nginx", "Cloudflare CDN", "WordPress"]
  },
  "waf": {
    "host": "example.com",
    "provider": "Cloudflare",
    "confidence": "high",
    "detected_providers": ["Cloudflare"]
  },
  "total_unique": 3
}
Batch JSON (domains.txt): domains object per root plus aggregate counts.
🧪 Tips & performance
If sources throttle or you get timeouts: increase --timeout and add --delay 0.2
Use --dns-resolver 1.1.1.1 for faster DNS in some environments
For large wordlists, keep concurrency around 100–300; watch your resolver’s rate limits
Batch mode + per-domain files: pass -o out_dir/ (trailing slash)
🔐 Responsible use
Use only against assets you own or are authorized to test
Respect third-party data sources’ ToS and rate limits
🐛 Troubleshooting
SSL certificate issues: try --no-verify (only if you understand the risks)
Low results: increase --timeout, add --delay 0.2, use --resolve, or try another DNS via --dns-resolver

🤝 Contributing
PRs welcome! Please:

📜 License
MIT — see LICENSE.

Example banner:

╔══════════════════════════════════╗
║    ╭─[ Reconex ]────────────────╮║
║    │  Subdomain Intel  │  v1.1  ║
║    │  by R3XD17 ╰────────────────╯║
╚══════════════════════════════════╝
