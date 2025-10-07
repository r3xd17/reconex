# 🔍 Reconex

**Advanced subdomain reconnaissance tool with comprehensive enumeration, validation, and analysis capabilities**

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

Reconex is a powerful subdomain reconnaissance tool that combines passive enumeration, active brute-forcing, DNS validation, and security analysis to provide comprehensive attack surface mapping.

## ✨ Features

### 🎯 Enumeration
- **Passive Intelligence**: Gather subdomains from 15+ sources (crt.sh, CertSpotter, Wayback Machine, urlscan, OTX, etc.)
- **Active Brute-forcing**: High-performance wordlist-based enumeration with configurable concurrency
- **Hybrid Mode**: Combine passive and active approaches for maximum coverage
- **Batch Processing**: Handle multiple root domains efficiently

### 🔍 Validation & Analysis
- **DNS Validation**: Filter results to only resolvable subdomains (A/AAAA records or CNAME chains)
- **WAF/CDN Detection**: Identify Cloudflare, Akamai, CloudFront, Fastly, Imperva, and more
- **Technology Stack Detection**: Fingerprint servers, frameworks, CMS, analytics, and DevOps platforms
- **Live Probes**: HTTP/HTTPS connectivity checks
- **Takeover Detection**: Identify vulnerable subdomains for potential takeover

### 💾 Output & Usability
- **Flexible Output**: Plain text, structured JSON, per-domain files in batch mode
- **Rich CLI Experience**: Color output, progress bars, and intuitive interface
- **Performance Optimized**: Configurable timeouts, delays, and concurrency controls

## 🚀 Quick Installation

```bash
git clone https://github.com/r3xd17/reconex.git
cd reconex
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
## 🧰 Command Reference
```bash
Flag                                  Description

-d,--domain                    DOMAIN	Target root domain
-dL,--domains-list             FILE	File of root domains (one per line)
-w,--wordlist                  FILE	Wordlist for active brute-force
--passive	                   Enable passive enumeration
--active	                   Enable active enumeration
--all	                       Passive + active
--resolve	                   Keep only DNS-valid hosts (A/AAAA or CNAME → A/AAAA)
--dns-resolver                 IPCustom DNS resolver (e.g., 1.1.1.1)
--tech-detect	               Technology fingerprinting
--waf-check	                   WAF/CDN detection on root domains
--takeover                     TARGET_OR_FILE	Subdomain takeover check (single or file)
--live                         FILE	Probe HTTP/HTTPS liveness from list
-o,--output                    PATH	Output file; with -dL, if PATH ends with “/” or is a directory, write per-domain files inside
-J,--json-output               FILE	Save structured JSON
--concurrency/--threads        N Concurrency (default 100)
--timeout                      SECONDS	Timeout per request (default 10)
--delay                        SECONDS	Delay between requests (default 0)
--mode                         light/aggressive	Presets (light lowers timeouts and concurrency)
--silent	                   Minimal console/UI
--no-verify	                   Disable TLS certificate verification
--name                         NAME	Override tool name in banner/User-Agent
```
## 📖 Usage Examples
```bash
# Single domain (defaults to passive if no mode flags)
python3 reconex.py -d example.com

# Passive + resolve (DNS-valid only), save JSON
python3 reconex.py -d example.com --passive --resolve -J results.json

# Active + passive with a wordlist
python3 reconex.py -d example.com --all -w words.txt --resolve

# Batch mode from a list of roots; save per-domain files
python3 reconex.py -dL domains.txt --passive --resolve -o out_dir/

# WAF/CDN detection
python3 reconex.py -d example.com --waf-check

# Tech stack detection
python3 reconex.py -d example.com --tech-detect

# Live check from a file of subdomains
python3 reconex.py --live subdomains.txt

# Subdomain takeover check
python3 reconex.py --takeover docs.example.com
python3 reconex.py --takeover subs.txt
```

## 🧪 Tips & Performance

- **Timeout Handling**: If sources throttle or you get timeouts, increase `--timeout` and add `--delay 0.2`
- **DNS Optimization**: Use `--dns-resolver 1.1.1.1` for faster DNS resolution in some environments
- **Concurrency Management**: For large wordlists, keep concurrency around 100–300; watch your resolver's rate limits
- **Batch Processing**: Use `-o out_dir/` (trailing slash) for per-domain files in batch mode

## 🐛 Troubleshooting

- **SSL Certificate Issues**: Try `--no-verify` (only if you understand the risks)
- **Low Results**: 
  - Increase `--timeout`
  - Add `--delay 0.2`
  - Use `--resolve` to keep DNS-valid hosts
  - Try a different DNS via `--dns-resolver`
- **Connectivity Issues**:
  - Run via a network with fewer egress restrictions
  - Adjust VPN/proxy settings

## 🔐 Responsible Use

- Only test assets you own or are explicitly authorized to assess
- Respect third-party data sources' terms of service and rate limits

## 🤝 Contributing

Contributions are welcome! Please:
- Follow existing code style conventions
- Add tests for new features
- Update documentation accordingly












