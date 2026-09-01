```
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗████████╗███████╗██╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║╚══██╔══╝██╔════╝██║
██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║   ██║   █████╗  ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║   ██║   ██╔══╝  ██║
██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║   ██║   ███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
                 PHISHINTEL — OPEN-SOURCE INTELLIGENCE TOOL
```

[Русская версия](README.md)

An autonomous domain intelligence and phishing-risk analysis tool with a JSON report contract.

## Usage

```bash
python3 main.py
python3 main.py domain-scan example.com --profile quick
python3 main.py domain-scan example.com --profile full --stdout
python3 main.py domain-scan example.com --profile security --active-tool nmap
python3 main.py resource-parser https://example.com --stdout
python3 -m unittest discover -s tests -v
```

Running `python3 main.py` opens the interactive tool menu. The domain tool supports three analysis profiles:

- `quick` — basic network checks without JavaScript, search visibility, or active scanners;
- `full` — complete analysis with JavaScript, dynamic browser analysis, and search visibility;
- `security` — extended audit with JavaScript, dynamic analysis, and all active scanners in thorough mode.

Network checks are optional: DNS, HTTP, and TLS errors are returned in the corresponding report sections as `status: unavailable`, so an unavailable service does not stop the complete report.

While the scan is running, the CLI displays a progress bar in `stderr`, showing completed stages relative to the total number of stages. By default, the JSON report is saved to the `reports/` directory, and the console only displays a completion message and the saved file path. Use `--no-progress` to disable the progress bar.

## Features

```
        ╭──────╮
        │  🌐  │
        │ .com │
        ╰──────╯
             ╲
              ╲
```

- domain analysis;
- extended DNS and IP/reverse DNS checks;
- RDAP and WHOIS registration data;
- HTTP, TLS, and redirect analysis;
- content, form, and technology analysis;
- sitemap analysis for `urlset` and `sitemapindex`;
- local DNS/TLS history;
- basic subdomain discovery;
- explainable, context-aware phishing-risk scoring;
- configurable reputation checks for domains, URLs, IP addresses, form actions, and external resources;
- bounded static JavaScript analysis and optional isolated browser observation;
- optional search-visibility OSINT, which is not a standalone risk verdict.
- recursive resource parsing for publicly exposed contact data.

### Resource parser

```bash
python3 main.py resource-parser https://example.com --stdout
```

The parser recursively visits HTML pages of the resource and discovered subdomains, collecting emails, phone numbers, cryptocurrency wallets, and strings that look like physical addresses. Each value is associated with its source page. The default limits are 500 pages and depth 8; use `--max-pages` and `--max-depth` to change them.

For safety, crawling is limited to the original domain and its subdomains; external domains are not visited and binary files are skipped.

Subdomain discovery uses two available sources: Certificate Transparency (`crt.sh`) and brute force against `wordlists/subdomains.txt`. The `passive_dns` field and a separate DNS source are part of the report contract, but require an external passive-DNS API.

ASN, organization, country, and city in the IP result are returned as `null` when no external GeoIP/ASN provider is configured.

Sitemaps are loaded from `https://<domain>/sitemap.xml`. The analyzer supports `urlset` and `sitemapindex`, with limits of 10 sitemap files, 2 MB per file, and 10,000 URLs. History is stored in the JSONL file `data/history.jsonl`. Change the path with the `PHISHINTEL_HISTORY_FILE` environment variable. The report's `history` field contains DNS/TLS snapshots and changes compared with the previous run. Invalid history lines are ignored.

## Domain tool options

- `domain-scan` — domain analysis tool;
- `resource-parser` — recursive resource contact-data collection;
- `target` — domain name or URL to analyze;
- `--profile` — analysis profile: `quick`, `full`, or `security`;
- `--timeout` — network-operation timeout in seconds, defaulting to `8.0`;
- `--no-progress` — disable the progress bar;
- `--stdout` — print JSON to stdout instead of saving it to a file;
- `--active-tool` — limit active scanning to selected scanners (`nmap`, `nuclei`, or `zap`); repeat the option for multiple tools. In the `security` profile, omitting this option runs all supported scanners. Thorough Nmap uses a bounded discovery pass followed by service/version, NSE, and OS detection; its separate Nmap budget is at least 300 seconds so the audit is not cut short by the ordinary network timeout. Nuclei runs all available templates at low–critical severity without the quick-scan rate limit. Nmap exploit and brute-force script categories are intentionally excluded. Missing or unconfigured scanners are reported in `active_scan.tools` and do not stop the report.

Lightweight checks additionally inspect security headers and cookie flags, mixed content, sensitive form fields, HTTP/HTTPS form actions, GET forms, dangerous download links, `robots.txt`, and `security.txt`. These are heuristics; a missing CSRF indicator is not proof of a vulnerability.

All application settings are configured in `.env`. Copy `.env.example` to `.env` and fill in the required values. The file contains API keys, timeouts, resource-parser limits, domain profile, active scanners, username options, JSON/progress/color output settings, and the history path. Unconfigured providers are omitted from reports. Explicit CLI arguments take precedence over `.env`.

```bash
cp .env.example .env
python3 main.py resource-parser https://example.com
```

Static JavaScript analysis downloads a bounded number of external scripts, stores metadata and SHA-256 hashes, and checks heuristics such as `eval`, dynamic loading, cookie access, network submissions, and obfuscation. These signals are not proof of malware. Dynamic analysis is enabled only explicitly, does not submit forms, and disables downloads; use it only against systems you are authorized to test.

In the `security` profile, active scanners run automatically; use `--active-tool` to limit the set. In thorough mode, Nmap scans all TCP ports, detects services and the operating system, and runs default plus safe `vuln` NSE checks; Nuclei runs all available low–critical templates. ZAP requires a preconfigured daemon/API and reports configuration guidance when unavailable. Nmap exploit and brute-force script categories are intentionally excluded. Run active checks only against systems you are authorized to test.

```bash
python3 main.py domain-scan example.com --profile security --active-tool nmap
python3 main.py domain-scan example.com --profile security --active-tool nuclei
python3 main.py domain-scan example.com --profile security --active-tool nmap --active-tool nuclei
```

Reports are pretty-printed and structured by default. For automation, print JSON to stdout, for example:

```bash
python3 main.py domain-scan example.com --stdout --no-progress > report.json
```

The files `wordlists/brands.txt` and `wordlists/phishing_keywords.txt` are used to detect brand mentions and phishing-related phrases in page content. The file `wordlists/subdomains.txt` is used to probe common subdomains through DNS. The lists can be extended one entry per line; blank lines and lines starting with `#` are ignored.

The report filename is generated from the domain and the UTC start time, for example `reports/example.com_2026-08-22T14-30-15Z.json`.

For automation, explicitly print JSON to stdout:

```bash
python3 main.py domain-scan example.com --stdout --no-progress > report.json
```

## Progress stages

The progress bar tracks these stages:

1. domain
2. DNS
3. IP/reverse DNS
4. RDAP
5. TLS
6. HTTP
7. redirects
8. content
9. WHOIS
10. sitemap
11. subdomains
12. history
13. scoring