# phishintel

![PhishIntel](https://github.com/Bednyakov/PhishIntel/blob/main/data/PhishIntel.png)

[Русская версия](README.md)

An autonomous domain intelligence and phishing-risk analysis tool with a JSON report contract.

## Usage

```bash
python3 scan.py example.com
python3 scan.py example.com --no-progress
python3 scan.py example.com --output-dir ./reports
python3 scan.py example.com --stdout
python3 -m unittest discover -s tests -v
```

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
- explainable, context-aware phishing-risk scoring.

A keyword alone receives an `informational` severity. The severity increases only when additional form, brand, or external `action` context is present.

Subdomain discovery uses two available sources: Certificate Transparency (`crt.sh`) and brute force against `wordlists/subdomains.txt`. The `passive_dns` field and a separate DNS source are part of the report contract, but require an external passive-DNS API.

ASN, organization, country, and city in the IP result are returned as `null` when no external GeoIP/ASN provider is configured.

Sitemaps are loaded from `https://<domain>/sitemap.xml`. The analyzer supports `urlset` and `sitemapindex`, with limits of 10 sitemap files, 2 MB per file, and 10,000 URLs. History is stored in the JSONL file `data/history.jsonl`. Change the path with the `PHISHINTEL_HISTORY_FILE` environment variable. The report's `history` field contains DNS/TLS snapshots and changes compared with the previous run. Invalid history lines are ignored.

## CLI options

- `domain` — domain name or URL to analyze;
- `--timeout` — network-operation timeout in seconds, defaulting to `8.0`;
- `--compact` — print compact JSON without indentation (reports are pretty-printed by default);
- `--no-progress` — disable the progress bar;
- `--output-dir` — directory for JSON reports, defaulting to `reports`;
- `--stdout` — print JSON to stdout instead of saving it to a file.

Reports are pretty-printed and structured by default. To reduce the output size, use the inverse `--compact` option, for example:

```bash
python3 scan.py example.com --stdout --compact --no-progress > report.json
```

The files `wordlists/brands.txt` and `wordlists/phishing_keywords.txt` are used to detect brand mentions and phishing-related phrases in page content. The file `wordlists/subdomains.txt` is used to probe common subdomains through DNS. The lists can be extended one entry per line; blank lines and lines starting with `#` are ignored.

The report filename is generated from the domain and the UTC start time, for example `reports/example.com_2026-08-22T14-30-15Z.json`.

For automation, explicitly print JSON to stdout:

```bash
python3 scan.py example.com --stdout --no-progress > report.json
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