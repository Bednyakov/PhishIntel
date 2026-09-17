# PhishIntel

```
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗████████╗███████╗██╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║╚══██╔══╝██╔════╝██║
██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║   ██║   █████╗  ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║   ██║   ██╔══╝  ██║
██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║   ██║   ███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
                 PHISHINTEL — OPEN-SOURCE INTELLIGENCE TOOL
```
[Русская версия](README.ru.md)

An authorized website and domain data collection tool. Its primary output is a
compact structured JSON report + HTML report.

## Quick start

Interactive mode:
```bash
python3 main.py
```

or

```bash
python3 main.py resource-parser https://example.com \
  --max-pages 500 --max-depth 3 --concurrency 8 --stdout
```

Without `--stdout`, the report is saved in `reports/`.

![Example HTML report](https://github.com/Bednyakov/PhishIntel/blob/main/data/rep_en1.jpg)
Example HTML report

## Main command: resource-parser

```text
python3 main.py resource-parser TARGET [OPTIONS]
```

`TARGET` is a domain name or URL.

| Option | Description | Default |
|---|---|---:|
| `--timeout` | network timeout | `8.0` seconds |
| `--max-pages` | maximum processed URLs | `500` |
| `--max-depth` | maximum crawl depth | `8` |
| `--concurrency` | simultaneous requests | `8` |
| `--no-progress` | disable terminal progress | off |
| `--stdout` | print JSON instead of saving a file | off |

Example:

```bash
python3 main.py resource-parser https://example.com \
  --max-depth 2 --max-pages 200 --concurrency 6 \
  --no-progress --stdout > report.json
```

The parser asynchronously crawls HTML pages on the target domain and its
subdomains. URLs from `sitemap.xml` and nested sitemap files are used as crawl
seeds, but sitemap data is not included in the final report.

## Report contents

- email addresses;
- phone numbers matching Russian and US formats;
- phone values from dedicated fields such as `tel`, `phone`, `telephone`, and
  `mobile`;
- addresses from dedicated fields and lines with explicit address hints;
- source pages only where contacts were found;
- external domains;
- external API endpoints;
- external JavaScript files;
- aggregated crawl counters;
- DNS, IP, and reverse DNS;
- RDAP and WHOIS;
- TLS certificate data;
- redirect chains;
- discovered subdomains;
- local DNS/TLS history.
- bounded TCP port scanning and technology detection for the original domain.

### Redirect chain analysis

The `domain.redirects` section opens the source URL and records every HTTP
transition until the final address. Each transition contains `from`, `to`, and
`status_code`; the report also includes the final URL (`final_url`) and the total
number of transitions (`count`). This helps identify suspicious external
redirects and intermediate domains.


Main JSON sections:

```json
{
  "tool": "resource-parser",
  "target": "https://example.com",
  "root_domain": "example.com",
  "summary": {},
  "contacts": {},
  "contact_sources": [],
  "external_resources": {
    "domains": [],
    "api_urls": [],
    "scripts": []
  },
  "domain": {
    "dns": {},
    "ip": {},
    "rdap": {},
    "whois": {},
    "tls": {},
    "redirects": {},
    "subdomains": {},
    "history": {}
  }
}
```

Individual service failures are represented inside their own section with
`status: unavailable`; there is no global `errors` field.

## Subdomains

Discovery uses Certificate Transparency (`crt.sh`) and DNS checks against names
from `wordlists/subdomains.txt`. Results are available in `domain.subdomains`
with per-source results, a merged list, and a count.

## Additional commands

```bash
python3 main.py email-check user@example.com --stdout
python3 main.py email-check user@example.com --smtp --stdout
python3 main.py email-search user@example.com --stdout
python3 main.py username-search username --stdout
```

`email-check` validates syntax, disposable domains, role accounts, DNS/MX, and
local rules. SMTP probing does not prove mailbox existence.

Command-specific options:

```bash
python3 main.py email-check --help
python3 main.py email-search --help
python3 main.py username-search --help
```

`domain-scan` remains technically available as a legacy command for the old
pipeline. It is not the primary workflow and may contain old risk/indicator
sections. Use `resource-parser` for the current data collection workflow.

`resource-parser` automatically starts the bundled Go scanner in parallel with
the page crawler. It scans only the original domain using a bounded TCP port
list; external domains discovered in pages are never scanned. Results are
available in the JSON `port_scan` section and the HTML report.

## Configuration

```bash
cp .env.example .env
```

```env
PHISHINTEL_TIMEOUT=8.0
PHISHINTEL_RESOURCE_MAX_PAGES=500
PHISHINTEL_RESOURCE_MAX_DEPTH=8
PHISHINTEL_RESOURCE_CONCURRENCY=8
PHISHINTEL_RESOURCE_USER_AGENTS=
PHISHINTEL_RESOURCE_PROXIES=
PHISHINTEL_HISTORY_FILE=data/history.jsonl
```

Explicit CLI options override `.env` values.

`PHISHINTEL_RESOURCE_USER_AGENTS` is a comma-separated User-Agent pool. When
empty, the built-in crawler User-Agent is used. `PHISHINTEL_RESOURCE_PROXIES`
accepts comma-separated HTTP/HTTPS proxy URLs; configured proxies are assigned
to requests in round-robin order. An empty value preserves the default direct
connection.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Only collect data from resources you are authorized to inspect.