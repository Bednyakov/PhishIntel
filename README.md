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
[English version](README.en.md)

Инструмент для авторизованного сбора публичных данных с сайта и домена.
Основной результат — компактный структурированный JSON-отчёт.

## Быстрый старт

```bash
python3 main.py
```

или

```bash
python3 main.py resource-parser https://example.com \
  --max-pages 500 --max-depth 3 --concurrency 8 --stdout
```

Без `--stdout` отчёт сохраняется в `reports/`. Интерактивный режим:

## Основная команда: resource-parser

```text
python3 main.py resource-parser TARGET [OPTIONS]
```

`TARGET` — домен или URL ресурса.

| Параметр | Назначение | По умолчанию |
|---|---|---:|
| `--timeout` | таймаут сетевого запроса | `8.0` секунд |
| `--max-pages` | максимум обработанных URL | `500` |
| `--max-depth` | максимальная глубина обхода | `8` |
| `--concurrency` | число одновременных запросов | `8` |
| `--no-progress` | отключить прогресс в терминале | выключен |
| `--stdout` | вывести JSON вместо файла | выключен |

Пример:

```bash
python3 main.py resource-parser https://example.com \
  --max-depth 2 --max-pages 200 --concurrency 6 \
  --no-progress --stdout > report.json
```

Парсер асинхронно обходит HTML-страницы исходного домена и его поддоменов.
URL из `sitemap.xml` и вложенных sitemap используются как источники страниц,
но данные sitemap не включаются в итоговый отчёт.

## Что попадает в отчёт

- email-адреса;
- телефоны по российским и американским форматам;
- телефоны из HTML-полей `tel`, `phone`, `telephone`, `mobile` и аналогов;
- адреса из специализированных полей и строк с явными адресными признаками;
- источники только тех страниц, где найдены контакты;
- внешние домены;
- внешние API endpoint-ы;
- внешние JavaScript-файлы;
- агрегированные счётчики обхода;
- DNS, IP и reverse DNS;
- RDAP и WHOIS;
- TLS-сертификат;
- цепочка перенаправлений;
- найденные поддомены;
- локальная история DNS/TLS.
- ограниченное сканирование TCP-портов исходного домена и определение технологий.

### Анализ цепочки перенаправлений

Раздел `domain.redirects` открывает исходный URL и записывает все HTTP-переходы
до конечного адреса. Для каждого перехода сохраняются `from`, `to` и
`status_code`; также в отчёт добавляются конечный URL (`final_url`) и общее
количество переходов (`count`). Это помогает выявлять подозрительные внешние
переходы и промежуточные домены.


Основные разделы JSON:

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

Ошибки отдельных сервисов отражаются внутри соответствующего раздела через
`status: unavailable`; отдельного поля `errors` нет.

## Поддомены

Используются Certificate Transparency (`crt.sh`) и DNS-проверка имён из
`wordlists/subdomains.txt`. Результат доступен в `domain.subdomains` и содержит
источники, объединённый список и количество найденных поддоменов.

## Дополнительные команды

```bash
python3 main.py email-check user@example.com --stdout
python3 main.py email-check user@example.com --smtp --stdout
python3 main.py email-search user@example.com --stdout
python3 main.py username-search username --stdout
```

`email-check` проверяет синтаксис, disposable-домен, role-адрес, DNS/MX и
локальные правила. SMTP-проверка не доказывает существование ящика.

Параметры:

```bash
python3 main.py email-check --help
python3 main.py email-search --help
python3 main.py username-search --help
```

`domain-scan` остаётся технически доступной legacy-командой старого pipeline.
Она не является основным сценарием и может содержать старые risk/indicator-
разделы. Для актуального сбора данных используйте `resource-parser`.

При запуске `resource-parser` автоматически и параллельно с обходом страниц
запускается встроенный Go-сканер ограниченного списка TCP-портов. Результат
доступен в разделе `port_scan` JSON-отчёта и в HTML-отчёте. Сканируется только
исходный домен; внешние домены, найденные на страницах, не передаются сканеру.

## Конфигурация

```bash
cp .env.example .env
```

```env
PHISHINTEL_TIMEOUT=8.0
PHISHINTEL_RESOURCE_MAX_PAGES=500
PHISHINTEL_RESOURCE_MAX_DEPTH=8
PHISHINTEL_RESOURCE_CONCURRENCY=8
PHISHINTEL_HISTORY_FILE=data/history.jsonl
```

Явные параметры CLI имеют приоритет над `.env`.

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

Запускайте сбор только для ресурсов, на проверку которых у вас есть разрешение.