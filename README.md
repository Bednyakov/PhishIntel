# phishintel

![PhishIntel](https://github.com/Bednyakov/PhishIntel/blob/main/data/PhishIntel.png)

![Видеоинструкция проверки подозрительного сайта](https://www.youtube.com/watch?v=gJqeG9Og9_Q)


[English version](README.en.md)

Автономный OSINT инструмент для анализа доменов и оценки фишингового риска с JSON-контрактом отчёта.

## Запуск

```bash
python3 scan.py example.com
python3 scan.py example.com --no-progress
python3 scan.py example.com --output-dir ./reports
python3 scan.py example.com --stdout
python3 -m unittest discover -s tests -v
```

Сетевые проверки не являются обязательными: ошибки DNS/HTTP/TLS возвращаются в соответствующем разделе как `status: unavailable`, поэтому один недоступный сервис не останавливает полный отчёт.

Во время проверки CLI показывает progress bar в stderr: количество завершённых этапов относительно общего количества. По умолчанию JSON-отчёт сохраняется в директории `reports/`, а в консоль выводится только сообщение о завершении и путь к файлу. Для отключения progress bar используйте `--no-progress`.

## Возможности

```
        ╭──────╮
        │  🌐  │
        │ .com │
        ╰──────╯
             ╲
              ╲
```

- domain-анализ;
- расширенный DNS и IP/reverse DNS;
- RDAP и WHOIS registration;
- HTTP, TLS и redirects;
- анализ содержимого, форм и технологий;
- sitemap (`urlset` и `sitemapindex`);
- локальная история DNS/TLS;
- базовый subdomain discovery;
- explainable context-aware scoring.

Одно ключевое слово само по себе имеет уровень `informational`; уровень повышается только при наличии контекста формы, бренда или внешнего `action`.

Subdomain discovery использует два доступных источника: Certificate Transparency (`crt.sh`) и brute force по `wordlists/subdomains.txt`. Поля `passive_dns` и отдельный DNS-источник заложены в контракте, но требуют подключения внешнего passive-DNS API.

ASN, organization, country и city в IP-результате возвращаются как `null`, если не подключён внешний GeoIP/ASN provider.

Sitemap загружается с `https://<domain>/sitemap.xml`; поддерживаются `urlset` и `sitemapindex` с ограничениями 10 sitemap-файлов, 2 MB на файл и 10 000 URL. История сохраняется в JSONL-файл `data/history.jsonl`. Путь можно изменить переменной `PHISHINTEL_HISTORY_FILE`. В отчёте поле `history` содержит снимки DNS/TLS, а также изменения относительно предыдущего запуска. Битые строки истории игнорируются.

## CLI-параметры

- `domain` — домен или URL для проверки;
- `--timeout` — таймаут сетевых операций в секундах, по умолчанию `8.0`;
- `--compact` — вывести компактный JSON без отступов (по умолчанию отчёт форматированный);
- `--no-progress` — отключить progress bar.
- `--output-dir` — директория для JSON-отчётов, по умолчанию `reports`;
- `--stdout` — вывести JSON в stdout вместо сохранения в файл.
- `--active-tool` — явно запустить установленный активный сканер (`nmap`, `nuclei` или `zap`); параметр можно повторять. Без этого флага активное сканирование отключено.

Лёгкие проверки дополнительно анализируют security headers и cookie-флаги, mixed content, чувствительные поля форм, HTTP/HTTPS для `action`, GET-формы, опасные ссылки на загрузки, `robots.txt` и `security.txt`. Это эвристики, а отсутствие CSRF-индикатора не является доказательством уязвимости.

Активные сканеры запускаются только по явному `--active-tool`. Nmap и Nuclei должны быть заранее установлены в `PATH`; ZAP в текущей версии возвращает инструкцию по настройке API и не запускается автоматически. Запускайте такие проверки только для систем, на которые у вас есть разрешение.

```bash
python3 scan.py example.com --active-tool nmap
python3 scan.py example.com --active-tool nuclei
python3 scan.py example.com --active-tool nmap --active-tool nuclei
```

Отчёты по умолчанию сохраняются в структурированном, форматированном JSON. Для уменьшения размера вывода можно использовать обратный флаг `--compact`, например:

```bash
python3 scan.py example.com --stdout --compact --no-progress > report.json
```

Файлы `wordlists/brands.txt` и `wordlists/phishing_keywords.txt` используются для поиска упоминаний брендов и фишинговых фраз в содержимом страниц. Файл `wordlists/subdomains.txt` используется для DNS-проверки распространённых subdomains. Списки можно расширять построчно; пустые строки и строки, начинающиеся с `#`, игнорируются.

Имя файла формируется из домена и UTC-времени запуска, например `reports/example.com_2026-08-22T14-30-15Z.json`.

Для автоматизации можно явно вывести JSON в stdout:

```bash
python3 scan.py example.com --stdout --no-progress > report.json
```
