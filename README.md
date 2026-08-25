# phishintel

![PhishIntel](https://github.com/Bednyakov/PhishIntel/blob/main/data/PhishIntel.png)

## Видеоинструкция проверки подозрительного сайта
[![PhishIntel на YouTube](https://img.youtube.com/vi/gJqeG9Og9_Q/0.jpg)](https://www.youtube.com/watch?v=gJqeG9Og9_Q)


[English version](README.en.md)

Автономный OSINT инструмент для анализа доменов и оценки фишингового риска с JSON-контрактом отчёта.

## Запуск

```bash
python3 scan.py example.com
```

или с доп флагами:
```
python3 scan.py example.com --no-progress
python3 scan.py example.com --output-dir ./reports
python3 scan.py example.com --stdout
python3 scan.py example.com --active-tool nmap --dynamic --search
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

- анализ домена;
- расширенные проверки DNS, IP и обратной DNS-записи;
- регистрационные данные RDAP и WHOIS;
- анализ HTTP, TLS и цепочки перенаправлений;
- анализ содержимого, форм и используемых технологий;
- анализ sitemap (`urlset` и `sitemapindex`);
- локальная история DNS и TLS;
- базовое обнаружение поддоменов;
- объяснимый контекстный скоринг фишингового риска;
- настраиваемая проверка репутации доменов, URL, IP, адресов отправки форм и внешних ресурсов;
- ограниченный статический анализ JavaScript и опциональное изолированное наблюдение в браузере;
- опциональный OSINT-анализ поисковой видимости, который не является самостоятельным вердиктом о риске.

Одно ключевое слово само по себе имеет уровень `informational`; уровень повышается только при наличии контекста формы, бренда или внешнего `action`.

Subdomain discovery использует два доступных источника: Certificate Transparency (`crt.sh`) и brute force по `wordlists/subdomains.txt`. Поля `passive_dns` и отдельный DNS-источник заложены в контракте, но требуют подключения внешнего passive-DNS API.

ASN, organization, country и city в IP-результате возвращаются как `null`, если не подключён внешний GeoIP/ASN provider.

Sitemap загружается с `https://<domain>/sitemap.xml`; поддерживаются `urlset` и `sitemapindex` с ограничениями 10 sitemap-файлов, 2 MB на файл и 10 000 URL. История сохраняется в JSONL-файл `data/history.jsonl`. Путь можно изменить переменной `PHISHINTEL_HISTORY_FILE`. В отчёте поле `history` содержит снимки DNS/TLS, а также изменения относительно предыдущего запуска. Битые строки истории игнорируются.

## CLI-параметры

- `domain` — домен или URL для проверки;
- `--timeout` — таймаут сетевых операций в секундах, по умолчанию `8.0`;
- `--compact` — вывести компактный JSON без отступов (по умолчанию отчёт форматированный);
- `--no-progress` — отключить индикатор прогресса;
- `--output-dir` — директория для JSON-отчётов, по умолчанию `reports`;
- `--stdout` — вывести JSON в stdout вместо сохранения в файл;
- `--active-tool` — явно запустить установленный активный сканер (`nmap`, `nuclei` или `zap`); параметр можно повторять. Без этого флага активное сканирование отключено.
- `--dynamic` — запустить изолированный браузерный анализ через Playwright, если установлен Playwright и Chromium/Chrome;
- `--search` — запросить поисковую видимость через настроенный Bing Web Search API; результат не влияет на оценку риска.

Лёгкие проверки дополнительно анализируют security headers и cookie-флаги, mixed content, чувствительные поля форм, HTTP/HTTPS для `action`, GET-формы, опасные ссылки на загрузки, `robots.txt` и `security.txt`. Это эвристики, а отсутствие CSRF-индикатора не является доказательством уязвимости.

Репутация настраивается переменными `PHISHINTEL_GOOGLE_SAFE_BROWSING_KEY` и `PHISHINTEL_VIRUSTOTAL_KEY`; ненастроенные источники не включаются в отчёт. Для поисковой видимости используется `PHISHINTEL_BING_KEY`; блок добавляется только при запуске с `--search` и настроенным ключом. Внешние URL очищаются от query-параметров перед репутационной проверкой, чтобы не отправлять потенциальные токены.

Пример запуска с переменными для одной команды:
```
PHISHINTEL_GOOGLE_SAFE_BROWSING_KEY="google-key" \
PHISHINTEL_VIRUSTOTAL_KEY="virustotal-key" \
PHISHINTEL_BING_KEY="bing-key" \
python3 scan.py example.com --search
```

на текущую сессию терминала:
```
export PHISHINTEL_VIRUSTOTAL_KEY="ваш_ключ"
export PHISHINTEL_GOOGLE_SAFE_BROWSING_KEY="ваш_ключ"
export PHISHINTEL_BING_KEY="ваш_ключ"
```
после этого:
```
python3 scan.py example.com --search
```

Статический анализ JavaScript загружает ограниченное число внешних скриптов, сохраняет только метаданные и SHA-256 и использует эвристики (`eval`, динамическая загрузка, cookie-доступ, сетевые отправки и обфускация). Эти признаки не являются доказательством malware. Динамический режим запускается только явно, без отправки форм и с запретом загрузок; используйте его только для разрешённых целей.

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
