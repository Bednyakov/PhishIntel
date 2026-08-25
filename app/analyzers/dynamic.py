"""Optional isolated browser observation using Playwright."""

import shutil


def analyze(url: str, timeout: float = 15.0) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"status": "not_configured", "error": "Playwright is not installed"}
    if not url:
        return {"status": "unavailable", "error": "No URL available"}
    try:
        with sync_playwright() as playwright:
            browser_type = playwright.chromium
            executable = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
            launch_options = {"headless": True}
            if executable:
                launch_options["executable_path"] = executable
            browser = browser_type.launch(**launch_options)
            context = browser.new_context(accept_downloads=False, java_script_enabled=True)
            page = context.new_page()
            requests, responses, redirects, downloads = [], [], [], []
            page.on("request", lambda request: requests.append({"url": request.url, "method": request.method}))
            page.on("response", lambda response: responses.append({"url": response.url, "status": response.status}))
            page.on("request", lambda request: redirects.append({"url": request.url}) if request.is_navigation_request() and request.redirected_from else None)
            page.on("download", lambda download: downloads.append({"url": download.url, "suggested_filename": download.suggested_filename}))
            response = page.goto(url, wait_until="domcontentloaded", timeout=max(1000, int(timeout * 1000)))
            result = {"status": "ok", "final_url": page.url, "status_code": response.status if response else None, "title": page.title(), "requests_count": len(requests), "external_domains": sorted({item["url"].split('/')[2] for item in requests if "://" in item["url"]}), "redirects": redirects, "downloads": downloads}
            context.close()
            browser.close()
            return result
    except Exception as exc:
        return {"status": "unavailable", "error": str(exc)}