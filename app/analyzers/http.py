"""HTTP metadata analyzer."""

import ssl
import urllib.error
import urllib.request

from .common import normalize_target, unavailable


def analyze(target: str, timeout: float = 8.0) -> dict:
    host, url = normalize_target(target)
    request = urllib.request.Request(url, headers={"User-Agent": "phishintel/1.0"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            body = response.read(256_000)
            headers = {key.lower(): value for key, value in response.headers.items()}
            return {"status": "ok", "url": response.geturl(), "host": host, "status_code": response.status, "headers": headers, "content_type": headers.get("content-type"), "body_size": len(body), "_body": body}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return unavailable(exc)
