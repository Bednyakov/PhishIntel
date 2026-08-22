"""Redirect chain analyzer."""

import urllib.error
import urllib.request

from .common import normalize_target, unavailable


class _Recorder(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        self.chain: list[dict] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"from": req.full_url, "to": newurl, "status_code": code})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def analyze(target: str, timeout: float = 8.0) -> dict:
    _, url = normalize_target(target)
    recorder = _Recorder()
    opener = urllib.request.build_opener(recorder)
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "phishintel/1.0"}), timeout=timeout) as response:
            return {"status": "ok", "chain": recorder.chain, "final_url": response.geturl(), "count": len(recorder.chain)}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {**unavailable(exc), "chain": recorder.chain}
