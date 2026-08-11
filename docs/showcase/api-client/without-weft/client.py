"""Tiny HTTP client helpers."""

BASE = "https://api.example.com"


def build_url(path):
    return BASE.rstrip("/") + "/" + path.lstrip("/")

def join_headers(**kw):
    return {k.replace("_", "-").title(): str(v) for k, v in kw.items()}

def with_query(url, **params):
    if not params:
        return url
    q = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return f"{url}?{q}"

def retry(fn, attempts=3):
    for i in range(attempts):
        try:
            return fn()
        except Exception:
            continue
    raise RuntimeError("giving up after {} attempts".format(attempts)

