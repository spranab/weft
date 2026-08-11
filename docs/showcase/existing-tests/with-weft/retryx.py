"""Retry helpers."""


def retry(fn, attempts=3):
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last = exc
    raise last

def constant_backoff(attempt, delay=0.5):
    return delay

def expo_backoff(attempt, base=0.25, cap=8.0):
    return min(cap, base * (2 ** attempt))

