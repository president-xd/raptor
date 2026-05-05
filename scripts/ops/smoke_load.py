#!/usr/bin/env python3
"""Small production smoke/load probe for a running RAPTOR backend.

This intentionally uses only the standard library. It checks health and then
performs concurrent authenticated status requests against the lightweight health
endpoint to validate ingress, auth, and rate limiting behavior.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def request(url: str, api_key: str, timeout: float) -> tuple[int, float]:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    req = urllib.request.Request(url, headers=headers)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response.read()
            return response.status, time.perf_counter() - started
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, time.perf_counter() - started


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/api/v1")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    url = args.base_url.rstrip("/") + "/health"
    results: list[tuple[int, float]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = [pool.submit(request, url, args.api_key, args.timeout) for _ in range(max(1, args.requests))]
        for future in as_completed(futures):
            results.append(future.result())

    statuses = {}
    latencies = []
    for status, latency in results:
        statuses[status] = statuses.get(status, 0) + 1
        latencies.append(latency)
    payload = {
        "url": url,
        "requests": len(results),
        "statuses": statuses,
        "latency_ms_p50": round(statistics.median(latencies) * 1000, 2),
        "latency_ms_max": round(max(latencies) * 1000, 2),
    }
    print(json.dumps(payload, sort_keys=True))
    return 0 if statuses.get(200, 0) == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
