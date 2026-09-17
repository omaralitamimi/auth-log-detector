"""Detect repeated authentication failures in synthetic JSONL logs."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def detect(events: list[dict], threshold: int = 5, window_minutes: int = 10) -> list[dict]:
    windows: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    alerts: list[dict] = []
    window = timedelta(minutes=window_minutes)
    for event in sorted(events, key=lambda item: parse_time(item["timestamp"])):
        if event.get("result") != "failure":
            continue
        key = (event.get("username", "unknown"), event.get("source_ip", "unknown"))
        current = parse_time(event["timestamp"])
        bucket = windows[key]
        while bucket and current - bucket[0] > window:
            bucket.popleft()
        bucket.append(current)
        if len(bucket) == threshold:
            alerts.append({"username": key[0], "source_ip": key[1], "failures": len(bucket), "window_minutes": window_minutes, "last_seen": event["timestamp"]})
    return alerts


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=10)
    args = parser.parse_args()
    print(json.dumps(detect(load_jsonl(args.log), args.threshold, args.window), indent=2))


if __name__ == "__main__":
    main()
