#!/usr/bin/env python3
"""
Fetch IOC feeds, normalize, dedupe, and write a single combined
IP + domain blocklist to global.txt at the repo root.
"""
import re
import sys
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "sources.yml"
OUTPUT_FILE = ROOT / "global.txt"

DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def fetch(url: str, timeout: int = 30) -> list[str]:
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "ioc-pipeline/1.0"})
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"  ! failed to fetch {url}: {e}", file=sys.stderr)
        return []
    lines = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        lines.append(line)
    return lines


def is_valid_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(value))


def load_sources():
    with open(SOURCES_FILE) as f:
        return yaml.safe_load(f)


def build_list(sources, validator, label):
    seen = set()
    ordered = []
    for src in sources:
        print(f"Fetching {label} source: {src['name']} ({src['url']})")
        raw_lines = fetch(src["url"])
        added = 0
        for line in raw_lines:
            token = line.split(",")[0].split()[0].strip()
            if not validator(token):
                continue
            if token not in seen:
                seen.add(token)
                ordered.append(token)
                added += 1
        print(f"  -> {added} new entries")
    return ordered


def main():
    sources = load_sources()

    ip_entries = build_list(sources.get("ip_sources", []), is_valid_ip_or_cidr, "IP")
    domain_entries = build_list(sources.get("domain_sources", []), is_valid_domain, "domain")

    # Combine into a single sorted, deduped list for global.txt
    combined = sorted(set(ip_entries) | set(domain_entries))

    with open(OUTPUT_FILE, "w") as f:
        for entry in combined:
            f.write(entry + "\n")

    print(f"\nWrote {len(combined)} total entries to {OUTPUT_FILE}")
    print(f"  IPs: {len(ip_entries)} | Domains: {len(domain_entries)}")


if __name__ == "__main__":
    main()
