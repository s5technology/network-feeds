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

# RFC1918 private space plus other non-routable / reserved ranges
# to exclude from the IP list (loopback, link-local, multicast, etc.)
NON_ROUTABLE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # "this" network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918 private
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT (RFC6598)
    ipaddress.ip_network("127.0.0.0/8"),        # loopback
    ipaddress.ip_network("169.254.0.0/16"),     # link-local
    ipaddress.ip_network("172.16.0.0/12"),      # RFC1918 private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (documentation)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 relay anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC1918 private
    ipaddress.ip_network("198.18.0.0/15"),      # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (documentation)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (documentation)
    ipaddress.ip_network("224.0.0.0/4"),        # multicast
    ipaddress.ip_network("240.0.0.0/4"),        # reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # limited broadcast
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]


def is_non_routable(value: str) -> bool:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return any(net.overlaps(reserved) for reserved in NON_ROUTABLE_NETWORKS)


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

    before_count = len(ip_entries)
    ip_entries = [ip for ip in ip_entries if not is_non_routable(ip)]
    excluded_count = before_count - len(ip_entries)
    if excluded_count:
        print(f"Excluded {excluded_count} non-routable/reserved address entries")

    ip_entries = sorted(
        set(ip_entries),
        key=lambda x: (ipaddress.ip_network(x, strict=False).version, ipaddress.ip_network(x, strict=False))
    )
    domain_entries = sorted(set(domain_entries))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with open(OUTPUT_FILE, "w") as f:
        f.write(f"# Auto-generated {ts} — do not edit by hand\n")
        f.write("#\n")
        f.write("# ==============================\n")
        f.write("# IP Addresses / CIDR Ranges\n")
        f.write(f"# Count: {len(ip_entries)} (non-routable/reserved ranges excluded)\n")
        f.write("# ==============================\n")
        for entry in ip_entries:
            f.write(entry + "\n")
        f.write("#\n")
        f.write("# ==============================\n")
        f.write("# Domains\n")
        f.write(f"# Count: {len(domain_entries)}\n")
        f.write("# ==============================\n")
        for entry in domain_entries:
            f.write(entry + "\n")

    print(f"\nWrote {len(ip_entries) + len(domain_entries)} total entries to {OUTPUT_FILE}")
    print(f"  IPs: {len(ip_entries)} | Domains: {len(domain_entries)}")


if __name__ == "__main__":
    main()
