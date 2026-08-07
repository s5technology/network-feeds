#!/usr/bin/env python3
"""
Fetch IOC feeds, normalize, dedupe, and write a combined IP + domain
blocklist to global.txt at the repo root.
"""
import re
import sys
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "sources.yml"
OUTPUT_FILE = ROOT / "global.txt"
MANUAL_FILE = ROOT / "manual_iocs.txt"

DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")

# Non-routable / reserved IP ranges to exclude from output
# (RFC1918 private space, loopback, link-local, multicast, etc.)
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
        # Strip brackets from bracketed IPv6 literals (e.g. "[2001:db8::1]"),
        # which some feeds use but ipaddress.ip_network() won't parse.
        line = line.replace("[", "").replace("]", "")
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


def load_manual_entries():
    """Read manual_iocs.txt (one IP/CIDR or domain per line, '#' comments
    and blank lines ignored). Returns (manual_ips, manual_domains)."""
    if not MANUAL_FILE.exists():
        return [], []
    manual_ips, manual_domains = [], []
    with open(MANUAL_FILE) as f:
        for raw_line in f:
            line = raw_line.split("#")[0].strip()
            if not line:
                continue
            if is_valid_ip_or_cidr(line):
                manual_ips.append(line)
            elif is_valid_domain(line):
                manual_domains.append(line)
            else:
                print(f"  ! skipping unrecognized manual entry: {line!r}", file=sys.stderr)
    return manual_ips, manual_domains


def collect_sources(sources, label):
    """Fetch each source and classify every entry as an IP/CIDR or a domain
    based on its content, not on which sources.yml section it came from.
    Some "domain" feeds list full URLs whose host may be a bare IP, so IPs
    are checked first and always classified as IPs."""
    seen_ips, seen_domains = set(), set()
    ip_entries, domain_entries = [], []
    for src in sources:
        print(f"Fetching {label} source: {src['name']} ({src['url']})")
        raw_lines = fetch(src["url"])
        added_ips = added_domains = 0
        for line in raw_lines:
            # Some feeds delimit with '#' (e.g. AlienVault reputation.data)
            # or commas; take the first field.
            token = line.split("#")[0].split(",")[0].split()[0].strip()
            # Extract the host from full URLs (e.g. URLhaus), which may
            # itself be a domain or a bare IP.
            if "://" in token:
                host = urlparse(token).hostname
                token = host if host else token
            if is_valid_ip_or_cidr(token):
                if token not in seen_ips:
                    seen_ips.add(token)
                    ip_entries.append(token)
                    added_ips += 1
            elif is_valid_domain(token):
                if token not in seen_domains:
                    seen_domains.add(token)
                    domain_entries.append(token)
                    added_domains += 1
        print(f"  -> {added_ips} new IPs, {added_domains} new domains")
    return ip_entries, domain_entries


def main():
    sources = load_sources()

    ip_from_ip_sources, domain_from_ip_sources = collect_sources(sources.get("ip_sources", []), "IP")
    ip_from_domain_sources, domain_from_domain_sources = collect_sources(sources.get("domain_sources", []), "domain")

    # Dedupe across both groups in case a feed under one section (e.g. IP
    # URLs in a "domain" feed) produces entries that belong in the other.
    ip_entries = list(dict.fromkeys(ip_from_ip_sources + ip_from_domain_sources))
    domain_entries = list(dict.fromkeys(domain_from_ip_sources + domain_from_domain_sources))

    reclassified = len(ip_from_domain_sources) + len(domain_from_ip_sources)
    if reclassified:
        print(
            f"Reclassified {len(ip_from_domain_sources)} IP(s) found in domain "
            f"sources and {len(domain_from_ip_sources)} domain(s) found in IP "
            f"sources."
        )

    before_count = len(ip_entries)
    ip_entries = [ip for ip in ip_entries if not is_non_routable(ip)]
    excluded_count = before_count - len(ip_entries)
    if excluded_count:
        print(f"Excluded {excluded_count} non-routable/reserved address entries")

    manual_ips, manual_domains = load_manual_entries()
    if manual_ips or manual_domains:
        print(f"Loaded {len(manual_ips)} manual IP entries and {len(manual_domains)} manual domain entries")
        # Manual entries are intentional and bypass the non-routable filter.
        ip_entries = list(set(ip_entries) | set(manual_ips))
        domain_entries = list(set(domain_entries) | set(manual_domains))

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
