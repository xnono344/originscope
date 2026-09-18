#!/usr/bin/env python3
"""Refresh local, public provider data without sending observed client IPs."""
import datetime as dt
import gzip
import ipaddress
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "OriginScope/0.1 (+local metadata tool)"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(30 * 1024 * 1024 + 1)
    if len(raw) > 30 * 1024 * 1024:
        raise ValueError(f"Download too large: {url}")
    return raw


def save(dest, data):
    temp = dest.with_suffix(dest.suffix + ".tmp")
    temp.write_bytes(data)
    temp.replace(dest)
    print(f"Updated {dest.relative_to(ROOT)} ({len(data):,} bytes)")


def lines(raw, cidr=False):
    values = [line.strip() for line in raw.decode().splitlines() if line.strip() and not line.startswith("#")]
    for value in values:
        (ipaddress.ip_network if cidr else ipaddress.ip_address)(value)
    if not values:
        raise ValueError("Empty address list")
    return ("\n".join(values) + "\n").encode()


def main():
    cf4 = fetch("https://www.cloudflare.com/ips-v4")
    cf6 = fetch("https://www.cloudflare.com/ips-v6")
    save(DATA / "cloudflare-ranges.txt", lines(cf4 + b"\n" + cf6, cidr=True))
    save(DATA / "tor-exits.txt", lines(fetch("https://check.torproject.org/torbulkexitlist")))
    month = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m")
    for kind in ("asn", "country"):
        url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
        save(DATA / f"dbip-{kind}-lite.mmdb", gzip.decompress(fetch(url)))
    print("DB-IP Lite: CC BY 4.0; attribution appears in the UI and README.")


if __name__ == "__main__":
    main()
