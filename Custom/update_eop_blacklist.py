#!/usr/bin/env python3
import pathlib
import re
import uuid
import requests

def main():
    # 1) Fetch Microsoft 365 Exchange/EOP IPv4 ranges
    guid = str(uuid.uuid4())
    url = (
        "https://endpoints.office.com/endpoints/worldwide"
        f"?ServiceAreas=Exchange&NoIPv6=true&ClientRequestId={guid}"
    )
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    cidrs = set()
    for entry in data:
        for ip in entry.get("ips", []):
            if re.match(r"^\d+\.\d+\.\d+\.\d+/", ip):
                cidrs.add(ip)

    # 2) Path to your Evilginx blacklist file (relative to script)
    path = pathlib.Path(__file__).resolve().parent / "blacklist.txt"

    # 3) Merge with existing entries so you keep manual ranges
    existing = set()
    if path.exists():
        existing = {
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        }

    all_cidrs = existing | cidrs

    # 4) Write back merged list
    path.write_text("\n".join(sorted(all_cidrs)) + "\n")

if __name__ == "__main__":
    main()
