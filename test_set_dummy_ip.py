#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests",
#     "python-dotenv",
#     "types-requests",
# ]
# ///
"""
Test script: Set DNS A records to dummy IP

Sets the first 3 configured DNS A records to 1.2.3.4 for testing purposes.
Reads credentials from .env file in the same directory.
"""

import os
import sys
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv  # type: ignore[import-not-found]  # no stubs available

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
DUMMY_IP = "1.2.3.4"


def get_auth_headers() -> dict[str, str] | None:
    """Build Cloudflare API authentication headers."""
    api_token = os.getenv("CLOUDFLARE_API_TOKEN", "").strip()
    if api_token:
        return {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
    return None


def get_dns_record(headers: dict[str, str], zone_id: str, record_name: str) -> dict[str, Any] | None:
    """Fetch DNS record details from Cloudflare."""
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records"
    params = {"type": "A", "name": record_name}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            return None

        results = data.get("result", [])
        if not results:
            return None

        result: dict[str, Any] = results[0]
        return result
    except requests.RequestException:
        return None


def update_dns_record(
    headers: dict[str, str], zone_id: str, record_id: str, record_name: str, new_ip: str
) -> bool:
    """Update a DNS record in Cloudflare."""
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records/{record_id}"
    payload = {
        "type": "A",
        "name": record_name,
        "content": new_ip,
        "ttl": 1,
        "proxied": False,
    }

    try:
        response = requests.put(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return bool(data.get("success", False))
    except requests.RequestException:
        return False


def main() -> int:
    """Set the first 3 DNS records to dummy IP."""
    # Load .env
    script_dir = Path(__file__).parent.resolve()
    env_file = script_dir / ".env"

    if not env_file.exists():
        print(f"ERROR: .env file not found at {env_file}")
        return 1

    load_dotenv(env_file)

    # Check auth
    headers = get_auth_headers()
    if not headers:
        print("ERROR: CLOUDFLARE_API_TOKEN not found in .env")
        return 1

    print(f"Setting first 3 DNS records to {DUMMY_IP}...\n")

    all_success = True
    for i in range(1, 4):
        zone_id = os.getenv(f"CLOUDFLARE_ZONE_ID{i}", "").strip()
        record_name = os.getenv(f"CLOUDFLARE_RECORD_NAME{i}", "").strip()

        if not zone_id or not record_name:
            print(f"SKIP: Record {i} - missing zone_id or record_name")
            continue

        # Get current record
        record = get_dns_record(headers, zone_id, record_name)
        if not record:
            print(f"FAIL: Record {i} ({record_name}) - could not fetch")
            all_success = False
            continue

        record_id = record.get("id")
        current_ip = record.get("content")

        if not record_id:
            print(f"FAIL: Record {i} ({record_name}) - no record ID")
            all_success = False
            continue

        # Update
        if update_dns_record(headers, zone_id, str(record_id), record_name, DUMMY_IP):
            print(f"OK:   Record {i} ({record_name}) - updated from {current_ip} to {DUMMY_IP}")
        else:
            print(f"FAIL: Record {i} ({record_name}) - update failed")
            all_success = False

    return 0 if all_success else 1


if __name__ == "__main__":
    sys.exit(main())
