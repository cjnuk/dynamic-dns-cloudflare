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
Cloudflare Dynamic DNS Updater

Updates multiple DNS A records in Cloudflare with your current public IP address.
Designed to run as a systemd service or timer.

Features local IP caching to minimize Cloudflare API calls.

Environment Variables:
    Authentication (one method required):
        CLOUDFLARE_API_TOKEN: Scoped API token (recommended)
        OR
        CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY: Global API key (legacy)

    Records:
        CLOUDFLARE_ZONE_ID1-5: Zone ID for each record (paired with RECORD_NAME)
        CLOUDFLARE_RECORD_NAME1-5: DNS record names to update (paired with ZONE_ID)

    Caching:
        DDNS_VERIFY_INTERVAL_MINUTES: How often to verify with Cloudflare API
                                      when IP is unchanged (default: 60)

    Each record requires BOTH CLOUDFLARE_ZONE_ID{N} and CLOUDFLARE_RECORD_NAME{N} to be set.
    At least one complete pair is required.
"""

__version__ = "1.0.0"

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv  # type: ignore[import-not-found]  # no stubs available

# Configure logging for systemd/journald compatibility
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# IP lookup services with fallbacks
IP_SERVICES = [
    ("https://api.ipify.org", None),
    ("https://icanhazip.com", str.strip),
    ("https://ifconfig.me/ip", str.strip),
]

# Cloudflare API base URL
CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"

# State file for caching
STATE_FILE_NAME = ".ddns_state.json"

# Default verification interval in minutes
DEFAULT_VERIFY_INTERVAL_MINUTES = 60


def get_state_file_path() -> Path:
    """Get the path to the state file in the script's directory."""
    return Path(__file__).parent.resolve() / STATE_FILE_NAME


def load_state() -> dict[str, Any] | None:
    """
    Load cached state from state file.

    Returns:
        Dict with 'last_ip', 'last_updated', 'last_verified' keys,
        or None if file missing, corrupt, or invalid.
    """
    state_file = get_state_file_path()
    try:
        if not state_file.exists():
            logger.debug("No state file found")
            return None

        with open(state_file) as f:
            state = json.load(f)

        # Validate required fields
        if not isinstance(state, dict):
            logger.warning("State file is not a valid JSON object")
            return None

        if "last_ip" not in state:
            logger.warning("State file missing 'last_ip' field")
            return None

        logger.debug(f"Loaded state: IP={state.get('last_ip')}, verified={state.get('last_verified')}")
        return state

    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load state file: {e}")
        return None


def save_state(ip: str, just_verified: bool = False) -> None:
    """
    Save state to state file.

    Args:
        ip: Current IP address to cache
        just_verified: If True, only update last_verified timestamp (IP unchanged).
                      If False, update all fields (IP changed or new state).
    """
    state_file = get_state_file_path()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if just_verified:
        # Load existing state and just update verification time
        existing = load_state()
        if existing and existing.get("last_ip") == ip:
            state = {
                "last_ip": ip,
                "last_updated": existing.get("last_updated", now),
                "last_verified": now,
            }
        else:
            # Fallback to full update if state doesn't match
            state = {
                "last_ip": ip,
                "last_updated": now,
                "last_verified": now,
            }
    else:
        # Full update - IP changed or new state
        state = {
            "last_ip": ip,
            "last_updated": now,
            "last_verified": now,
        }

    try:
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
        logger.debug(f"Saved state: IP={ip}, verified={now}")
    except OSError as e:
        logger.warning(f"Failed to save state file: {e}")


def get_verify_interval_minutes() -> int:
    """
    Get verification interval from environment variable.

    Returns:
        Interval in minutes (default: 60)
    """
    try:
        interval = int(os.getenv("DDNS_VERIFY_INTERVAL_MINUTES", str(DEFAULT_VERIFY_INTERVAL_MINUTES)))
        if interval < 1:
            logger.warning(f"DDNS_VERIFY_INTERVAL_MINUTES must be >= 1, using default {DEFAULT_VERIFY_INTERVAL_MINUTES}")
            return DEFAULT_VERIFY_INTERVAL_MINUTES
        return interval
    except ValueError:
        logger.warning(f"Invalid DDNS_VERIFY_INTERVAL_MINUTES, using default {DEFAULT_VERIFY_INTERVAL_MINUTES}")
        return DEFAULT_VERIFY_INTERVAL_MINUTES


def is_verification_needed(state: dict[str, Any], verify_interval_minutes: int) -> bool:
    """
    Check if API verification is needed based on last_verified timestamp.

    Args:
        state: State dict with 'last_verified' key
        verify_interval_minutes: Interval in minutes

    Returns:
        True if verification is needed, False otherwise
    """
    last_verified_str = state.get("last_verified")
    if not last_verified_str:
        return True

    try:
        last_verified = datetime.fromisoformat(last_verified_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        age_minutes = (now - last_verified).total_seconds() / 60

        if age_minutes >= verify_interval_minutes:
            logger.info(f"Last verification was {age_minutes:.1f} minutes ago, reconfirmation needed")
            return True
        else:
            logger.debug(f"Last verification was {age_minutes:.1f} minutes ago")
            return False

    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to parse last_verified timestamp: {e}")
        return True


def get_auth_headers() -> dict[str, str] | None:
    """
    Build Cloudflare API authentication headers.

    Supports two methods:
    1. API Token (Bearer) - recommended
    2. Global API Key + Email - legacy

    Returns:
        Dict of headers, or None if no valid credentials found.
    """
    api_token = os.getenv("CLOUDFLARE_API_TOKEN", "").strip()
    api_email = os.getenv("CLOUDFLARE_EMAIL", "").strip()
    api_key = os.getenv("CLOUDFLARE_API_KEY", "").strip()

    if api_token:
        logger.debug("Using API token authentication")
        return {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
    elif api_email and api_key:
        logger.debug("Using Global API key authentication")
        return {
            "X-Auth-Email": api_email,
            "X-Auth-Key": api_key,
            "Content-Type": "application/json",
        }
    else:
        return None


def get_public_ip() -> str | None:
    """
    Fetch public IP address from multiple services with fallback.

    Returns:
        Public IP address as string, or None if all services fail.
    """
    for url, transform in IP_SERVICES:
        try:
            logger.debug(f"Trying IP service: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            ip: str = response.text
            if transform:
                ip = transform(ip)
            logger.debug(f"Got IP {ip} from {url}")
            return ip
        except requests.RequestException as e:
            logger.debug(f"Failed to get IP from {url}: {e}")
            continue

    logger.error("Failed to get public IP from all services")
    return None


def get_dns_record(headers: dict[str, str], zone_id: str, record_name: str) -> dict[str, Any] | None:
    """
    Fetch DNS record details from Cloudflare.

    Args:
        headers: Authentication headers from get_auth_headers()
        zone_id: Cloudflare zone ID
        record_name: Full DNS record name (e.g., subdomain.example.com)

    Returns:
        Dict with record details including 'id' and 'content', or None on failure.
    """
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records"
    params = {"type": "A", "name": record_name}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            logger.error(f"Cloudflare API error for {record_name}: {errors}")
            return None

        results = data.get("result", [])
        if not results:
            logger.error(f"DNS record not found: {record_name}")
            return None

        record: dict[str, Any] = results[0]
        logger.debug(f"Found record {record_name} with IP {record['content']}")
        return record

    except requests.RequestException as e:
        logger.error(f"Failed to fetch DNS record {record_name}: {e}")
        return None


def update_dns_record(
    headers: dict[str, str], zone_id: str, record_id: str, record_name: str, new_ip: str
) -> bool:
    """
    Update a DNS record in Cloudflare.

    Args:
        headers: Authentication headers from get_auth_headers()
        zone_id: Cloudflare zone ID
        record_id: Cloudflare record ID
        record_name: Full DNS record name
        new_ip: New IP address to set

    Returns:
        True on success, False on failure.
    """
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records/{record_id}"
    payload = {
        "type": "A",
        "name": record_name,
        "content": new_ip,
        "ttl": 1,  # Auto TTL
        "proxied": False,
    }

    try:
        response = requests.put(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()

        if data.get("success"):
            logger.info(f"Updated {record_name} to {new_ip}")
            return True
        else:
            errors = data.get("errors", [])
            logger.error(f"Failed to update {record_name}: {errors}")
            return False

    except requests.RequestException as e:
        logger.error(f"Failed to update DNS record {record_name}: {e}")
        return False


def get_configured_records() -> list[tuple[str, str]]:
    """
    Get list of configured DNS records from environment variables.

    Returns:
        List of (zone_id, record_name) tuples from CLOUDFLARE_ZONE_ID1-5
        and CLOUDFLARE_RECORD_NAME1-5. Only includes records where both
        zone_id and record_name are set.
    """
    records = []
    for i in range(1, 6):
        zone_id = os.getenv(f"CLOUDFLARE_ZONE_ID{i}", "").strip()
        record_name = os.getenv(f"CLOUDFLARE_RECORD_NAME{i}", "").strip()

        if zone_id and record_name:
            records.append((zone_id, record_name))
            logger.debug(f"Found configured record: {record_name} (zone {zone_id[:8]}...)")
        elif zone_id and not record_name:
            logger.warning(f"CLOUDFLARE_ZONE_ID{i} is set but CLOUDFLARE_RECORD_NAME{i} is missing")
        elif record_name and not zone_id:
            logger.warning(f"CLOUDFLARE_RECORD_NAME{i} is set but CLOUDFLARE_ZONE_ID{i} is missing")

    return records


def verify_and_update_records(
    auth_headers: dict[str, str], configured_records: list[tuple[str, str]], public_ip: str
) -> bool:
    """
    Verify DNS records with Cloudflare API and update if needed.

    Args:
        auth_headers: Authentication headers
        configured_records: List of (zone_id, record_name) tuples
        public_ip: Current public IP address

    Returns:
        True if all operations succeeded, False otherwise
    """
    all_success = True

    for zone_id, record_name in configured_records:
        logger.debug(f"Processing record: {record_name}")

        # Get current DNS record
        record = get_dns_record(auth_headers, zone_id, record_name)
        if not record:
            all_success = False
            continue

        current_ip = record.get("content")
        record_id = record.get("id")

        if not record_id:
            logger.error(f"No record ID found for {record_name}")
            all_success = False
            continue

        if current_ip == public_ip:
            logger.info(f"{record_name} already points to {public_ip}, no update needed")
            continue

        logger.info(f"{record_name} needs update: {current_ip} -> {public_ip}")

        # Update the record
        if not update_dns_record(auth_headers, zone_id, str(record_id), record_name, public_ip):
            all_success = False

    return all_success


def main() -> int:
    """
    Main entry point for the DDNS updater.

    Returns:
        Exit code: 0 on success, 1 on failure.
    """
    # Load .env from script's directory
    script_dir = Path(__file__).parent.resolve()
    env_file = script_dir / ".env"
    if env_file.exists():
        load_dotenv(env_file)
        logger.debug(f"Loaded environment from {env_file}")

    # Get verification interval and log at startup
    verify_interval = get_verify_interval_minutes()
    logger.info(f"Verification interval: {verify_interval} minutes")

    # Get current public IP first (this is cheap/fast)
    public_ip = get_public_ip()
    if not public_ip:
        return 1

    logger.info(f"Current public IP: {public_ip}")

    # Load cached state
    state = load_state()

    # Check if we can use cached state
    if state and state.get("last_ip") == public_ip:
        # IP matches cache - check if verification is needed
        if not is_verification_needed(state, verify_interval):
            logger.info("IP unchanged, skipping API check")
            return 0
        else:
            logger.info("IP unchanged but hourly reconfirmation needed, verifying with Cloudflare API")
    else:
        if state:
            logger.info(f"IP changed from {state.get('last_ip')} to {public_ip}, updating Cloudflare")
        else:
            logger.info("No cached state, querying Cloudflare API")

    # At this point we need to call Cloudflare API
    # Validate authentication credentials
    auth_headers = get_auth_headers()
    if not auth_headers:
        logger.error("Authentication required: set CLOUDFLARE_API_TOKEN or (CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY)")
        return 1

    # Get configured records (zone_id, record_name pairs)
    configured_records = get_configured_records()
    if not configured_records:
        logger.error("At least one CLOUDFLARE_ZONE_ID{N}/CLOUDFLARE_RECORD_NAME{N} pair is required")
        return 1

    logger.info(f"Processing {len(configured_records)} record(s)")

    # Verify and update records
    all_success = verify_and_update_records(auth_headers, configured_records, public_ip)

    # Save state
    if all_success:
        # Determine if this was just a verification or a real update
        just_verified = bool(state and state.get("last_ip") == public_ip)
        save_state(public_ip, just_verified=just_verified)
        logger.info("DDNS update completed successfully")
        return 0
    else:
        logger.error("DDNS update completed with errors")
        return 1


if __name__ == "__main__":
    sys.exit(main())
