#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pytest",
#     "pytest-mock",
#     "requests-mock",
#     "requests",
#     "python-dotenv",
# ]
# ///
"""
Test suite for Cloudflare Dynamic DNS Updater.

Run with: uv run pytest test_cloudflare_ddns.py -v
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

import cloudflare_ddns as ddns


# =============================================================================
# State Management Tests
# =============================================================================


class TestLoadState:
    """Tests for load_state() function."""

    def test_load_state_valid_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading a valid state file."""
        state_file = tmp_path / ".ddns_state.json"
        state_data = {
            "last_ip": "203.0.113.42",
            "last_updated": "2024-01-15T10:30:00Z",
            "last_verified": "2024-01-15T11:00:00Z",
        }
        state_file.write_text(json.dumps(state_data))

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        result = ddns.load_state()

        assert result is not None
        assert result["last_ip"] == "203.0.113.42"
        assert result["last_updated"] == "2024-01-15T10:30:00Z"
        assert result["last_verified"] == "2024-01-15T11:00:00Z"

    def test_load_state_missing_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading when state file does not exist."""
        state_file = tmp_path / ".ddns_state.json"
        # Don't create the file

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        result = ddns.load_state()

        assert result is None

    def test_load_state_corrupt_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading a corrupt JSON file."""
        state_file = tmp_path / ".ddns_state.json"
        state_file.write_text("{ invalid json content")

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        result = ddns.load_state()

        assert result is None

    def test_load_state_not_dict(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading a JSON file that is not a dict."""
        state_file = tmp_path / ".ddns_state.json"
        state_file.write_text('["not", "a", "dict"]')

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        result = ddns.load_state()

        assert result is None

    def test_load_state_missing_last_ip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading a state file missing the required last_ip field."""
        state_file = tmp_path / ".ddns_state.json"
        state_data = {
            "last_updated": "2024-01-15T10:30:00Z",
            "last_verified": "2024-01-15T11:00:00Z",
        }
        state_file.write_text(json.dumps(state_data))

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        result = ddns.load_state()

        assert result is None


class TestSaveState:
    """Tests for save_state() function."""

    def test_save_state_new(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test saving state to a new file."""
        state_file = tmp_path / ".ddns_state.json"

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        ddns.save_state("203.0.113.42", just_verified=False)

        assert state_file.exists()
        saved = json.loads(state_file.read_text())
        assert saved["last_ip"] == "203.0.113.42"
        assert "last_updated" in saved
        assert "last_verified" in saved

    def test_save_state_update_existing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test updating an existing state file with new IP."""
        state_file = tmp_path / ".ddns_state.json"
        old_state = {
            "last_ip": "192.0.2.100",
            "last_updated": "2024-01-10T08:00:00Z",
            "last_verified": "2024-01-10T08:00:00Z",
        }
        state_file.write_text(json.dumps(old_state))

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        ddns.save_state("203.0.113.42", just_verified=False)

        saved = json.loads(state_file.read_text())
        assert saved["last_ip"] == "203.0.113.42"
        # Both timestamps should be updated for new IP
        assert saved["last_updated"] != "2024-01-10T08:00:00Z"

    def test_save_state_just_verified(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test updating only the verification timestamp."""
        state_file = tmp_path / ".ddns_state.json"
        original_updated = "2024-01-10T08:00:00Z"
        old_state = {
            "last_ip": "203.0.113.42",
            "last_updated": original_updated,
            "last_verified": "2024-01-10T08:00:00Z",
        }
        state_file.write_text(json.dumps(old_state))

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        ddns.save_state("203.0.113.42", just_verified=True)

        saved = json.loads(state_file.read_text())
        assert saved["last_ip"] == "203.0.113.42"
        # last_updated should be preserved
        assert saved["last_updated"] == original_updated
        # last_verified should be updated
        assert saved["last_verified"] != "2024-01-10T08:00:00Z"


class TestIsVerificationNeeded:
    """Tests for is_verification_needed() function."""

    def test_verification_needed_missing_timestamp(self) -> None:
        """Test verification needed when last_verified is missing."""
        state = {"last_ip": "203.0.113.42"}

        result = ddns.is_verification_needed(state, verify_interval_minutes=60)

        assert result is True

    def test_verification_needed_stale_timestamp(self) -> None:
        """Test verification needed when timestamp is older than interval."""
        two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
        state = {
            "last_ip": "203.0.113.42",
            "last_verified": two_hours_ago.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        result = ddns.is_verification_needed(state, verify_interval_minutes=60)

        assert result is True

    def test_verification_not_needed_fresh_timestamp(self) -> None:
        """Test verification not needed when timestamp is fresh."""
        five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
        state = {
            "last_ip": "203.0.113.42",
            "last_verified": five_minutes_ago.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        result = ddns.is_verification_needed(state, verify_interval_minutes=60)

        assert result is False

    def test_verification_needed_invalid_timestamp(self) -> None:
        """Test verification needed when timestamp is invalid."""
        state = {
            "last_ip": "203.0.113.42",
            "last_verified": "not-a-valid-timestamp",
        }

        result = ddns.is_verification_needed(state, verify_interval_minutes=60)

        assert result is True

    def test_verification_boundary_exact_interval(self) -> None:
        """Test verification at exact boundary of interval."""
        exactly_60_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=60)
        state = {
            "last_ip": "203.0.113.42",
            "last_verified": exactly_60_minutes_ago.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        result = ddns.is_verification_needed(state, verify_interval_minutes=60)

        assert result is True


# =============================================================================
# Configuration Tests
# =============================================================================


class TestGetVerifyIntervalMinutes:
    """Tests for get_verify_interval_minutes() function."""

    def test_default_interval(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test default interval when env var not set."""
        monkeypatch.delenv("DDNS_VERIFY_INTERVAL_MINUTES", raising=False)

        result = ddns.get_verify_interval_minutes()

        assert result == 60

    def test_valid_interval(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test valid custom interval."""
        monkeypatch.setenv("DDNS_VERIFY_INTERVAL_MINUTES", "120")

        result = ddns.get_verify_interval_minutes()

        assert result == 120

    def test_invalid_non_numeric(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fallback to default for non-numeric value."""
        monkeypatch.setenv("DDNS_VERIFY_INTERVAL_MINUTES", "invalid")

        result = ddns.get_verify_interval_minutes()

        assert result == 60

    def test_invalid_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fallback to default for zero value."""
        monkeypatch.setenv("DDNS_VERIFY_INTERVAL_MINUTES", "0")

        result = ddns.get_verify_interval_minutes()

        assert result == 60

    def test_invalid_negative(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fallback to default for negative value."""
        monkeypatch.setenv("DDNS_VERIFY_INTERVAL_MINUTES", "-5")

        result = ddns.get_verify_interval_minutes()

        assert result == 60

    def test_minimum_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test minimum valid interval of 1."""
        monkeypatch.setenv("DDNS_VERIFY_INTERVAL_MINUTES", "1")

        result = ddns.get_verify_interval_minutes()

        assert result == 1


class TestGetAuthHeaders:
    """Tests for get_auth_headers() function."""

    def test_api_token_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test authentication with API token."""
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token-123")
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)

        result = ddns.get_auth_headers()

        assert result is not None
        assert result["Authorization"] == "Bearer test-token-123"
        assert result["Content-Type"] == "application/json"

    def test_global_key_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test authentication with global API key."""
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.setenv("CLOUDFLARE_EMAIL", "user@example.com")
        monkeypatch.setenv("CLOUDFLARE_API_KEY", "global-api-key-456")

        result = ddns.get_auth_headers()

        assert result is not None
        assert result["X-Auth-Email"] == "user@example.com"
        assert result["X-Auth-Key"] == "global-api-key-456"
        assert result["Content-Type"] == "application/json"

    def test_api_token_takes_precedence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that API token takes precedence over global key."""
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token-123")
        monkeypatch.setenv("CLOUDFLARE_EMAIL", "user@example.com")
        monkeypatch.setenv("CLOUDFLARE_API_KEY", "global-api-key-456")

        result = ddns.get_auth_headers()

        assert result is not None
        assert "Authorization" in result
        assert "X-Auth-Email" not in result

    def test_missing_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test None returned when no credentials available."""
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)

        result = ddns.get_auth_headers()

        assert result is None

    def test_partial_global_key_missing_email(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test None when only API key is set (missing email)."""
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.setenv("CLOUDFLARE_API_KEY", "global-api-key-456")

        result = ddns.get_auth_headers()

        assert result is None

    def test_partial_global_key_missing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test None when only email is set (missing key)."""
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.setenv("CLOUDFLARE_EMAIL", "user@example.com")
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)

        result = ddns.get_auth_headers()

        assert result is None

    def test_whitespace_token_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that whitespace-only token is treated as missing."""
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "   ")
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)

        result = ddns.get_auth_headers()

        assert result is None


class TestGetConfiguredRecords:
    """Tests for get_configured_records() function."""

    def test_valid_single_pair(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test with a single valid zone/record pair."""
        # Clear all zone/record env vars
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        monkeypatch.setenv("CLOUDFLARE_ZONE_ID1", "zone-id-abc123")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME1", "home.example.com")

        result = ddns.get_configured_records()

        assert len(result) == 1
        assert result[0] == ("zone-id-abc123", "home.example.com")

    def test_valid_multiple_pairs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test with multiple valid zone/record pairs."""
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        monkeypatch.setenv("CLOUDFLARE_ZONE_ID1", "zone-id-1")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME1", "home.example.com")
        monkeypatch.setenv("CLOUDFLARE_ZONE_ID2", "zone-id-2")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME2", "backup.otherdomain.com")
        monkeypatch.setenv("CLOUDFLARE_ZONE_ID3", "zone-id-3")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME3", "api.thirdsite.org")

        result = ddns.get_configured_records()

        assert len(result) == 3
        assert ("zone-id-1", "home.example.com") in result
        assert ("zone-id-2", "backup.otherdomain.com") in result
        assert ("zone-id-3", "api.thirdsite.org") in result

    def test_missing_all_pairs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test with no zone/record pairs configured."""
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        result = ddns.get_configured_records()

        assert len(result) == 0

    def test_partial_pair_zone_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test partial pair with only zone ID set (logs warning, skips)."""
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        monkeypatch.setenv("CLOUDFLARE_ZONE_ID1", "zone-id-abc123")
        # CLOUDFLARE_RECORD_NAME1 not set

        result = ddns.get_configured_records()

        assert len(result) == 0

    def test_partial_pair_record_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test partial pair with only record name set (logs warning, skips)."""
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        # CLOUDFLARE_ZONE_ID1 not set
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME1", "home.example.com")

        result = ddns.get_configured_records()

        assert len(result) == 0

    def test_mixed_valid_and_partial_pairs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test mix of valid pairs and partial pairs."""
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        # Valid pair
        monkeypatch.setenv("CLOUDFLARE_ZONE_ID1", "zone-id-1")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME1", "home.example.com")
        # Partial pair (zone only)
        monkeypatch.setenv("CLOUDFLARE_ZONE_ID2", "zone-id-2")
        # Valid pair
        monkeypatch.setenv("CLOUDFLARE_ZONE_ID3", "zone-id-3")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME3", "api.example.com")

        result = ddns.get_configured_records()

        assert len(result) == 2
        assert ("zone-id-1", "home.example.com") in result
        assert ("zone-id-3", "api.example.com") in result


# =============================================================================
# API Interaction Tests (Mocked)
# =============================================================================


class TestGetPublicIp:
    """Tests for get_public_ip() function."""

    def test_first_service_success(self, requests_mock: MagicMock) -> None:
        """Test successful IP fetch from first service."""
        requests_mock.get("https://api.ipify.org", text="203.0.113.42")

        result = ddns.get_public_ip()

        assert result == "203.0.113.42"

    def test_fallback_to_second_service(self, requests_mock: MagicMock) -> None:
        """Test fallback when first service fails."""
        requests_mock.get("https://api.ipify.org", status_code=500)
        requests_mock.get("https://icanhazip.com", text="203.0.113.42\n")

        result = ddns.get_public_ip()

        assert result == "203.0.113.42"

    def test_fallback_to_third_service(self, requests_mock: MagicMock) -> None:
        """Test fallback when first two services fail."""
        requests_mock.get("https://api.ipify.org", exc=requests.exceptions.ConnectionError)
        requests_mock.get("https://icanhazip.com", status_code=503)
        requests_mock.get("https://ifconfig.me/ip", text="  203.0.113.42  \n")

        result = ddns.get_public_ip()

        assert result == "203.0.113.42"

    def test_all_services_fail(self, requests_mock: MagicMock) -> None:
        """Test None returned when all services fail."""
        requests_mock.get("https://api.ipify.org", exc=requests.exceptions.Timeout)
        requests_mock.get("https://icanhazip.com", exc=requests.exceptions.ConnectionError)
        requests_mock.get("https://ifconfig.me/ip", status_code=500)

        result = ddns.get_public_ip()

        assert result is None

    def test_whitespace_stripping(self, requests_mock: MagicMock) -> None:
        """Test that IP services that return whitespace are handled."""
        requests_mock.get("https://api.ipify.org", status_code=500)
        requests_mock.get("https://icanhazip.com", text="\n  203.0.113.42  \n\n")

        result = ddns.get_public_ip()

        assert result == "203.0.113.42"

    def test_invalid_ip_rejected(self, requests_mock: MagicMock) -> None:
        """Test that non-IPv4 responses are rejected and fallback occurs."""
        # First service returns HTML garbage
        requests_mock.get("https://api.ipify.org", text="<html>Error</html>")
        # Second service returns valid IP
        requests_mock.get("https://icanhazip.com", text="203.0.113.42\n")

        result = ddns.get_public_ip()

        assert result == "203.0.113.42"

    def test_ipv6_rejected(self, requests_mock: MagicMock) -> None:
        """Test that IPv6 addresses are rejected (only IPv4 A records supported)."""
        requests_mock.get("https://api.ipify.org", text="2001:db8::1")
        requests_mock.get("https://icanhazip.com", text="203.0.113.42\n")

        result = ddns.get_public_ip()

        assert result == "203.0.113.42"


class TestGetDnsRecord:
    """Tests for get_dns_record() function."""

    def test_successful_response(self, requests_mock: MagicMock) -> None:
        """Test successful DNS record fetch."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        zone_id = "zone-id-123"
        record_name = "home.example.com"

        mock_response = {
            "success": True,
            "result": [
                {
                    "id": "record-id-456",
                    "name": "home.example.com",
                    "type": "A",
                    "content": "203.0.113.42",
                    "ttl": 1,
                }
            ],
        }
        requests_mock.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            json=mock_response,
        )

        result = ddns.get_dns_record(headers, zone_id, record_name)

        assert result is not None
        assert result["id"] == "record-id-456"
        assert result["content"] == "203.0.113.42"

    def test_api_error_response(self, requests_mock: MagicMock) -> None:
        """Test handling of API error response."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        zone_id = "zone-id-123"
        record_name = "home.example.com"

        mock_response = {
            "success": False,
            "errors": [{"code": 9103, "message": "Invalid API token"}],
        }
        requests_mock.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            json=mock_response,
        )

        result = ddns.get_dns_record(headers, zone_id, record_name)

        assert result is None

    def test_record_not_found(self, requests_mock: MagicMock) -> None:
        """Test handling when DNS record does not exist."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        zone_id = "zone-id-123"
        record_name = "nonexistent.example.com"

        mock_response = {
            "success": True,
            "result": [],
        }
        requests_mock.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            json=mock_response,
        )

        result = ddns.get_dns_record(headers, zone_id, record_name)

        assert result is None

    def test_request_exception(self, requests_mock: MagicMock) -> None:
        """Test handling of request exceptions."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        zone_id = "zone-id-123"
        record_name = "home.example.com"

        requests_mock.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            exc=requests.exceptions.ConnectionError,
        )

        result = ddns.get_dns_record(headers, zone_id, record_name)

        assert result is None


class TestUpdateDnsRecord:
    """Tests for update_dns_record() function."""

    def test_successful_update(self, requests_mock: MagicMock) -> None:
        """Test successful DNS record update."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        zone_id = "zone-id-123"
        record_id = "record-id-456"
        record_name = "home.example.com"
        new_ip = "198.51.100.1"

        mock_response = {
            "success": True,
            "result": {
                "id": record_id,
                "name": record_name,
                "type": "A",
                "content": new_ip,
            },
        }
        requests_mock.put(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
            json=mock_response,
        )

        existing_record = {"id": record_id, "name": record_name, "content": "203.0.113.42", "ttl": 300, "proxied": True}
        result = ddns.update_dns_record(headers, zone_id, record_id, record_name, new_ip, existing_record)

        assert result is True

    def test_update_failure_api_error(self, requests_mock: MagicMock) -> None:
        """Test handling of API error during update."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        zone_id = "zone-id-123"
        record_id = "record-id-456"
        record_name = "home.example.com"
        new_ip = "198.51.100.1"

        mock_response = {
            "success": False,
            "errors": [{"code": 9103, "message": "Invalid API token"}],
        }
        requests_mock.put(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
            json=mock_response,
        )

        existing_record = {"id": record_id, "name": record_name, "content": "203.0.113.42", "ttl": 1, "proxied": False}
        result = ddns.update_dns_record(headers, zone_id, record_id, record_name, new_ip, existing_record)

        assert result is False

    def test_update_failure_request_exception(self, requests_mock: MagicMock) -> None:
        """Test handling of request exceptions during update."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        zone_id = "zone-id-123"
        record_id = "record-id-456"
        record_name = "home.example.com"
        new_ip = "198.51.100.1"

        requests_mock.put(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
            exc=requests.exceptions.Timeout,
        )

        existing_record = {"id": record_id, "name": record_name, "content": "203.0.113.42", "ttl": 1, "proxied": False}
        result = ddns.update_dns_record(headers, zone_id, record_id, record_name, new_ip, existing_record)

        assert result is False

    def test_preserves_existing_record_settings(self, requests_mock: MagicMock) -> None:
        """Test that existing TTL and proxy settings are preserved in update payload."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        zone_id = "zone-id-123"
        record_id = "record-id-456"
        record_name = "home.example.com"
        new_ip = "198.51.100.1"
        existing_record = {
            "id": record_id,
            "name": record_name,
            "content": "203.0.113.42",
            "ttl": 300,
            "proxied": True,
        }

        mock_response = {"success": True, "result": {"id": record_id, "content": new_ip}}
        requests_mock.put(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
            json=mock_response,
        )

        result = ddns.update_dns_record(headers, zone_id, record_id, record_name, new_ip, existing_record)

        assert result is True
        # Verify the PUT payload preserved TTL and proxy settings
        put_request = requests_mock.request_history[-1]
        sent_payload = json.loads(put_request.body)
        assert sent_payload["ttl"] == 300
        assert sent_payload["proxied"] is True
        assert sent_payload["content"] == new_ip


# =============================================================================
# Integration Tests
# =============================================================================


class TestVerifyAndUpdateRecords:
    """Tests for verify_and_update_records() function."""

    def test_update_needed(self, requests_mock: MagicMock) -> None:
        """Test when DNS record needs updating."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        records = [("zone-id-1", "home.example.com")]
        public_ip = "198.51.100.1"

        # Mock get_dns_record response (old IP)
        get_response = {
            "success": True,
            "result": [
                {
                    "id": "record-id-456",
                    "name": "home.example.com",
                    "type": "A",
                    "content": "203.0.113.42",  # Different from public_ip
                }
            ],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response,
        )

        # Mock update_dns_record response
        update_response = {
            "success": True,
            "result": {"id": "record-id-456", "content": public_ip},
        }
        requests_mock.put(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records/record-id-456",
            json=update_response,
        )

        result = ddns.verify_and_update_records(headers, records, public_ip)

        assert result is True
        # Verify update was called
        assert requests_mock.call_count == 2
        put_request = requests_mock.request_history[-1]
        assert put_request.method == "PUT"

    def test_already_current(self, requests_mock: MagicMock) -> None:
        """Test when DNS record already has correct IP."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        records = [("zone-id-1", "home.example.com")]
        public_ip = "198.51.100.1"

        # Mock get_dns_record response (same IP)
        get_response = {
            "success": True,
            "result": [
                {
                    "id": "record-id-456",
                    "name": "home.example.com",
                    "type": "A",
                    "content": "198.51.100.1",  # Same as public_ip
                }
            ],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response,
        )

        result = ddns.verify_and_update_records(headers, records, public_ip)

        assert result is True
        # Verify update was NOT called (only GET)
        assert requests_mock.call_count == 1
        assert requests_mock.request_history[0].method == "GET"

    def test_partial_failure(self, requests_mock: MagicMock) -> None:
        """Test when one record succeeds but another fails."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        records = [
            ("zone-id-1", "home.example.com"),
            ("zone-id-2", "backup.otherdomain.com"),
        ]
        public_ip = "198.51.100.1"

        # First record: success
        get_response_1 = {
            "success": True,
            "result": [{"id": "record-1", "name": "home.example.com", "content": "old-ip-1"}],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response_1,
        )
        update_response_1 = {"success": True, "result": {"id": "record-1"}}
        requests_mock.put(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records/record-1",
            json=update_response_1,
        )

        # Second record: failure (record not found)
        get_response_2 = {
            "success": True,
            "result": [],  # Empty - record not found
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-2/dns_records",
            json=get_response_2,
        )

        result = ddns.verify_and_update_records(headers, records, public_ip)

        assert result is False  # Partial failure

    def test_multiple_records_all_success(self, requests_mock: MagicMock) -> None:
        """Test successful update of multiple records."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        records = [
            ("zone-id-1", "home.example.com"),
            ("zone-id-2", "backup.otherdomain.com"),
        ]
        public_ip = "198.51.100.1"

        # First record
        get_response_1 = {
            "success": True,
            "result": [{"id": "record-1", "name": "home.example.com", "content": "old-ip"}],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response_1,
        )
        update_response_1 = {"success": True, "result": {"id": "record-1"}}
        requests_mock.put(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records/record-1",
            json=update_response_1,
        )

        # Second record
        get_response_2 = {
            "success": True,
            "result": [{"id": "record-2", "name": "backup.otherdomain.com", "content": "old-ip"}],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-2/dns_records",
            json=get_response_2,
        )
        update_response_2 = {"success": True, "result": {"id": "record-2"}}
        requests_mock.put(
            "https://api.cloudflare.com/client/v4/zones/zone-id-2/dns_records/record-2",
            json=update_response_2,
        )

        result = ddns.verify_and_update_records(headers, records, public_ip)

        assert result is True
        # Verify both records were updated (2 GET + 2 PUT)
        assert requests_mock.call_count == 4

    def test_record_missing_id(self, requests_mock: MagicMock) -> None:
        """Test handling of record with missing ID field."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        records = [("zone-id-1", "home.example.com")]
        public_ip = "198.51.100.1"

        # Record without id field
        get_response = {
            "success": True,
            "result": [
                {
                    # "id": missing
                    "name": "home.example.com",
                    "type": "A",
                    "content": "203.0.113.42",
                }
            ],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response,
        )

        result = ddns.verify_and_update_records(headers, records, public_ip)

        assert result is False


# =============================================================================
# Additional Edge Case Tests
# =============================================================================


class TestSaveStateEdgeCases:
    """Additional edge case tests for save_state()."""

    def test_save_state_just_verified_ip_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test just_verified=True but cached IP doesn't match (fallback to full update)."""
        state_file = tmp_path / ".ddns_state.json"
        # Create existing state with different IP
        existing_state = {
            "last_ip": "203.0.113.99",  # Different from what we'll save
            "last_updated": "2024-01-15T10:00:00Z",
            "last_verified": "2024-01-15T10:00:00Z",
        }
        state_file.write_text(json.dumps(existing_state))

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        # Save with just_verified=True but different IP
        ddns.save_state("198.51.100.1", just_verified=True)

        # Should do full update since IPs don't match
        saved = json.loads(state_file.read_text())
        assert saved["last_ip"] == "198.51.100.1"
        # Both timestamps should be updated (not preserved)
        assert saved["last_updated"] == saved["last_verified"]

    def test_save_state_write_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test handling of write failure (e.g., read-only filesystem)."""
        # Point to a non-existent directory to cause write failure
        state_file = tmp_path / "nonexistent_dir" / ".ddns_state.json"

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        # Should not raise, just log warning
        ddns.save_state("198.51.100.1")

        # File should not exist
        assert not state_file.exists()


class TestVerifyAndUpdateRecordsEdgeCases:
    """Additional edge case tests for verify_and_update_records()."""

    def test_update_fails(self, requests_mock: MagicMock) -> None:
        """Test when update API call fails."""
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}
        records = [("zone-id-1", "home.example.com")]
        public_ip = "198.51.100.1"

        # Get succeeds with different IP
        get_response = {
            "success": True,
            "result": [{"id": "record-1", "name": "home.example.com", "content": "old-ip"}],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response,
        )

        # Update fails
        update_response = {"success": False, "errors": [{"message": "Update failed"}]}
        requests_mock.put(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records/record-1",
            json=update_response,
        )

        result = ddns.verify_and_update_records(headers, records, public_ip)

        assert result is False


# =============================================================================
# Main Function Tests
# =============================================================================


class TestMain:
    """Tests for main() function."""

    def test_main_ip_unchanged_skip_api(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requests_mock: MagicMock
    ) -> None:
        """Test main() when IP unchanged and verification not needed."""
        # Setup state file with current IP
        state_file = tmp_path / ".ddns_state.json"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        state_data = {
            "last_ip": "198.51.100.1",
            "last_updated": now,
            "last_verified": now,
        }
        state_file.write_text(json.dumps(state_data))
        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        # Mock IP service
        requests_mock.get("https://api.ipify.org", text="198.51.100.1")

        # Clear env vars to prevent real config interference
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.setenv("DDNS_VERIFY_INTERVAL_MINUTES", "60")

        # Mock load_dotenv to do nothing
        monkeypatch.setattr(ddns, "load_dotenv", lambda x: None)

        result = ddns.main()

        # Should return 0 (success) without calling Cloudflare API
        assert result == 0

    def test_main_no_public_ip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requests_mock: MagicMock
    ) -> None:
        """Test main() when public IP cannot be determined."""
        # Mock all IP services to fail
        requests_mock.get("https://api.ipify.org", exc=requests.exceptions.Timeout)
        requests_mock.get("https://icanhazip.com", exc=requests.exceptions.Timeout)
        requests_mock.get("https://ifconfig.me/ip", exc=requests.exceptions.Timeout)

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: tmp_path / ".ddns_state.json")

        result = ddns.main()

        assert result == 1  # Failure

    def test_main_no_auth_credentials(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requests_mock: MagicMock
    ) -> None:
        """Test main() when no auth credentials are configured."""
        # Mock IP service
        requests_mock.get("https://api.ipify.org", text="198.51.100.1")

        # No state file - will query API
        monkeypatch.setattr(ddns, "get_state_file_path", lambda: tmp_path / ".ddns_state.json")

        # Clear all auth and record env vars (prevent real .env from being used)
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        # Mock load_dotenv to do nothing
        monkeypatch.setattr(ddns, "load_dotenv", lambda x: None)

        result = ddns.main()

        assert result == 1  # Failure - no credentials

    def test_main_no_configured_records(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requests_mock: MagicMock
    ) -> None:
        """Test main() when no DNS records are configured."""
        # Mock IP service
        requests_mock.get("https://api.ipify.org", text="198.51.100.1")

        monkeypatch.setattr(ddns, "get_state_file_path", lambda: tmp_path / ".ddns_state.json")

        # Clear all real env vars first
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        # Mock load_dotenv to do nothing
        monkeypatch.setattr(ddns, "load_dotenv", lambda x: None)

        # Now set test auth but no records
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token")

        result = ddns.main()

        assert result == 1  # Failure - no records configured

    def test_main_successful_update(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requests_mock: MagicMock
    ) -> None:
        """Test main() with successful update flow."""
        state_file = tmp_path / ".ddns_state.json"
        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        # Mock IP service
        requests_mock.get("https://api.ipify.org", text="198.51.100.1")

        # Clear all real env vars first
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        # Mock load_dotenv to do nothing
        monkeypatch.setattr(ddns, "load_dotenv", lambda x: None)

        # Set test auth and record
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token")
        monkeypatch.setenv("CLOUDFLARE_ZONE_ID1", "zone-id-1")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME1", "home.example.com")

        # Mock Cloudflare API
        get_response = {
            "success": True,
            "result": [{"id": "record-1", "name": "home.example.com", "content": "old-ip"}],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response,
        )
        update_response = {"success": True, "result": {"id": "record-1"}}
        requests_mock.put(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records/record-1",
            json=update_response,
        )

        result = ddns.main()

        assert result == 0  # Success
        # State should be saved
        assert state_file.exists()
        saved_state = json.loads(state_file.read_text())
        assert saved_state["last_ip"] == "198.51.100.1"

    def test_main_update_with_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requests_mock: MagicMock
    ) -> None:
        """Test main() when update completes with errors."""
        state_file = tmp_path / ".ddns_state.json"
        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        # Mock IP service
        requests_mock.get("https://api.ipify.org", text="198.51.100.1")

        # Clear all real env vars first
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        # Mock load_dotenv to do nothing
        monkeypatch.setattr(ddns, "load_dotenv", lambda x: None)

        # Set test auth and record
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token")
        monkeypatch.setenv("CLOUDFLARE_ZONE_ID1", "zone-id-1")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME1", "home.example.com")

        # Mock Cloudflare API - get fails
        get_response = {"success": True, "result": []}  # Record not found
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response,
        )

        result = ddns.main()

        assert result == 1  # Failure
        # State should NOT be saved on failure
        assert not state_file.exists()

    def test_main_ip_changed_from_cached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requests_mock: MagicMock
    ) -> None:
        """Test main() when IP changes from a previously cached state."""
        state_file = tmp_path / ".ddns_state.json"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Old state with different IP
        state_data = {
            "last_ip": "203.0.113.42",
            "last_updated": now,
            "last_verified": now,
        }
        state_file.write_text(json.dumps(state_data))
        monkeypatch.setattr(ddns, "get_state_file_path", lambda: state_file)

        # Mock IP service returns NEW IP
        requests_mock.get("https://api.ipify.org", text="198.51.100.1")

        # Clear env vars
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        monkeypatch.delenv("CLOUDFLARE_EMAIL", raising=False)
        monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)
        for i in range(1, 6):
            monkeypatch.delenv(f"CLOUDFLARE_ZONE_ID{i}", raising=False)
            monkeypatch.delenv(f"CLOUDFLARE_RECORD_NAME{i}", raising=False)

        monkeypatch.setattr(ddns, "load_dotenv", lambda x: None)

        # Set test auth and record
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token")
        monkeypatch.setenv("CLOUDFLARE_ZONE_ID1", "zone-id-1")
        monkeypatch.setenv("CLOUDFLARE_RECORD_NAME1", "home.example.com")

        # Mock Cloudflare API
        get_response = {
            "success": True,
            "result": [{"id": "record-1", "name": "home.example.com", "content": "203.0.113.42", "ttl": 1, "proxied": False}],
        }
        requests_mock.get(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records",
            json=get_response,
        )
        update_response = {"success": True, "result": {"id": "record-1"}}
        requests_mock.put(
            "https://api.cloudflare.com/client/v4/zones/zone-id-1/dns_records/record-1",
            json=update_response,
        )

        result = ddns.main()

        assert result == 0
        saved_state = json.loads(state_file.read_text())
        assert saved_state["last_ip"] == "198.51.100.1"


# =============================================================================
# Run tests if executed directly
# =============================================================================


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
