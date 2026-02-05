# Cloudflare Dynamic DNS Updater

Keep your DNS A records synchronized with your current public IP address using the Cloudflare API.

## Features

- **Multi-domain support**: Update up to 5 DNS A records simultaneously
- **Automatic IP detection**: Fetches current public IP from external service
- **Efficient caching**: Only updates Cloudflare API when IP actually changes
- **systemd integration**: User-level timer for reliable scheduling (default: every 1 minute)
- **Structured logging**: Outputs to stdout and integrates with journald

## Requirements

- Python 3.14 or later
- [UV](https://docs.astral.sh/uv/) for running standalone scripts
- Cloudflare account with DNS edit permissions

## Quick Start

1. **Clone or download this repository**

2. **Create a `.env` file** with your Cloudflare credentials:
   ```
   CLOUDFLARE_API_TOKEN=your_scoped_api_token_here
   CLOUDFLARE_ZONE_ID1=your_zone_id_here
   CLOUDFLARE_RECORD_NAME1=home.example.com
   CLOUDFLARE_ZONE_ID2=your_second_zone_id
   CLOUDFLARE_RECORD_NAME2=backup.example.com
   ```

3. **Run manually** to test:
   ```bash
   ./cloudflare_ddns.py
   # or
   uv run cloudflare_ddns.py
   ```

## Configuration

Store your credentials in a `.env` file in the repository root. This file is git-ignored and should never be committed.

### Environment Variables

**Authentication** (choose one):
- `CLOUDFLARE_API_TOKEN` - Scoped API token with DNS edit permissions (recommended)
- `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` - Legacy global API key

**DNS Records** (up to 5 pairs):
- `CLOUDFLARE_ZONE_ID{1-5}` - Zone ID for your domain (paired with RECORD_NAME)
- `CLOUDFLARE_RECORD_NAME{1-5}` - DNS A record name to update (paired with ZONE_ID)

**Optional**:
- `DDNS_VERIFY_INTERVAL_MINUTES` - How often to verify with Cloudflare when IP unchanged (default: 60)

### Example `.env`
```
CLOUDFLARE_API_TOKEN=c5c4e0e2f3c4e0e2f3c4e0e2f3c4e0e2f3c4e
CLOUDFLARE_ZONE_ID1=abc123def456ghi789jkl012
CLOUDFLARE_RECORD_NAME1=home.example.com
CLOUDFLARE_ZONE_ID2=xyz987uvw654tsr321onm098
CLOUDFLARE_RECORD_NAME2=backup.otherdomain.com
```

## Service Installation

For automatic updates every minute, install as a systemd user service.

### Prerequisites

1. Ensure lingering is enabled for your user (allows services to run without login):
   ```bash
   sudo loginctl enable-linger $USER
   ```

### Setup Steps

1. Copy systemd files to your user systemd directory:
   ```bash
   mkdir -p ~/.config/systemd/user/
   cp systemd/cloudflare-ddns.service ~/.config/systemd/user/
   cp systemd/cloudflare-ddns.timer ~/.config/systemd/user/
   ```

2. Reload systemd and enable the timer:
   ```bash
   systemctl --user daemon-reload
   systemctl --user enable cloudflare-ddns.timer
   systemctl --user start cloudflare-ddns.timer
   ```

### Verify Installation

Check that the timer is running:
```bash
systemctl --user status cloudflare-ddns.timer
```

View recent logs:
```bash
journalctl --user -u cloudflare-ddns.service -f
```

### Common Commands

```bash
# Check service status (shows last run result)
systemctl --user status cloudflare-ddns.service

# Run manually (useful for testing)
systemctl --user start cloudflare-ddns.service

# View all timers
systemctl --user list-timers

# Stop the timer
systemctl --user stop cloudflare-ddns.timer

# Disable the timer
systemctl --user disable cloudflare-ddns.timer
```

For more details, see `systemd/README.md`.

## Testing

### Unit Tests

Run the test suite using pytest:

```bash
uv run pytest test_cloudflare_ddns.py -v
```

### Manual Testing

To verify that the DNS update path works correctly, use the included test script:

```bash
uv run test_set_dummy_ip.py
```

This script sets a dummy IP to your DNS records, allowing you to confirm that Cloudflare API updates are functioning properly.

## Running Manually

```bash
./cloudflare_ddns.py

# View logs
journalctl --user -u cloudflare-ddns.service -f

# Control service
systemctl --user start cloudflare-ddns.service
systemctl --user stop cloudflare-ddns.service
systemctl --user restart cloudflare-ddns.service
```

## License

MIT
