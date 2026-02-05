# Systemd Installation

## Path Configuration

The service file uses `%h` as a systemd specifier that expands to your user's home directory. This makes the configuration portable across different users and installations.

- `%h` = Your home directory (e.g., `/home/username`)
- The service expects:
  - `uv` binary at: `%h/.local/bin/uv`
  - Script at: `%h/dynamic-dns-cloudflare/cloudflare_ddns.py`
  - Working directory: `%h/dynamic-dns-cloudflare`

If you installed the project in a different location, edit `cloudflare-ddns.service` and update the paths accordingly.

### Finding Your `uv` Installation

Verify where `uv` is installed:
```bash
which uv
```

If `uv` is not at `~/.local/bin/uv`, update the `ExecStart` path in `cloudflare-ddns.service` to match your installation location.

## Install as User Service (recommended)

1. Enable lingering for your user (allows services to run without login):
   ```bash
   sudo loginctl enable-linger $USER
   ```

2. Create user systemd directory and copy files:
   ```bash
   mkdir -p ~/.config/systemd/user/
   cp cloudflare-ddns.service ~/.config/systemd/user/
   cp cloudflare-ddns.timer ~/.config/systemd/user/
   ```

3. Reload systemd and enable timer:
   ```bash
   systemctl --user daemon-reload
   systemctl --user enable cloudflare-ddns.timer
   systemctl --user start cloudflare-ddns.timer
   ```

## Useful Commands

```bash
# Check timer status
systemctl --user status cloudflare-ddns.timer

# Check service status (last run)
systemctl --user status cloudflare-ddns.service

# View logs
journalctl --user -u cloudflare-ddns.service -f

# Run manually
systemctl --user start cloudflare-ddns.service

# List timers
systemctl --user list-timers
```
