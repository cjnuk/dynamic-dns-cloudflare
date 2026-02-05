# Systemd Installation

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
