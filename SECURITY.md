# Security Policy

## Credential Handling

This tool handles sensitive Cloudflare API credentials. Best practices:

- Store credentials in `.env` file (never commit to git)
- Use scoped API tokens instead of global API keys
- Grant minimum required permissions: Zone > DNS > Edit
- Limit token scope to specific zones when possible

## Reporting Vulnerabilities

If you discover a security vulnerability, please open a GitHub issue.

**Do NOT include sensitive information** (API keys, tokens, zone IDs) in issue reports.
