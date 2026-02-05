# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Credential Handling

This tool handles sensitive Cloudflare API credentials. Best practices:

- Store credentials in `.env` file (never commit to git)
- Restrict `.env` file permissions: `chmod 600 .env`
- Use scoped API tokens instead of global API keys
- Grant minimum required permissions: Zone > DNS > Edit
- Limit token scope to specific zones when possible

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please use [GitHub's private vulnerability reporting](https://github.com/cjnuk/dynamic-dns-cloudflare/security/advisories/new) to submit a report.

You should receive an initial response within 72 hours. If the issue is confirmed, a fix will be released as soon as possible.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Do NOT include sensitive information** (API keys, tokens, zone IDs) in any reports.
