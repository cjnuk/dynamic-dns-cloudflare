# Contributing

Thank you for considering contributing to Cloudflare DDNS Updater!

## Development Setup

1. Clone the repository
2. Install [UV](https://docs.astral.sh/uv/)
3. Copy `.env.example` to `.env` and configure with your Cloudflare credentials

## Running Tests

```bash
uv run pytest test_cloudflare_ddns.py -v
```

## Code Style

This project uses:
- [ruff](https://docs.astral.sh/ruff/) for linting
- [mypy](https://mypy-lang.org/) with strict mode for type checking

Before submitting, ensure your code passes:
```bash
uv tool run ruff check *.py
uv tool run mypy --strict cloudflare_ddns.py
```

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass
5. Submit a pull request

## Reporting Issues

Please use GitHub Issues for bug reports and feature requests.
