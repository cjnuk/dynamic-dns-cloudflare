# Contributing

Thank you for considering contributing to Cloudflare DDNS Updater!

## Development Setup

1. Install [Python 3.12+](https://www.python.org/downloads/) and [UV](https://docs.astral.sh/uv/)
2. Clone the repository
3. Copy `.env.example` to `.env` and configure with your Cloudflare credentials:
   ```bash
   cp .env.example .env
   chmod 600 .env
   ```

## Running Tests

The test script declares its own dependencies (pytest, requests-mock, etc.) inline,
so no separate install step is needed:

```bash
uv run test_cloudflare_ddns.py -v
```

## Code Style

This project uses:
- [ruff](https://docs.astral.sh/ruff/) for linting
- [mypy](https://mypy-lang.org/) with strict mode for type checking

Before submitting, ensure your code passes:
```bash
uv tool run ruff check *.py
uv run --with types-requests --with mypy -- mypy --strict cloudflare_ddns.py
```

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass
5. Submit a pull request

By submitting a pull request, you agree that your contributions will be licensed
under the same [MIT License](LICENSE) that covers this project.

## Reporting Issues

Please use GitHub Issues for bug reports and feature requests.
