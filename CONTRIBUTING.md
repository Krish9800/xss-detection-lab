# Contributing to XSS Detection Lab

We welcome contributions to detection signatures, context encoders, and test scenarios.

## Development Setup

```bash
git clone https://github.com/cybersecurity-portfolio/xss-detection-lab.git
cd xss-detection-lab
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality Gates

Before submitting code, ensure all quality gates pass:

```bash
# 1. Run test suite with >=90% coverage
pytest --cov=xsslab --cov-report=term-missing --cov-fail-under=90

# 2. Check formatting and linting
ruff check .
ruff format --check .

# 3. Static type verification
mypy src tests

# 4. Security linting
bandit -r src/
```
