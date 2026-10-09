# XSS Detection Lab (`xsslab`)

[![CI](https://img.shields.io/badge/CI-Passing-brightgreen.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Coverage](https://img.shields.io/badge/Coverage-97%25-brightgreen.svg)](#)
[![Type Checked](https://img.shields.io/badge/Mypy-Strict-blue.svg)](https://mypy-lang.org/)
[![Linted](https://img.shields.io/badge/Ruff-Compliant-blueviolet.svg)](https://astral.sh/ruff)
[![Security](https://img.shields.io/badge/Bandit-Passed-brightgreen.svg)](https://bandit.readthedocs.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Enterprise-Grade Cross-Site Scripting (XSS, CWE-79) Detection Engine, Context-Aware Defensive Encoder, and Dual-Mode Simulation Laboratory.

---

## 1. Overview & Problem Statement

Cross-Site Scripting (XSS, CWE-79) remains one of the most persistent vulnerabilities in modern web applications and APIs. Attackers inject executable scripts into trusted applications to hijack user sessions, exfiltrate sensitive data, manipulate the DOM, or pivot to remote code execution in desktop/Electron environments.

Traditional defense solutions rely on naive blacklist string filtering (such as stripping `<script>`), which fails against modern evasion techniques, such as event handlers, SVG/XML vectors, pseudo-protocols (`javascript:`), and entity obfuscations (`&#x3C;`, `&#106;`).

`xsslab` provides an all-in-one detection, defense, and educational research platform featuring:
- **Lexical Execution Context Analysis**: Determines whether input lands in HTML body text, tag attributes, JavaScript string literals, URI schemes, or style blocks.
- **Multi-Vector Signature Scanning**: 14 curated rules covering dangerous tags, event handlers, pseudo-protocols, script breakouts, and credential harvesting gadgets.
- **Heuristic & Obfuscation Analysis**: Calculates entity density, Unicode/hex character escapes, script-tag density anomalies, and Shannon entropy.
- **Context-Aware Output Encoding**: Mathematically sound context-specific encoding and strict Content Security Policy (CSP) generator with nonce support.
- **Dual-Mode Defensive Simulation Lab**: Contrasts vulnerable vs hardened implementations across Reflected, Stored, and DOM injection vectors.
- **Multi-Format Reporting**: Generates OASIS SARIF v2.1.0 (for GitHub Code Scanning), structured JSON, and GitHub Flavored Markdown reports.
- **Rich Typer CLI & FastAPI Microservice**: Full-featured CLI and OpenAPI-compliant REST API.

---

## 2. Architecture & Components

```
                    ┌─────────────────────────────────────────┐
                    │        Untrusted Input / Payload        │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │      HTML Context Analyzer (Lexer)      │
                    │   (HTML Body, Attribute, JS, URI, Style)│
                    └────────────────────┬────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
┌────────▼──────────────┐   ┌────────────▼──────────────┐   ┌────────────▼──────────────┐
│  XSS Signature Engine │   │   Heuristic Analyzer      │   │ Context-Aware Encoder     │
│  - Dangerous Tags     │   │   - Entity Obfuscation    │   │ - HTML Entity             │
│  - Event Handlers     │   │   - Unicode / Hex Escapes │   │ - Attribute Hex Entity    │
│  - Pseudo-Protocols   │   │   - Tag Density           │   │ - JS Unicode Escape       │
│  - DOM Sinks & Gadgets│   │   - Shannon Entropy       │   │ - URI Scheme Validation   │
└────────┬──────────────┘   └────────────┬──────────────┘   └────────────┬──────────────┘
         │                               │                               │
         └───────────────────────────────┼───────────────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │       Consolidated Risk Evaluator       │
                    │      (Risk Score: 0.0 - 100.0)          │
                    └────────────────────┬────────────────────┘
                                         │
         ┌───────────────────────────────┴───────────────────────────────┐
         │                                                               │
┌────────▼──────────────────────────────┐       ┌────────────────────────▼──────────────────────┐
│       Dual-Mode Simulation Lab        │       │             Reporting & Interfaces            │
│  - Reflected: Raw vs Encoded          │       │  - Typer CLI (`xsslab audit / analyze`)       │
│  - Stored: In-memory Guestbook        │       │  - FastAPI REST Microservice (`/api/v1/...`)  │
│  - DOM: innerHTML vs textContent      │       │  - SARIF v2.1.0 / JSON / Markdown Reporters   │
└───────────────────────────────────────┘       └───────────────────────────────────────────────┘
```

---

## 3. Quickstart & Installation

### Requirements
- Python 3.11 or 3.12
- Linux / macOS / WSL

### Local Installation
```bash
# Clone the repository
git clone https://github.com/cybersecurity-portfolio/xss-detection-lab.git
cd xss-detection-lab

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## 4. Command Line Interface (CLI)

The `xsslab` CLI provides commands for auditing payloads, batch analysis, safe encoding, benchmarking, and interactive lab execution:

### 1. Audit Single Payload
```bash
# Terminal table output with risk score and detected triggers
xsslab audit "<script>alert(document.cookie)</script>"

# Export as OASIS SARIF v2.1.0 for GitHub Code Scanning
xsslab audit "<img src=x onerror=alert(1)>" --format sarif --output audit.sarif

# Export as Markdown report
xsslab audit "javascript:alert(1)" --format markdown --output report.md
```

### 2. Batch File Analysis
```bash
# Analyze a list of payloads line by line
xsslab analyze payloads.txt --format table
```

### 3. Context-Aware Encoding
```bash
# Encode for HTML body
xsslab encode "<script>alert(1)</script>" --context html

# Encode for HTML attribute
xsslab encode "foo\" onfocus=\"alert(1)" --context attr

# Encode for JavaScript string literal
xsslab encode "'; alert(1); //" --context js
```

### 4. Run Detection Benchmark
```bash
# Evaluate True Positives, True Negatives, Precision, Recall, and Latency
xsslab benchmark
```

### 5. Interactive Defensive Lab
```bash
# Insecure reflected mode (vulnerable)
xsslab lab "<script>alert(1)</script>" --mode insecure --type reflected

# Hardened reflected mode (neutralized)
xsslab lab "<script>alert(1)</script>" --mode hardened --type reflected

# DOM sink simulation (innerHTML vs textContent)
xsslab lab "<h1>Injected</h1>" --mode hardened --type dom
```

---

## 5. REST API Microservice

Launch the FastAPI microservice:
```bash
uvicorn xsslab.api.app:app --host 127.0.0.1 --port 8081 --reload
```
Interactive OpenAPI documentation is available at `http://127.0.0.1:8081/docs`.

### API Endpoints:
- `GET /health`: Health status and application version.
- `POST /api/v1/detect`: Inspect untrusted input for XSS vectors with composite risk scoring.
- `POST /api/v1/sanitize`: Context-aware encoding (HTML body, attributes, JS strings, URIs).
- `POST /api/v1/simulate`: Simulate execution across reflected, stored, or DOM sinks.
- `POST /api/v1/audit/csp`: Audit Content Security Policy headers for unsafe directives.
- `GET /api/v1/rules`: List all registered detection rules and CWE taxonomy.

---

## 6. Docker Deployment

A rootless, multi-stage production Docker image (`UID 10001:10001`) is included:

```bash
# Build and run with docker-compose
docker compose up -d

# Check service health
curl http://localhost:8081/health
```

---

## 7. Verification & Quality Assurance

This codebase enforces strict quality gates:
```bash
# Run unit and integration test suite with coverage gate (>= 90%)
pytest --cov=xsslab --cov-report=term-missing --cov-fail-under=90

# Static type checking (100% strict)
mypy src tests

# Code style and formatting (PEP 8, line length <= 100)
ruff check .
ruff format --check .

# SAST security vulnerability scan
bandit -r src/ -c pyproject.toml
```

---

## 8. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
