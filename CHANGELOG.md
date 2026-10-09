# Changelog

All notable changes to `xss-detection-lab` (`xsslab`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-09

### Added
- **Project Foundation & Configuration**: `pyproject.toml`, `.gitignore`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and runtime settings with environment overrides.
- **Domain Taxonomy & Models**: `XSSCategory`, `ContextType`, `ConfidenceLevel`, `DetectionFinding`, `XSSAuditResult`, `LabSimRequest`, `LabSimResult`, `EncodingRequest`, and `EncodingResult`.
- **HTML Lexer & Execution Context Analyzer**: `HTMLContextAnalyzer` determining whether injection points target HTML body text, tag attributes (quoted/unquoted), JavaScript strings, URI schemes, or style contexts.
- **Multi-Vector XSS Signature Engine**: `XSSSignatureEngine` featuring 14 curated rules covering dangerous HTML tags (`<script>`, `<iframe>`, `<svg>`, `<object>`, `<base>`), event handlers (`onload`, `onerror`, `onclick`), pseudo-protocols (`javascript:`, `data:`), DOM execution sinks (`document.write`, `innerHTML`, `eval`), and credential harvesting gadgets (`document.cookie`, `alert`).
- **Heuristic & Obfuscation Analyzer**: `XSSHeuristicAnalyzer` detecting hex, decimal, and named entity obfuscation, character escape sequences, Shannon entropy, and tag density metrics.
- **Consolidated Detection Engine**: `XSSDetectionEngine` calculating composite risk scores ($0.0 - 100.0$) and categorizing inputs into `CLEAN`, `SUSPICIOUS`, and `MALICIOUS`.
- **Context-Aware Defense & Encoding Engine**: `ContextAwareEncoder` implementing safe context-specific transformations (HTML entity, attribute hex, JavaScript Unicode escape, URI scheme validation) and `CSPPolicyGenerator` crafting strict Content-Security-Policy headers with nonces.
- **Dual-Mode Interactive Simulation Lab**: `LabSimExecutor` and thread-safe in-memory `StoredXSSStorage` executing reflected, stored, and DOM injection patterns side-by-side in vulnerable vs hardened modes.
- **Multi-Format Reporters**: `JSONReporter`, `MarkdownReporter`, `SARIFReporter` conforming to OASIS SARIF v2.1.0 schema, and `ReporterFactory`.
- **Typer & Rich CLI**: `xsslab` CLI tool supporting `audit`, `analyze`, `encode`, `benchmark`, `lab`, and `version` commands with terminal tables and exit codes.
- **FastAPI REST Microservice**: High-performance API endpoints `/health`, `/api/v1/detect`, `/api/v1/sanitize`, `/api/v1/simulate`, `/api/v1/audit/csp`, and `/api/v1/rules`.
- **Production Containerization & CI/CD**: Rootless multi-stage `Dockerfile` (`UID 10001:10001`), `docker-compose.yml`, and GitHub Actions workflow testing Python 3.11 and 3.12.
- **Threat Modeling & Architecture**: Comprehensive STRIDE threat model matrix and architecture specification.
