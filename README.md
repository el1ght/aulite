<div align="center">

<img src="docs/banner.jpg" alt="Aulite — EU AI Act Compliance Proxy" width="100%" />

[![License](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE.md)
[![Tests](https://img.shields.io/badge/tests-108%20passing-brightgreen.svg)]()
[![Docker Pulls](https://img.shields.io/docker/pulls/el1ght/aulite.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/el1ght/aulite)
[![Docker Size](https://img.shields.io/docker/image-size/el1ght/aulite/latest?logo=docker&logoColor=white&label=image)](https://hub.docker.com/r/el1ght/aulite)
[![Node](https://img.shields.io/badge/node-%3E%3D22-339933.svg?logo=node.js&logoColor=white)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6.svg?logo=typescript&logoColor=white)]()
[![GitHub Stars](https://img.shields.io/github/stars/el1ght/aulite?style=flat&logo=github)](https://github.com/el1ght/aulite/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/el1ght/aulite?logo=github)](https://github.com/el1ght/aulite/issues)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/el1ght/aulite?logo=github)](https://github.com/el1ght/aulite/commits/main)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Annex%20III-orange.svg)]()
[![Compliance Rules](https://img.shields.io/badge/compliance%20rules-143-blueviolet.svg)]()
[![Risk Domains](https://img.shields.io/badge/risk%20domains-8-teal.svg)]()
[![Overhead](https://img.shields.io/badge/overhead-%3C5ms-green.svg)]()
[![Self Hosted](https://img.shields.io/badge/self--hosted-yes-blue.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/el1ght/aulite/pulls)

[Documentation](docs/) · [Quick Start](#quick-start) · [Configuration](docs/configuration.md) · [API Reference](docs/api-reference.md)

</div>

---

Aulite is a transparent HTTP proxy that sits between your application and any AI provider. It analyzes every request and response for EU AI Act compliance risks, logs everything into a tamper-proof hash-chained audit trail, and generates legal-grade PDF reports.

Your application changes one URL. Everything else works exactly as before.

<div align="center">
<img src="docs/screenshots/dashboard-overview.png" alt="Dashboard Overview" width="800" />
<br/>
<sub>Compliance Overview — real-time risk monitoring with violation categories and article references</sub>
</div>

```python
client = OpenAI(
    base_url="http://localhost:3000/v1",  # Aulite instead of OpenAI
    api_key="your-aulite-key"
)
```

## Why

The EU AI Act (Regulation 2024/1689) enforcement for high-risk AI systems begins **August 2, 2026**. Non-compliance fines reach **EUR 35M or 7% of global revenue**.

Aulite helps you:

- **Detect** prohibited practices, discrimination, and oversight violations in real time
- **Log** every AI interaction in a tamper-evident audit trail (Art. 12)
- **Report** to regulators with pre-filled FRIA drafts and incident reports (Art. 27, 73)
- **Prove** compliance with hash-chain verification that auditors can independently verify

## Quick Start

```bash
docker run -d \
  -p 3000:3000 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  el1ght/aulite
```

Open `http://localhost:3000` for the dashboard.

<div align="center">
<img src="docs/screenshots/terminal.png" alt="Terminal" width="700" />
</div>

## Features

**Analysis Pipeline**

- 143 keyword rules across all 8 EU AI Act Annex III high-risk categories
- 11 EU-specific PII patterns (IBAN, BSN, NIR, national IDs)
- Context-aware matching — "single-threaded" won't trigger, "is the candidate single?" will
- Optional LLM Judge for deeper semantic analysis
- < 5ms overhead for deterministic checks

**Compliance Domains**

| Domain | Annex III | Rules |
|---|---|---|
| HR & Employment | Point 4 | 33 |
| Finance | Point 5 | 13 |
| Biometrics | Point 1 | 12 |
| Education | Point 3 | 13 |
| Critical Infrastructure | Point 2 | 12 |
| Law Enforcement | Point 6 | 14 |
| Migration & Asylum | Point 7 | 13 |
| Justice | Point 8 | 14 |

Base rules (Art. 5 prohibitions, GDPR Art. 9) are always active.

**Audit Trail**

- SHA-256 hash chain — each entry contains the hash of the previous entry
- Tamper-evident, append-only SQLite with WAL mode
- Verifiable at any time via `/verify` endpoint
- Minimum 6 months retention per Art. 26(6)

**Reports**

- Art. 12 Compliance Audit Report (PDF)
- Art. 27 Fundamental Rights Impact Assessment draft (PDF)
- Art. 72 Post-Market Monitoring Report (PDF)
- Art. 73 Serious Incident Report (PDF)

**Dashboard**

- Real-time compliance overview with risk score trends
- Flagged request browser with detail view
- Compliance page with article violation breakdown
- One-click PDF report generation

**Provider Support**

- OpenAI, Anthropic, Azure OpenAI
- Any OpenAI-compatible API (Ollama, vLLM, LocalAI, llama.cpp)
- Auto-routing by model name — `claude-*` → Anthropic, `gpt-*` → OpenAI
- SSE streaming with zero latency penalty

## Configuration

```yaml
provider:
  default: anthropic

analysis:
  mode: advisory
  domains:
    - hr
    - finance
```

All options can be set via environment variables. See [Configuration docs](docs/configuration.md) for details.

## Architecture

```
Client App  →  Aulite (:3000)  →  AI Provider
                    ↓
              Analysis Pipeline
                    ↓
              SQLite Audit Log
                    ↓
              Dashboard + Reports
```

Self-hosted. Single Docker container. Your data never leaves your infrastructure.

See [Architecture docs](docs/architecture.md) for the full request flow.

## Development

```bash
git clone https://github.com/el1ght/aulite.git
cd aulite
npm install
cd dashboard && npm install && cd ..
npm run dev          # start with hot reload
npm test             # 108 tests
npm run build        # production build
```

## Links

- [Documentation](docs/)
- [Configuration](docs/configuration.md)
- [API Reference](docs/api-reference.md)
- [Providers](docs/providers.md)
- [Self-Hosting](docs/self-hosting.md)
