# gws-inspector

Multi-framework compliance audit tool for Google Workspace environments.

> **Formerly `google-workspaces-audit`.** The original FedRAMP-only scripts are preserved in the [`legacy/`](legacy/) directory.

## Overview

gws-inspector automates security compliance auditing for Google Workspace by querying the Admin SDK, Policy API (GA Feb 2025), Reports API, Alert Center, Chrome Policy, and Cloud Identity APIs.

### Compliance Frameworks (8)

| Framework | Standard | Controls |
|-----------|----------|----------|
| FedRAMP | NIST 800-53 | AC, IA, AU, SC, SI families |
| CMMC 2.0 | NIST 800-171 | AC, IA, AU practices |
| SOC 2 | Trust Services | CC6, CC7 criteria |
| DISA STIG | CIS-mapped | Authentication, logging, access |
| IRAP | ISM + Essential Eight | Australian government |
| ISMAP | ISO 27001 | Japanese government |
| PCI-DSS 4.0.1 | PCI SSC | Requirements 7 & 8 |
| CIS Benchmarks | CIS v1.2.0 | Google Workspace Foundations |

### Security Controls (19 checks)

14-16 automated (up from 6 in the original tool), thanks to the Google Policy API:
- 2SV/MFA enforcement, password policies, session duration, less secure apps, Advanced Protection, SSO
- Super admin count, inactive users, audit logging, Alert Center, OAuth token review
- Group membership, mobile device management, Chrome browser policies
- Manual: SPF/DKIM/DMARC, data regions, DLP rules

## Quick Start

```bash
# Install
pip install -e .
# or with uv
uv sync

# Run with service account (recommended)
gws-inspector -c service-account.json -a admin@example.com -d example.com

# Run with OAuth (development)
gws-inspector -c client_secrets.json --oauth -d example.com

# Run specific frameworks only
gws-inspector -c creds.json -a admin@example.com -d example.com --frameworks fedramp,cmmc,cis

# Environment variables
export GWS_CREDENTIALS_FILE=path/to/credentials.json
export GWS_ADMIN_EMAIL=admin@example.com
export GWS_DOMAIN=example.com
gws-inspector
```

## Prerequisites

- Python 3.12+
- Google Workspace Business or Enterprise
- Google Cloud project with Admin SDK, Reports API, Alert Center API enabled
- Service account with domain-wide delegation OR OAuth client credentials

## Authentication

### Service Account (recommended for production)

1. Create a service account in Google Cloud Console
2. Enable domain-wide delegation in Google Workspace Admin Console
3. Grant required OAuth scopes (see `src/gws_inspector/auth.py` for full list)

### OAuth 2.0 (for development)

1. Create OAuth client credentials (Desktop app type)
2. Run with `--oauth` flag — opens browser for consent on first run

## Architecture

```
src/gws_inspector/
├── auth.py              # Service account + OAuth 2.0
├── client.py            # Multi-service API client (6 Google APIs)
├── collector.py         # Data collection → GWSData (in-memory bus)
├── engine.py            # Orchestrator: collect → analyze → report → archive
├── models.py            # ComplianceFinding, GWSData, typed intermediates
├── output.py            # File I/O, ZIP archiving
├── cli.py               # CLI entry point
├── analyzers/           # 8 framework analyzers (auto-discovered)
│   ├── common.py        # Shared analysis functions
│   ├── fedramp.py, cmmc.py, soc2.py, stig.py
│   ├── irap.py, ismap.py, pci_dss.py
│   └── cis.py           # CIS Google Workspace Benchmark
└── reporters/           # 11 report generators (auto-discovered)
    ├── executive.py     # Executive summary
    ├── matrix.py        # Cross-framework compliance matrix
    └── ...              # Per-framework reports
```

## Legacy

The original FedRAMP-only implementations (Python, Go, JavaScript) are in [`legacy/`](legacy/).

## License

GPL-3.0 — see [COPYING](COPYING)
