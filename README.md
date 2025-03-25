# Google Workspaces FedRAMP Compliance Audit

A tool to audit Google Workspace environments for FedRAMP compliance settings, helping organizations verify and maintain their compliance posture.

## Overview

This project provides scripts to check Google Workspace environments against FedRAMP compliance requirements. It uses the Google Workspace Admin SDK APIs to automate compliance verification across multiple security controls.

## Features

- Comprehensive checks based on official FedRAMP compliance requirements
- Verifies compliance across 12 critical security controls
- Generates detailed compliance reports with remediation recommendations
- Available in multiple languages (JavaScript, Python, and Go)
- Multiple authentication methods (OAuth, Service Account, Secret Managers, and more)

## Available Implementations

- `fedramp-compliance-check.js` - JavaScript implementation
- `fedramp_check.py` - Python implementation
- `fedramp_check.go` - Go implementation

## Prerequisites

- Google Workspace Enterprise or Business account with admin privileges
- Google Cloud project with Admin SDK APIs enabled
- OAuth 2.0 client credentials configured for API access

## Installation

### JavaScript Version
```bash
npm install googleapis
```

### Python Version
```bash
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib

# Optional dependencies for additional auth methods
pip install pyyaml  # For YAML config support
pip install boto3  # For AWS Secrets Manager support
pip install google-cloud-secret-manager  # For GCP Secret Manager support
pip install hvac  # For HashiCorp Vault support
```

### Go Version
```bash
go mod init google-workspaces-audit
go get -u golang.org/x/oauth2
go get -u google.golang.org/api/admin/directory/v1
go get -u google.golang.org/api/reports/v1
```

## Authentication Methods

Both Python and Go implementations support multiple authentication methods:

1. **OAuth 2.0** (Default)
   - Requires `credentials.json` file from Google Cloud Console
   - Stored token for repeated access

2. **Service Account**
   - With domain-wide delegation
   - Can provide JSON file or content via environment variable
   - Requires admin email for delegation

3. **Environment Variables**
   - Store credentials paths in environment variables
   - More secure than hardcoding paths

4. **Interactive Mode**
   - Prompt for credentials at runtime
   - No stored credentials on disk

5. **Configuration Files**
   - JSON or YAML (Python only) configuration
   - Load settings from file

6. **Google Cloud Secret Manager**
   - Retrieve credentials from GCP Secret Manager
   - Secure storage for sensitive information

7. **AWS Secrets Manager**
   - Retrieve credentials from AWS Secrets Manager
   - Works with existing AWS infrastructure

8. **HashiCorp Vault**
   - Retrieve credentials from Vault
   - Integration with enterprise secret management

## Usage

### JavaScript Version
```bash
node fedramp-compliance-check.js
```

### Python Version

Basic usage:
```bash
python fedramp_check.py
```

With command line options:
```bash
python fedramp_check.py --credentials-path /path/to/credentials.json --report-path /path/to/report.json

# Using service account
python fedramp_check.py --service-account /path/to/service-account.json --admin-email admin@domain.com

# Interactive mode
python fedramp_check.py --interactive 

# Using GCP Secret Manager
python fedramp_check.py --auth-method gcp_secret --gcp-secret-credentials project-id/secret-name

# Using config file
python fedramp_check.py --config-file /path/to/config.yaml
```

### Go Version

Basic usage:
```bash
go run fedramp_check.go
```

With command line options:
```bash
go run fedramp_check.go -credentials /path/to/credentials.json -report /path/to/report.json

# Using service account
go run fedramp_check.go -service-account /path/to/service-account.json -admin-email admin@domain.com

# Interactive mode
go run fedramp_check.go -interactive

# Using config file
go run fedramp_check.go -config /path/to/config.json
```

## Environment Variables

Both implementations support these environment variables:

- `GOOGLE_APPLICATION_CREDENTIALS`: Path to OAuth or Service Account credentials file
- `GOOGLE_WORKSPACE_TOKEN_PATH`: Path to OAuth token file
- `FEDRAMP_REPORT_PATH`: Path where report will be saved
- `GOOGLE_SERVICE_ACCOUNT_JSON`: Service account JSON content
- `GOOGLE_ADMIN_EMAIL`: Admin email for service account delegation
- `FEDRAMP_AUTH_METHOD`: Authentication method to use
- `GCP_PROJECT_ID`: GCP project ID for Secret Manager
- `GCP_SECRET_CREDENTIALS`: Secret name for GCP Secret Manager
- `AWS_SECRET_NAME`: Secret name for AWS Secrets Manager
- `AWS_REGION`: AWS region for Secrets Manager
- `VAULT_ADDR`: HashiCorp Vault address
- `VAULT_TOKEN`: HashiCorp Vault token
- `VAULT_SECRET_PATH`: Secret path for HashiCorp Vault

## Compliance Checks

The tool verifies compliance across these security controls:

1. FedRAMP Authorized Services
2. Data Region Policy
3. Assured Controls
4. Access Transparency
5. Password Policy
6. Two-Step Verification
7. Admin Privileges
8. Audit Logging
9. Security Center
10. Data Loss Prevention
11. Context-Aware Access
12. Endpoint Management

## Report Output

The tool generates a comprehensive compliance report with:
- Overall compliance status
- Detailed findings for each control
- Compliance statistics summary
- Specific recommendations for remediation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.