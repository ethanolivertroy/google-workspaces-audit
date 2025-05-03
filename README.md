# Google Workspaces FedRAMP Compliance Audit

![alt text](image.png)

A tool to audit Google Workspace environments for FedRAMP compliance settings, helping organizations verify and maintain their compliance posture.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Available Implementations](#available-implementations)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Authentication Methods](#authentication-methods)
- [Obtaining a Google Workspace Access Token](#obtaining-a-google-workspace-access-token)
- [Usage](#usage)
- [Environment Variables](#environment-variables)
- [Compliance Checks](#compliance-checks)
- [Report Output](#report-output)
- [License](#license)
- [Contributing](#contributing)

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

### Obtaining a Google Workspace Access Token

Google Workspace APIs use the same OAuth2 endpoints as other Google APIs but require Workspace-specific scopes. There are two common ways to obtain access tokens:

1. 3-Legged OAuth (User Consent)
   - Create an OAuth 2.0 Client ID in your GCP project (APIs & Services > Credentials > Create OAuth client ID).
   - Configure the OAuth consent screen with your app details and the required Workspace scopes (e.g., `https://www.googleapis.com/auth/admin.directory.user.readonly`).
   - Redirect users to Google's OAuth 2.0 authorization endpoint asking for these scopes.
   - After approval, exchange the authorization code returned to your redirect URI for an access token and refresh token.
   - Use the access token in `Authorization: Bearer <ACCESS_TOKEN>` headers for API calls.

2. Service Account + Domain-Wide Delegation (Server-to-Server)
   - In your GCP project, enable the Workspace APIs you need.
   - Create a Service Account and download the JSON key file.
   - Enable "Domain-wide Delegation" for the service account and note its client ID.
   - In the Google Workspace Admin console, go to Security > API Controls > Domain-wide Delegation and authorize the client ID for the required scopes.
   - In your code, load and impersonate an admin user to mint tokens. For example (Python):

```python
from google.oauth2 import service_account
from google.auth.transport.requests import Request

SCOPES = ['https://www.googleapis.com/auth/admin.directory.user.readonly']
creds = service_account.Credentials.from_service_account_file(
    'service-account.json',
    scopes=SCOPES,
    subject='admin@your-domain.com'
)
creds.refresh(Request())
token = creds.token
```

Use that token in the `Authorization` header for Workspace API requests.

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

The tool performs the following checks to ensure your Google Workspace environment meets FedRAMP requirements:

- **FedRAMP Authorized Services**: Confirms only FedRAMP-authorized Workspace services (Gmail, Drive, Meet, etc.) are enabled.
- **Data Region Policy**: Verifies Data Regions are restricted to the United States.
- **Assured Controls**: Checks if the Assured Controls add-on is enabled (Enterprise Plus only).
- **Access Transparency**: Verifies Access Transparency is enabled to monitor Google staff access events.
- **Password Policy**: Ensures password settings meet FedRAMP standards (minimum length, complexity, expiration).
- **Two-Step Verification**: Enforces 2-Step Verification across all user accounts.
- **Admin Privileges**: Reviews admin role assignments for least-privilege compliance.
- **Audit Logging**: Checks that audit logs for Admin, Drive, and login activities are enabled.
- **Security Center**: Ensures Security Center is configured and active (Enterprise Plus only).
- **Data Loss Prevention**: Verifies DLP rules are in place in Gmail and Drive.
- **Context-Aware Access**: Confirms context-aware access policies are applied.
- **Endpoint Management**: Ensures endpoint management policies are configured for devices.

## Report Output

The tool generates a comprehensive compliance report with:
- Overall compliance status
- Detailed findings for each control
- Compliance statistics summary
- Specific recommendations for remediation

## License

This project is distributed under the terms of the GNU General Public License v3.0 (GPL-3.0). See the COPYING file for the full license text.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.