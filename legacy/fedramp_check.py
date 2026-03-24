#!/usr/bin/env python3
"""
Google Workspace FedRAMP Compliance Checker

This script uses the Google Workspace Admin SDK APIs to verify FedRAMP compliance settings
across your Google Workspace environment. It's based on the official FedRAMP compliance
requirements from Google Cloud.

Reference: https://cloud.google.com/security/compliance/fedramp
"""

import argparse
import getpass
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Union

from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Try to import optional dependencies
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import boto3
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from google.cloud import secretmanager
    GCP_SECRET_MANAGER_AVAILABLE = True
except ImportError:
    GCP_SECRET_MANAGER_AVAILABLE = False

try:
    import hvac
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

# Default configuration
DEFAULT_CONFIG = {
    "credentials_path": "./credentials.json",
    "token_path": "./token.json",
    "report_output_path": "./fedramp-compliance-report.json",
    "config_file_path": "./fedramp_config.yaml",
    "scopes": [
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.domain.readonly",
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
        "https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly",
        "https://www.googleapis.com/auth/admin.directory.customer.readonly",
        "https://www.googleapis.com/auth/apps.licensing"
    ]
}

# Environment variable names
ENV_VAR_CREDENTIALS_PATH = "GOOGLE_APPLICATION_CREDENTIALS"
ENV_VAR_TOKEN_PATH = "GOOGLE_WORKSPACE_TOKEN_PATH"
ENV_VAR_CONFIG_PATH = "FEDRAMP_CONFIG_PATH"
ENV_VAR_REPORT_PATH = "FEDRAMP_REPORT_PATH"
ENV_VAR_SERVICE_ACCOUNT = "GOOGLE_SERVICE_ACCOUNT_JSON"
ENV_VAR_GCP_PROJECT = "GCP_PROJECT_ID"
ENV_VAR_GCP_SECRET_CREDS = "GCP_SECRET_CREDENTIALS"
ENV_VAR_GCP_SECRET_TOKEN = "GCP_SECRET_TOKEN"
ENV_VAR_AWS_SECRET_NAME = "AWS_SECRET_NAME"
ENV_VAR_VAULT_ADDR = "VAULT_ADDR"
ENV_VAR_VAULT_TOKEN = "VAULT_TOKEN"
ENV_VAR_VAULT_PATH = "VAULT_SECRET_PATH"

# FedRAMP authorized services for Workspace
FEDRAMP_AUTHORIZED_SERVICES = [
    "Gmail",
    "Calendar",
    "Drive and Docs",
    "Meet",
    "Chat",
    "Google Voice",
    "Classroom",
    "Keep",
    "Groups for Business",
    "Google Cloud Search",
    "Sites",
    "Vault",
    "Security Center"
]

# Define FedRAMP compliance checks
FEDRAMP_CHECKS = [
    {
        "id": "fedramp-authorized-services",
        "name": "FedRAMP Authorized Services",
        "description": "Check if only FedRAMP authorized services are enabled for users within FedRAMP boundary",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "In Admin Console, navigate to Apps > Google Workspace > Services. Ensure only FedRAMP authorized services are enabled."
    },
    {
        "id": "data-region-policy",
        "name": "Data Region Policy",
        "description": "Verify data region policy is set to United States for FedRAMP compliance",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "In Admin Console, go to Account > Settings > Data Regions and set the policy to United States."
    },
    {
        "id": "assured-controls",
        "name": "Assured Controls",
        "description": "Check if Assured Controls add-on is enabled (Enterprise Plus only)",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Purchase and enable the Assured Controls add-on for your Google Workspace Enterprise Plus subscription."
    },
    {
        "id": "access-transparency",
        "name": "Access Transparency",
        "description": "Verify that Access Transparency is enabled to monitor Google staff actions",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Go to Security > Access Transparency in Admin Console and enable this feature."
    },
    {
        "id": "password-policy",
        "name": "Password Policy",
        "description": "Check if password policy meets FedRAMP requirements (minimum 12 chars, complexity, etc.)",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Navigate to Security > Password management in Admin Console and update settings to require minimum 12 characters, complexity, and 60-day expiration."
    },
    {
        "id": "two-step-verification",
        "name": "Two-Step Verification",
        "description": "Verify 2-Step Verification is enforced for all users",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Go to Security > 2-Step Verification in Admin Console and enforce for all users."
    },
    {
        "id": "admin-privileges",
        "name": "Admin Privileges",
        "description": "Check if admin privileges follow the principle of least privilege",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Review admin role assignments in Admin > Account > Admin roles and ensure only necessary privileges are assigned."
    },
    {
        "id": "audit-logging",
        "name": "Audit Logging",
        "description": "Verify comprehensive audit logging is enabled for monitoring",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Configure audit logging in Admin > Security > Audit and investigation tools."
    },
    {
        "id": "security-center",
        "name": "Security Center",
        "description": "Check if Security Center is configured (Enterprise Plus only)",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "If using Enterprise Plus, go to Security > Security Center and ensure it is properly configured."
    },
    {
        "id": "data-loss-prevention",
        "name": "Data Loss Prevention",
        "description": "Check if DLP policies are configured to prevent data leakage",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Set up DLP policies in Security > Data protection to prevent accidental data leakage of sensitive information."
    },
    {
        "id": "context-aware-access",
        "name": "Context-Aware Access",
        "description": "Verify context-aware access policies are in place to restrict access based on context (Enterprise Plus)",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Configure context-aware access in Security > Access and data control > Context-Aware Access."
    },
    {
        "id": "endpoint-management",
        "name": "Endpoint Management",
        "description": "Check if endpoint management is configured for devices",
        "status": "Not Checked",
        "details": "",
        "fix_steps": "Set up endpoint management in Devices > Mobile & endpoints."
    }
]


def parse_arguments() -> Dict[str, Any]:
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(description="Google Workspace FedRAMP Compliance Checker")
    parser.add_argument(
        "--credentials-path", 
        help="Path to OAuth credentials JSON file"
    )
    parser.add_argument(
        "--token-path", 
        help="Path to OAuth token JSON file"
    )
    parser.add_argument(
        "--report-path", 
        help="Path where compliance report will be saved"
    )
    parser.add_argument(
        "--config-file", 
        help="Path to configuration file (YAML or JSON)"
    )
    parser.add_argument(
        "--service-account", 
        help="Path to service account JSON file"
    )
    parser.add_argument(
        "--gcp-secret-credentials", 
        help="GCP Secret Manager path for credentials (project/secret/version)"
    )
    parser.add_argument(
        "--aws-secret-name", 
        help="AWS Secrets Manager secret name"
    )
    parser.add_argument(
        "--vault-path", 
        help="HashiCorp Vault path for credentials"
    )
    parser.add_argument(
        "--admin-email", 
        help="Admin email (required for service account domain-wide delegation)"
    )
    parser.add_argument(
        "--interactive", 
        action="store_true", 
        help="Interactive mode - prompt for credentials"
    )
    parser.add_argument(
        "--auth-method", 
        choices=[
            "oauth", 
            "service_account", 
            "gcp_secret", 
            "aws_secret", 
            "vault", 
            "interactive", 
            "env_vars"
        ],
        help="Authentication method to use"
    )
    
    return vars(parser.parse_args())


def load_config_from_file(file_path: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML or JSON file
    """
    if not os.path.exists(file_path):
        print(f"Config file {file_path} not found")
        return {}
    
    try:
        if file_path.endswith(".yaml") or file_path.endswith(".yml"):
            if not YAML_AVAILABLE:
                print("YAML support requires PyYAML. Install with: pip install pyyaml")
                return {}
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            with open(file_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading config file: {e}")
        return {}


def get_secret_from_gcp(secret_name: str) -> Optional[str]:
    """
    Retrieve a secret from Google Cloud Secret Manager
    Format: project_id/secret_id/version_id
    """
    if not GCP_SECRET_MANAGER_AVAILABLE:
        print("GCP Secret Manager support requires google-cloud-secret-manager. Install with: pip install google-cloud-secret-manager")
        return None
    
    try:
        parts = secret_name.split('/')
        if len(parts) < 2:
            print(f"Invalid GCP secret format. Expected: project_id/secret_id[/version_id]")
            return None
            
        project_id = parts[0]
        secret_id = parts[1]
        version_id = parts[2] if len(parts) > 2 else "latest"
        
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        print(f"Error accessing GCP Secret Manager: {e}")
        return None


def get_secret_from_aws(secret_name: str) -> Optional[str]:
    """
    Retrieve a secret from AWS Secrets Manager
    """
    if not AWS_AVAILABLE:
        print("AWS Secrets Manager support requires boto3. Install with: pip install boto3")
        return None
    
    try:
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager')
        response = client.get_secret_value(SecretId=secret_name)
        if 'SecretString' in response:
            return response['SecretString']
        return None
    except Exception as e:
        print(f"Error accessing AWS Secrets Manager: {e}")
        return None


def get_secret_from_vault(path: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a secret from HashiCorp Vault
    """
    if not VAULT_AVAILABLE:
        print("HashiCorp Vault support requires hvac. Install with: pip install hvac")
        return None
    
    try:
        vault_addr = os.environ.get(ENV_VAR_VAULT_ADDR)
        vault_token = os.environ.get(ENV_VAR_VAULT_TOKEN)
        
        if not vault_addr or not vault_token:
            print("VAULT_ADDR and VAULT_TOKEN environment variables are required")
            return None
            
        client = hvac.Client(url=vault_addr, token=vault_token)
        response = client.secrets.kv.v2.read_secret_version(path=path)
        return response['data']['data']
    except Exception as e:
        print(f"Error accessing HashiCorp Vault: {e}")
        return None


def get_config_from_sources(cli_args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Load configuration from various sources in priority order:
    1. Command line arguments
    2. Environment variables
    3. Config file
    4. Default values
    """
    config = DEFAULT_CONFIG.copy()
    
    # Check for config file (from CLI or env var)
    config_file_path = cli_args.get('config_file') or os.environ.get(ENV_VAR_CONFIG_PATH) or config["config_file_path"]
    if os.path.exists(config_file_path):
        file_config = load_config_from_file(config_file_path)
        if file_config:
            config.update(file_config)
    
    # Override with environment variables
    if os.environ.get(ENV_VAR_CREDENTIALS_PATH):
        config["credentials_path"] = os.environ.get(ENV_VAR_CREDENTIALS_PATH)
    if os.environ.get(ENV_VAR_TOKEN_PATH):
        config["token_path"] = os.environ.get(ENV_VAR_TOKEN_PATH)
    if os.environ.get(ENV_VAR_REPORT_PATH):
        config["report_output_path"] = os.environ.get(ENV_VAR_REPORT_PATH)
    
    # Override with CLI arguments (if provided)
    if cli_args.get('credentials_path'):
        config["credentials_path"] = cli_args.get('credentials_path')
    if cli_args.get('token_path'):
        config["token_path"] = cli_args.get('token_path')
    if cli_args.get('report_path'):
        config["report_output_path"] = cli_args.get('report_path')
    if cli_args.get('admin_email'):
        config["admin_email"] = cli_args.get('admin_email')
    
    # Handle auth method selection
    if cli_args.get('auth_method'):
        config["auth_method"] = cli_args.get('auth_method')
    elif cli_args.get('interactive'):
        config["auth_method"] = "interactive"
    elif cli_args.get('service_account'):
        config["auth_method"] = "service_account"
        config["service_account_path"] = cli_args.get('service_account')
    elif cli_args.get('gcp_secret_credentials'):
        config["auth_method"] = "gcp_secret"
        config["gcp_secret_credentials"] = cli_args.get('gcp_secret_credentials')
    elif cli_args.get('aws_secret_name'):
        config["auth_method"] = "aws_secret"
        config["aws_secret_name"] = cli_args.get('aws_secret_name')
    elif cli_args.get('vault_path'):
        config["auth_method"] = "vault"
        config["vault_path"] = cli_args.get('vault_path')
    elif os.environ.get(ENV_VAR_SERVICE_ACCOUNT):
        config["auth_method"] = "service_account"
        config["service_account_json"] = os.environ.get(ENV_VAR_SERVICE_ACCOUNT)
    elif os.environ.get(ENV_VAR_GCP_SECRET_CREDS):
        config["auth_method"] = "gcp_secret"
        config["gcp_secret_credentials"] = os.environ.get(ENV_VAR_GCP_SECRET_CREDS)
    elif os.environ.get(ENV_VAR_AWS_SECRET_NAME):
        config["auth_method"] = "aws_secret"
        config["aws_secret_name"] = os.environ.get(ENV_VAR_AWS_SECRET_NAME)
    elif os.environ.get(ENV_VAR_VAULT_PATH):
        config["auth_method"] = "vault"
        config["vault_path"] = os.environ.get(ENV_VAR_VAULT_PATH)
    else:
        config["auth_method"] = "oauth"
    
    return config


def get_auth_from_interactive() -> Credentials:
    """
    Get authentication credentials interactively
    """
    print("Interactive Authentication Mode")
    print("==============================")
    
    auth_type = input("Select authentication type (oauth, service_account): ").strip().lower()
    
    if auth_type == "oauth":
        client_id = getpass.getpass("Enter OAuth Client ID: ")
        client_secret = getpass.getpass("Enter OAuth Client Secret: ")
        
        flow = InstalledAppFlow.from_client_config(
            {
                "installed": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            DEFAULT_CONFIG["scopes"]
        )
        return flow.run_local_server(port=0)
    elif auth_type == "service_account":
        service_account_info = json.loads(getpass.getpass("Enter service account JSON (as single line): "))
        admin_email = input("Enter admin email for domain-wide delegation: ")
        
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info, 
            scopes=DEFAULT_CONFIG["scopes"]
        )
        delegated_credentials = credentials.with_subject(admin_email)
        return delegated_credentials
    else:
        print(f"Unknown authentication type: {auth_type}")
        sys.exit(1)


def get_auth(config: Dict[str, Any]) -> Credentials:
    """
    Authenticate with Google API using the configured method
    """
    auth_method = config.get("auth_method", "oauth")
    print(f"Using authentication method: {auth_method}")
    
    if auth_method == "interactive":
        return get_auth_from_interactive()
    
    elif auth_method == "service_account":
        try:
            # Check if we have the JSON directly in an environment variable
            if "service_account_json" in config:
                service_account_info = json.loads(config["service_account_json"])
            # Otherwise, load from file
            elif "service_account_path" in config:
                with open(config["service_account_path"], 'r') as f:
                    service_account_info = json.load(f)
            else:
                print("Service account authentication requires either service_account_path or service_account_json")
                sys.exit(1)
            
            admin_email = config.get("admin_email")
            if not admin_email:
                print("Admin email is required for service account domain-wide delegation")
                sys.exit(1)
                
            credentials = service_account.Credentials.from_service_account_info(
                service_account_info, 
                scopes=config["scopes"]
            )
            delegated_credentials = credentials.with_subject(admin_email)
            return delegated_credentials
        except Exception as e:
            print(f"Error with service account authentication: {e}")
            sys.exit(1)
    
    elif auth_method == "gcp_secret":
        try:
            secret_name = config.get("gcp_secret_credentials")
            if not secret_name:
                print("GCP Secret Manager authentication requires gcp_secret_credentials")
                sys.exit(1)
                
            secret_content = get_secret_from_gcp(secret_name)
            if not secret_content:
                print("Failed to retrieve credentials from GCP Secret Manager")
                sys.exit(1)
                
            credentials_data = json.loads(secret_content)
            
            # Check if it's a service account or OAuth credentials
            if "type" in credentials_data and credentials_data["type"] == "service_account":
                admin_email = config.get("admin_email")
                if not admin_email:
                    print("Admin email is required for service account domain-wide delegation")
                    sys.exit(1)
                    
                credentials = service_account.Credentials.from_service_account_info(
                    credentials_data, 
                    scopes=config["scopes"]
                )
                return credentials.with_subject(admin_email)
            else:
                # Handle as OAuth credentials
                token_secret = config.get("gcp_secret_token")
                if token_secret:
                    token_data = get_secret_from_gcp(token_secret)
                    if token_data:
                        token_info = json.loads(token_data)
                        return Credentials.from_authorized_user_info(token_info, config["scopes"])
                
                # If no token or token retrieval failed, use credential flow
                flow = InstalledAppFlow.from_client_config(
                    {"installed": credentials_data},
                    config["scopes"]
                )
                credentials = flow.run_local_server(port=0)
                
                # Save token if path provided
                if "gcp_secret_token" in config:
                    token_secret = config["gcp_secret_token"]
                    token_data = credentials.to_json()
                    # Here you would need to implement saving back to GCP Secret Manager
                
                return credentials
        except Exception as e:
            print(f"Error with GCP Secret Manager authentication: {e}")
            sys.exit(1)
    
    elif auth_method == "aws_secret":
        try:
            secret_name = config.get("aws_secret_name")
            if not secret_name:
                print("AWS Secrets Manager authentication requires aws_secret_name")
                sys.exit(1)
                
            secret_content = get_secret_from_aws(secret_name)
            if not secret_content:
                print("Failed to retrieve credentials from AWS Secrets Manager")
                sys.exit(1)
                
            credentials_data = json.loads(secret_content)
            
            # Check if it's a service account or OAuth credentials
            if "type" in credentials_data and credentials_data["type"] == "service_account":
                admin_email = config.get("admin_email")
                if not admin_email:
                    print("Admin email is required for service account domain-wide delegation")
                    sys.exit(1)
                    
                credentials = service_account.Credentials.from_service_account_info(
                    credentials_data, 
                    scopes=config["scopes"]
                )
                return credentials.with_subject(admin_email)
            else:
                # Handle as OAuth credentials or token
                if "refresh_token" in credentials_data:
                    return Credentials.from_authorized_user_info(credentials_data, config["scopes"])
                else:
                    flow = InstalledAppFlow.from_client_config(
                        {"installed": credentials_data},
                        config["scopes"]
                    )
                    return flow.run_local_server(port=0)
        except Exception as e:
            print(f"Error with AWS Secrets Manager authentication: {e}")
            sys.exit(1)
    
    elif auth_method == "vault":
        try:
            vault_path = config.get("vault_path")
            if not vault_path:
                print("HashiCorp Vault authentication requires vault_path")
                sys.exit(1)
                
            secret_content = get_secret_from_vault(vault_path)
            if not secret_content:
                print("Failed to retrieve credentials from HashiCorp Vault")
                sys.exit(1)
                
            # Handle different credential types based on the data structure in Vault
            if "credentials" in secret_content:
                credentials_data = json.loads(secret_content["credentials"])
            else:
                credentials_data = secret_content
                
            # Check if it's a service account or OAuth credentials
            if "type" in credentials_data and credentials_data["type"] == "service_account":
                admin_email = config.get("admin_email") or secret_content.get("admin_email")
                if not admin_email:
                    print("Admin email is required for service account domain-wide delegation")
                    sys.exit(1)
                    
                credentials = service_account.Credentials.from_service_account_info(
                    credentials_data, 
                    scopes=config["scopes"]
                )
                return credentials.with_subject(admin_email)
            elif "refresh_token" in credentials_data:
                return Credentials.from_authorized_user_info(credentials_data, config["scopes"])
            else:
                flow = InstalledAppFlow.from_client_config(
                    {"installed": credentials_data},
                    config["scopes"]
                )
                return flow.run_local_server(port=0)
        except Exception as e:
            print(f"Error with Vault authentication: {e}")
            sys.exit(1)
                
    # Default OAuth flow (also used as fallback)
    else:  # auth_method == "oauth"
        creds = None
        token_path = config.get("token_path")
        
        if token_path and os.path.exists(token_path):
            try:
                creds = Credentials.from_authorized_user_info(
                    json.load(open(token_path)), config["scopes"]
                )
            except Exception as e:
                print(f"Error loading token file: {e}")
        
        # If there are no valid credentials, let the user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                credentials_path = config.get("credentials_path")
                if not os.path.exists(credentials_path):
                    print(f"Credentials file not found: {credentials_path}")
                    sys.exit(1)
                    
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_path, config["scopes"]
                )
                creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            if token_path:
                with open(token_path, 'w') as token:
                    token.write(creds.to_json())
        
        return creds


def check_authorized_services(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check if only FedRAMP authorized services are enabled
    """
    print("Checking FedRAMP Authorized Services...")
    
    try:
        # This would require the Service Management API
        # In a real implementation, you'd fetch all enabled services and compare against the authorized list
        
        # Since direct API for this is not available for Workspace, we provide manual validation guidance
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "fedramp-authorized-services")
        report["checks"][check_index]["status"] = "Not Checked"
        report["checks"][check_index]["details"] = (
            "Manual verification required. Please check Admin Console > Apps > Google Workspace > "
            "Services and ensure only FedRAMP authorized services are enabled for users in FedRAMP boundary."
            f"\n\nFedRAMP authorized services for Google Workspace include: {', '.join(FEDRAMP_AUTHORIZED_SERVICES)}"
        )
        
        # Don't update summary as this requires manual verification
    except Exception as e:
        print(f"Error checking authorized services: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "fedramp-authorized-services")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_data_region_policy(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check data region policy setting
    """
    print("Checking Data Region Policy...")
    
    try:
        # Currently, there is no direct API to check data region policy settings
        # This would require manual verification in the Admin Console
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "data-region-policy")
        report["checks"][check_index]["status"] = "Not Checked"
        report["checks"][check_index]["details"] = (
            "Manual verification required. For FedRAMP compliance, data region should be set to United States. "
            "Check in Admin Console > Account > Settings > Data Regions."
        )
        
        # Don't update summary as this requires manual verification
    except Exception as e:
        print(f"Error checking data region policy: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "data-region-policy")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_assured_controls(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check for Assured Controls add-on
    """
    print("Checking Assured Controls...")
    
    try:
        # This would require checking licensing information through the Licensing API
        # Unfortunately, direct API access to check for this add-on is limited
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "assured-controls")
        report["checks"][check_index]["status"] = "Not Checked"
        report["checks"][check_index]["details"] = (
            "Manual verification required. Assured Controls is an add-on for Enterprise Plus edition "
            "that allows precise control over cloud service provider access."
        )
        
        # Don't update summary as this requires manual verification
    except Exception as e:
        print(f"Error checking Assured Controls: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "assured-controls")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_access_transparency(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check Access Transparency setting
    """
    print("Checking Access Transparency...")
    
    try:
        # API for checking if Access Transparency is enabled is not directly available
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "access-transparency")
        report["checks"][check_index]["status"] = "Not Checked"
        report["checks"][check_index]["details"] = (
            "Manual verification required. Access Transparency provides logs of actions taken by Google staff. "
            "Verify this is enabled in Admin Console > Security > Access Transparency."
        )
        
        # Don't update summary as this requires manual verification
    except Exception as e:
        print(f"Error checking Access Transparency: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "access-transparency")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_password_policy(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check password policy settings
    """
    print("Checking Password Policy...")
    
    try:
        directory = build("admin", "directory_v1", credentials=auth)
        
        # Get password policy settings
        response = directory.customers().get(customerKey="my_customer").execute()
        
        if response and "passwordStatus" in response:
            password_policy = response["passwordStatus"]
            is_compliant = True
            details = []
            
            # Check minimum length (FedRAMP requires at least 12 characters)
            if not password_policy.get("passwordMinimumLength") or password_policy["passwordMinimumLength"] < 12:
                is_compliant = False
                details.append(f"Password minimum length is {password_policy.get('passwordMinimumLength', 'not set')}, should be at least 12 characters")
            
            # Check complexity requirements
            if not password_policy.get("enforcePasswordPolicy"):
                is_compliant = False
                details.append("Password policy enforcement is not enabled")
            
            # Check password expiration (FedRAMP requires maximum 60 days)
            if not password_policy.get("passwordMaximumLength") or password_policy["passwordMaximumLength"] > 60:
                is_compliant = False
                details.append(f"Password expiration is {password_policy.get('passwordMaximumLength', 'not set')} days, should be 60 days or less")
            
            check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "password-policy")
            
            if is_compliant:
                report["checks"][check_index]["status"] = "Compliant"
                report["checks"][check_index]["details"] = "Password policy meets FedRAMP requirements"
                report["summary"]["compliant"] += 1
            else:
                report["checks"][check_index]["status"] = "Not Compliant"
                report["checks"][check_index]["details"] = f"Password policy does not meet FedRAMP requirements: {'; '.join(details)}"
                report["summary"]["non_compliant"] += 1
            
            report["summary"]["not_checked"] -= 1
        else:
            check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "password-policy")
            report["checks"][check_index]["status"] = "Not Checked"
            report["checks"][check_index]["details"] = "Could not retrieve password policy settings"
    except Exception as e:
        print(f"Error checking Password Policy: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "password-policy")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_two_step_verification(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check if 2-Step Verification is enforced
    """
    print("Checking Two-Step Verification...")
    
    try:
        directory = build("admin", "directory_v1", credentials=auth)
        
        # Get 2SV settings
        response = directory.customers().get(customerKey="my_customer").execute()
        
        if response and response.get("isEnforcedIn2Sv"):
            check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "two-step-verification")
            report["checks"][check_index]["status"] = "Compliant"
            report["checks"][check_index]["details"] = "2-Step Verification is enforced domain-wide"
            report["summary"]["compliant"] += 1
            report["summary"]["not_checked"] -= 1
        else:
            check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "two-step-verification")
            report["checks"][check_index]["status"] = "Not Compliant"
            report["checks"][check_index]["details"] = "2-Step Verification is not enforced domain-wide"
            report["summary"]["non_compliant"] += 1
            report["summary"]["not_checked"] -= 1
    except Exception as e:
        print(f"Error checking Two-Step Verification: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "two-step-verification")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_admin_privileges(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check admin privileges for principle of least privilege
    """
    print("Checking Admin Privileges...")
    
    try:
        directory = build("admin", "directory_v1", credentials=auth)
        
        # Get role assignments
        response = directory.roleAssignments().list(customer="my_customer").execute()
        
        if response and "items" in response:
            role_assignments = response["items"]
            super_admin_assignments = [role for role in role_assignments if role["roleId"] == "101"]  # Super Admin role ID
            
            # Get total admin count
            admin_count = len(role_assignments)
            super_admin_count = len(super_admin_assignments)
            
            # For FedRAMP, principle of least privilege means minimizing super admin accounts
            # Using a threshold of 3 super admins as a reasonable assumption
            is_compliant = super_admin_count <= 3
            
            check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "admin-privileges")
            
            if is_compliant:
                report["checks"][check_index]["status"] = "Compliant"
                report["checks"][check_index]["details"] = f"Admin role assignments follow principle of least privilege. Total admin accounts: {admin_count}, Super admin accounts: {super_admin_count}"
                report["summary"]["compliant"] += 1
            else:
                report["checks"][check_index]["status"] = "Not Compliant"
                report["checks"][check_index]["details"] = f"Too many super admin accounts ({super_admin_count}). For principle of least privilege, limit super admin accounts to 3 or fewer. Total admin accounts: {admin_count}"
                report["summary"]["non_compliant"] += 1
            
            report["summary"]["not_checked"] -= 1
        else:
            check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "admin-privileges")
            report["checks"][check_index]["status"] = "Not Checked"
            report["checks"][check_index]["details"] = "Could not retrieve admin role assignments"
    except Exception as e:
        print(f"Error checking Admin Privileges: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "admin-privileges")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_audit_logging(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check audit logging configuration
    """
    print("Checking Audit Logging...")
    
    try:
        reports_service = build("admin", "reports_v1", credentials=auth)
        
        # Try to fetch admin audit logs to check if audit logging is enabled
        response = reports_service.activities().list(
            userKey="all",
            applicationName="admin",
            maxResults=1
        ).execute()
        
        is_logging_enabled = response and "items" in response and len(response["items"]) > 0
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "audit-logging")
        
        if is_logging_enabled:
            report["checks"][check_index]["status"] = "Compliant"
            report["checks"][check_index]["details"] = "Audit logging is enabled and capturing events"
            report["summary"]["compliant"] += 1
        else:
            report["checks"][check_index]["status"] = "Not Compliant"
            report["checks"][check_index]["details"] = "Audit logging does not appear to be capturing events"
            report["summary"]["non_compliant"] += 1
        
        report["summary"]["not_checked"] -= 1
    except Exception as e:
        print(f"Error checking Audit Logging: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "audit-logging")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_security_center(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check Security Center configuration
    """
    print("Checking Security Center...")
    
    try:
        # API for checking Security Center configuration is not available
        # This requires Enterprise Plus and manual verification
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "security-center")
        report["checks"][check_index]["status"] = "Not Checked"
        report["checks"][check_index]["details"] = (
            "Manual verification required. Security Center is available for Enterprise Plus users. "
            "Check Admin Console > Security > Security Center."
        )
        
        # Don't update summary as this requires manual verification
    except Exception as e:
        print(f"Error checking Security Center: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "security-center")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_dlp(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check Data Loss Prevention policies
    """
    print("Checking Data Loss Prevention...")
    
    try:
        # API for checking DLP configuration is not available
        # This requires manual verification
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "data-loss-prevention")
        report["checks"][check_index]["status"] = "Not Checked"
        report["checks"][check_index]["details"] = (
            "Manual verification required. Check Admin Console > Security > Data protection "
            "to verify if DLP rules are configured."
        )
        
        # Don't update summary as this requires manual verification
    except Exception as e:
        print(f"Error checking DLP: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "data-loss-prevention")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_context_aware_access(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check Context-Aware Access policies
    """
    print("Checking Context-Aware Access...")
    
    try:
        # API for checking Context-Aware Access is not available
        # This requires Enterprise Plus and manual verification
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "context-aware-access")
        report["checks"][check_index]["status"] = "Not Checked"
        report["checks"][check_index]["details"] = (
            "Manual verification required. Context-Aware Access is available for Enterprise Plus users. "
            "Check Admin Console > Security > Access and data control > Context-Aware Access."
        )
        
        # Don't update summary as this requires manual verification
    except Exception as e:
        print(f"Error checking Context-Aware Access: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "context-aware-access")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def check_endpoint_management(auth: Credentials, report: Dict[str, Any]) -> None:
    """
    Check endpoint management configuration
    """
    print("Checking Endpoint Management...")
    
    try:
        # API for checking endpoint management is not available
        # This requires manual verification
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "endpoint-management")
        report["checks"][check_index]["status"] = "Not Checked"
        report["checks"][check_index]["details"] = (
            "Manual verification required. Check Admin Console > Devices > Mobile & endpoints "
            "to verify endpoint management settings."
        )
        
        # Don't update summary as this requires manual verification
    except Exception as e:
        print(f"Error checking Endpoint Management: {e}")
        
        check_index = next(i for i, check in enumerate(report["checks"]) if check["id"] == "endpoint-management")
        report["checks"][check_index]["status"] = "Error"
        report["checks"][check_index]["details"] = f"Error during check: {str(e)}"


def generate_recommendations(report: Dict[str, Any]) -> None:
    """
    Generate recommendations based on non-compliant checks
    """
    non_compliant_checks = [check for check in report["checks"] if check["status"] == "Not Compliant"]
    
    for check in non_compliant_checks:
        report["recommendations"].append(f"{check['name']}: {check['fix_steps']}")


def check_fedramp_compliance() -> None:
    """
    Main function to execute all compliance checks
    """
    # Parse command line arguments and load config
    cli_args = parse_arguments()
    config = get_config_from_sources(cli_args)
    
    compliance_report = {
        "timestamp": datetime.now().isoformat(),
        "domain_name": "",
        "edition": "",
        "overall_status": "Not Compliant",
        "checks": FEDRAMP_CHECKS,
        "summary": {
            "compliant": 0,
            "non_compliant": 0,
            "not_checked": len(FEDRAMP_CHECKS)
        },
        "recommendations": []
    }

    try:
        # Authenticate
        auth = get_auth(config)
        print("✓ Authentication successful")

        # Get domain information
        directory = build("admin", "directory_v1", credentials=auth)
        try:
            domain_response = directory.domains().list(customer="my_customer").execute()
            
            if domain_response.get("domains") and len(domain_response["domains"]) > 0:
                compliance_report["domain_name"] = domain_response["domains"][0]["domainName"]
                print(f"✓ Retrieved domain: {compliance_report['domain_name']}")
        except Exception as e:
            print(f"Error retrieving domain information: {e}")

        # Get customer information (to determine edition)
        try:
            customer_response = directory.customers().get(customerKey="my_customer").execute()
            
            if customer_response:
                compliance_report["edition"] = customer_response.get("customerDomain", "Unknown")
                print("✓ Retrieved customer information")
        except Exception as e:
            print(f"Error retrieving customer information: {e}")

        # Run compliance checks
        check_authorized_services(auth, compliance_report)
        check_data_region_policy(auth, compliance_report)
        check_assured_controls(auth, compliance_report)
        check_access_transparency(auth, compliance_report)
        check_password_policy(auth, compliance_report)
        check_two_step_verification(auth, compliance_report)
        check_admin_privileges(auth, compliance_report)
        check_audit_logging(auth, compliance_report)
        check_security_center(auth, compliance_report)
        check_dlp(auth, compliance_report)
        check_context_aware_access(auth, compliance_report)
        check_endpoint_management(auth, compliance_report)

        # Generate recommendations for non-compliant checks
        generate_recommendations(compliance_report)

        # Determine overall status
        if compliance_report["summary"]["non_compliant"] == 0 and compliance_report["summary"]["not_checked"] == 0:
            compliance_report["overall_status"] = "Compliant"
        elif compliance_report["summary"]["non_compliant"] > 0:
            compliance_report["overall_status"] = "Not Compliant"
        else:
            compliance_report["overall_status"] = "Partially Checked"

        # Save report
        report_path = config.get("report_output_path", DEFAULT_CONFIG["report_output_path"])
        with open(report_path, "w") as f:
            json.dump(compliance_report, f, indent=2)
        
        # Display summary
        print("\n=== FedRAMP Compliance Report Summary ===")
        print(f"Domain: {compliance_report['domain_name']}")
        print(f"Edition: {compliance_report['edition']}")
        print(f"Overall Status: {compliance_report['overall_status']}")
        print(f"Compliant Checks: {compliance_report['summary']['compliant']}")
        print(f"Non-Compliant Checks: {compliance_report['summary']['non_compliant']}")
        print(f"Checks Not Performed: {compliance_report['summary']['not_checked']}")
        print(f"Report saved to: {report_path}")

        if compliance_report["recommendations"]:
            print("\n=== Key Recommendations ===")
            for i, rec in enumerate(compliance_report["recommendations"], 1):
                print(f"{i}. {rec}")

    except Exception as e:
        print(f"Error during compliance check: {e}")
        sys.exit(1)


if __name__ == "__main__":
    check_fedramp_compliance()