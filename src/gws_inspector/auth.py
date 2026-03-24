"""Google Workspace authentication — service account and OAuth 2.0 flows."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow

logger = logging.getLogger(__name__)

# All read-only scopes needed for a comprehensive audit
SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.customer.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    "https://www.googleapis.com/auth/apps.alerts",
    "https://www.googleapis.com/auth/cloud-identity.devices.readonly",
    "https://www.googleapis.com/auth/chrome.management.policy.readonly",
]


class GWSAuthenticator:
    """Handles Google Workspace authentication.

    Two modes:
    1. Service account with domain-wide delegation (production/CI)
    2. OAuth 2.0 installed app flow (development/interactive)
    """

    def __init__(self, credentials: service_account.Credentials) -> None:
        self._credentials = credentials

    @property
    def credentials(self) -> service_account.Credentials:
        """Return the underlying credentials, refreshing if needed."""
        if self._credentials.expired:
            self._credentials.refresh(Request())
        return self._credentials

    @classmethod
    def from_service_account(
        cls,
        credentials_file: str | Path,
        admin_email: str,
        *,
        scopes: list[str] | None = None,
    ) -> GWSAuthenticator:
        """Authenticate via service account with domain-wide delegation.

        Args:
            credentials_file: Path to the service account JSON key file.
            admin_email: Admin email to impersonate (required for domain-wide delegation).
            scopes: OAuth scopes (defaults to all audit scopes).
        """
        effective_scopes = scopes or SCOPES
        creds = service_account.Credentials.from_service_account_file(
            str(credentials_file),
            scopes=effective_scopes,
            subject=admin_email,
        )
        logger.info("Authenticated via service account (impersonating %s)", admin_email)
        return cls(creds)

    @classmethod
    def from_oauth(
        cls,
        client_secrets_file: str | Path,
        token_file: str | Path = "token.json",
        *,
        scopes: list[str] | None = None,
    ) -> GWSAuthenticator:
        """Authenticate via OAuth 2.0 installed app flow.

        Opens a browser for consent on first run, then caches the token.

        Args:
            client_secrets_file: Path to OAuth client secrets JSON.
            token_file: Path to cache the access/refresh token.
            scopes: OAuth scopes (defaults to all audit scopes).
        """
        from google.oauth2.credentials import Credentials

        effective_scopes = scopes or SCOPES
        token_path = Path(token_file)
        creds = None

        if token_path.exists():
            creds = Credentials.from_authorized_user_file(str(token_path), effective_scopes)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    str(client_secrets_file), effective_scopes
                )
                creds = flow.run_local_server(port=0)

            token_path.write_text(creds.to_json())
            logger.info("OAuth token cached at %s", token_path)

        logger.info("Authenticated via OAuth 2.0")
        return cls(creds)

    @classmethod
    def detect(
        cls,
        credentials_file: str | Path,
        admin_email: str | None = None,
        *,
        oauth: bool = False,
        token_file: str | Path = "token.json",
    ) -> GWSAuthenticator:
        """Auto-detect credential type and authenticate.

        If *oauth* is True or *admin_email* is not provided, uses OAuth flow.
        Otherwise, checks if the file is a service account key and uses delegation.
        """
        cred_path = Path(credentials_file)
        if not cred_path.exists():
            raise FileNotFoundError(f"Credentials file not found: {cred_path}")

        if oauth:
            return cls.from_oauth(cred_path, token_file)

        # Detect file type
        with open(cred_path) as f:
            data = json.load(f)

        if data.get("type") == "service_account":
            if not admin_email:
                raise ValueError(
                    "Service account credentials require --admin-email for domain-wide delegation"
                )
            return cls.from_service_account(cred_path, admin_email)

        # Assume OAuth client secrets
        return cls.from_oauth(cred_path, token_file)
