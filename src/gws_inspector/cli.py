"""Command-line interface for gws-inspector."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from gws_inspector import __version__
from gws_inspector.analyzers import available_frameworks


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="gws-inspector",
        description=f"Google Workspace Multi-Framework Compliance Audit Tool v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  gws-inspector -c credentials.json -a admin@example.com -d example.com
  gws-inspector -c credentials.json -a admin@example.com -d example.com --frameworks fedramp,cmmc
  GWS_CREDENTIALS_FILE=creds.json GWS_ADMIN_EMAIL=admin@example.com GWS_DOMAIN=example.com gws-inspector
  gws-inspector -c client_secrets.json --oauth -d example.com
""",
    )

    parser.add_argument(
        "-c", "--credentials",
        default=os.environ.get("GWS_CREDENTIALS_FILE"),
        help="Service account JSON key or OAuth client secrets.  Env: GWS_CREDENTIALS_FILE",
    )
    parser.add_argument(
        "-a", "--admin-email",
        default=os.environ.get("GWS_ADMIN_EMAIL"),
        help="Admin email for domain-wide delegation.  Env: GWS_ADMIN_EMAIL",
    )
    parser.add_argument(
        "-d", "--domain",
        default=os.environ.get("GWS_DOMAIN"),
        help="Google Workspace domain.  Env: GWS_DOMAIN",
    )
    parser.add_argument(
        "--oauth", action="store_true",
        help="Use OAuth 2.0 installed app flow instead of service account",
    )
    parser.add_argument(
        "--token-file",
        default=os.environ.get("GWS_TOKEN_FILE", "token.json"),
        help="Cached OAuth token path (default: token.json).  Env: GWS_TOKEN_FILE",
    )
    parser.add_argument(
        "-o", "--output-dir",
        help="Custom output directory (default: timestamped)",
    )
    parser.add_argument(
        "--frameworks",
        help=f"Comma-separated frameworks (default: all).  Available: {', '.join(available_frameworks())}",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args(argv)

    if not args.credentials:
        parser.error("--credentials is required (or set GWS_CREDENTIALS_FILE)")
    if not args.domain:
        parser.error("--domain is required (or set GWS_DOMAIN)")

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    from gws_inspector.auth import GWSAuthenticator
    from gws_inspector.client import GWSClient
    from gws_inspector.engine import AuditEngine
    from gws_inspector.output import OutputManager

    authenticator = GWSAuthenticator.detect(
        credentials_file=args.credentials,
        admin_email=args.admin_email,
        oauth=args.oauth,
        token_file=args.token_file,
    )

    client = GWSClient(
        credentials=authenticator.credentials,
        domain=args.domain,
        admin_email=args.admin_email or "",
    )

    output_dir = Path(args.output_dir) if args.output_dir else None
    output = OutputManager(base_dir=output_dir)

    frameworks = [f.strip() for f in args.frameworks.split(",")] if args.frameworks else None

    if not client.test_connection():
        logging.getLogger(__name__).error("Failed to connect. Verify credentials and domain.")
        sys.exit(1)

    engine = AuditEngine(client, output, frameworks=frameworks)

    try:
        engine.run()
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Audit interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.getLogger(__name__).error("Audit failed: %s", e)
        sys.exit(1)
