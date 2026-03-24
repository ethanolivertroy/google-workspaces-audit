"""Validation script and quick-reference guide generator."""

from __future__ import annotations

from datetime import datetime, timezone

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager
from gws_inspector.reporters import register_reporter
from gws_inspector.reporters.base import ReportGenerator


@register_reporter
class ValidationReportGenerator(ReportGenerator):
    """Generate a validation bash script and quick-reference guide."""

    name = "validation"
    display_name = "Validation Script & Quick Reference"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self._generate_script(output, ts)
        self._generate_quick_reference(findings, output, ts)

    def _generate_script(self, output: OutputManager, ts: str) -> None:
        script = f"""\
#!/usr/bin/env bash
# validate_compliance.sh — Quick compliance data validation
# Generated: {ts}
# Requires: jq (https://jqlang.github.io/jq/)

set -euo pipefail

RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

PASS=0
FAIL=0
WARN=0

pass() {{ echo -e "${{GREEN}}[PASS]${{NC}} $1"; ((PASS++)); }}
fail() {{ echo -e "${{RED}}[FAIL]${{NC}} $1"; ((FAIL++)); }}
warn() {{ echo -e "${{YELLOW}}[WARN]${{NC}} $1"; ((WARN++)); }}

check_file() {{
    if [[ -f "$1" ]]; then
        pass "File exists: $1"
    else
        fail "Missing file: $1"
        return 1
    fi
}}

check_json() {{
    if jq empty "$1" 2>/dev/null; then
        pass "Valid JSON: $1"
    else
        fail "Invalid JSON: $1"
    fi
}}

echo "========================================"
echo "  GWS Compliance Data Validation"
echo "========================================"
echo ""

# Determine base directory
BASE_DIR="${{1:-.}}"
echo "Checking directory: $BASE_DIR"
echo ""

echo "--- Core Data Files ---"
for f in users.json groups.json org_units.json domains.json; do
    filepath="$BASE_DIR/core_data/$f"
    if check_file "$filepath"; then
        check_json "$filepath"
    fi
done
echo ""

echo "--- Analysis Files ---"
for f in admin_analysis.json user_analysis.json monitoring_analysis.json; do
    filepath="$BASE_DIR/analysis/$f"
    if check_file "$filepath"; then
        check_json "$filepath"
    fi
done
echo ""

echo "--- User Count Validation ---"
USERS_FILE="$BASE_DIR/core_data/users.json"
if [[ -f "$USERS_FILE" ]]; then
    USER_COUNT=$(jq 'length' "$USERS_FILE" 2>/dev/null || echo "0")
    if [[ "$USER_COUNT" -gt 0 ]]; then
        pass "Found $USER_COUNT users in users.json"
    else
        warn "No users found in users.json (empty environment?)"
    fi

    SUSPENDED=$(jq '[.[] | select(.suspended == true)] | length' "$USERS_FILE" 2>/dev/null || echo "0")
    echo "  Suspended users: $SUSPENDED"

    ADMINS=$(jq '[.[] | select(.isAdmin == true)] | length' "$USERS_FILE" 2>/dev/null || echo "0")
    echo "  Admin users: $ADMINS"
fi
echo ""

echo "--- Compliance Reports ---"
for subdir in fedramp cmmc soc2 disa_stig irap ismap pci_dss cis; do
    dirpath="$BASE_DIR/compliance/$subdir"
    if [[ -d "$dirpath" ]]; then
        count=$(find "$dirpath" -name "*.md" 2>/dev/null | wc -l | tr -d ' ')
        if [[ "$count" -gt 0 ]]; then
            pass "compliance/$subdir: $count report(s)"
        else
            warn "compliance/$subdir: directory exists but no reports"
        fi
    else
        warn "Missing compliance directory: $subdir"
    fi
done
echo ""

echo "--- Password Policy Validation ---"
PW_FILE="$BASE_DIR/core_data/password_policies.json"
if [[ -f "$PW_FILE" ]]; then
    jq -r '.[] | "OU: \\(.orgUnit // "root") | Min Length: \\(.minLength // "default")"' "$PW_FILE" 2>/dev/null || warn "Could not parse password policies"
fi
echo ""

echo "--- 2SV Policy Validation ---"
TSV_FILE="$BASE_DIR/core_data/two_step_verification_policies.json"
if [[ -f "$TSV_FILE" ]]; then
    jq -r '.[] | "OU: \\(.orgUnit // "root") | Enforcement: \\(.enforcement // "unknown")"' "$TSV_FILE" 2>/dev/null || warn "Could not parse 2SV policies"
fi
echo ""

echo "========================================"
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings"
echo "========================================"

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
"""
        output.save_script(script, "validate_compliance.sh")

    def _generate_quick_reference(
        self,
        findings: list[ComplianceFinding],
        output: OutputManager,
        ts: str,
    ) -> None:
        lines: list[str] = []
        _a = lines.append

        _a("# GWS Inspector Output Quick Reference")
        _a("")
        _a(f"**Generated:** {ts}")
        _a("")
        _a("## Directory Structure")
        _a("")
        _a("```")
        _a("<output_dir>/")
        _a("├── core_data/              # Raw API data (JSON)")
        _a("│   ├── users.json")
        _a("│   ├── groups.json")
        _a("│   ├── group_members.json")
        _a("│   ├── org_units.json")
        _a("│   ├── domains.json")
        _a("│   ├── roles.json")
        _a("│   ├── role_assignments.json")
        _a("│   ├── mobile_devices.json")
        _a("│   ├── password_policies.json")
        _a("│   ├── two_step_verification_policies.json")
        _a("│   ├── session_policies.json")
        _a("│   └── alerts.json")
        _a("├── analysis/               # Derived analysis (JSON)")
        _a("│   ├── admin_analysis.json")
        _a("│   ├── user_analysis.json")
        _a("│   ├── monitoring_analysis.json")
        _a("│   └── device_analysis.json")
        _a("├── compliance/             # Framework reports (Markdown)")
        _a("│   ├── executive_summary.md")
        _a("│   ├── unified_compliance_matrix.md")
        _a("│   ├── fedramp/")
        _a("│   ├── cmmc/")
        _a("│   ├── soc2/")
        _a("│   ├── disa_stig/")
        _a("│   ├── irap/")
        _a("│   ├── ismap/")
        _a("│   ├── pci_dss/")
        _a("│   └── cis/")
        _a("├── validate_compliance.sh  # Data validation script")
        _a("└── QUICK_REFERENCE.md      # This file")
        _a("```")
        _a("")
        _a("## Output Files")
        _a("")
        _a("| File | Description |")
        _a("|------|-------------|")
        _a("| `core_data/*.json` | Raw data collected from Google Workspace APIs |")
        _a("| `analysis/*.json` | Processed analysis results derived from raw data |")
        _a("| `compliance/executive_summary.md` | High-level compliance overview across all frameworks |")
        _a("| `compliance/unified_compliance_matrix.md` | Cross-framework control mapping table |")
        _a("| `compliance/fedramp/` | FedRAMP (NIST 800-53) compliance report |")
        _a("| `compliance/cmmc/` | CMMC Level 2 readiness assessment with SPRS score |")
        _a("| `compliance/soc2/` | SOC 2 Type II (CC6/CC7) assessment |")
        _a("| `compliance/disa_stig/` | DISA STIG compliance checklist |")
        _a("| `compliance/irap/` | IRAP (Australian ISM) and Essential Eight assessment |")
        _a("| `compliance/ismap/` | ISMAP (Japan) ISO 27001-based assessment |")
        _a("| `compliance/pci_dss/` | PCI DSS v4.0 Requirements 7 & 8 gap analysis |")
        _a("| `compliance/cis/` | CIS Google Workspace Benchmark assessment |")
        _a("| `validate_compliance.sh` | Bash script to verify output data integrity |")
        _a("")
        _a("## Usage")
        _a("")
        _a("### Validate output data")
        _a("")
        _a("```bash")
        _a("chmod +x validate_compliance.sh")
        _a("./validate_compliance.sh <output_dir>")
        _a("```")
        _a("")
        _a("### Quick checks with jq")
        _a("")
        _a("```bash")
        _a("# Count users")
        _a("jq 'length' core_data/users.json")
        _a("")
        _a("# List admin users")
        _a('jq \'[.[] | select(.isAdmin == true) | .primaryEmail]\' core_data/users.json')
        _a("")
        _a("# Show suspended users")
        _a('jq \'[.[] | select(.suspended == true) | .primaryEmail]\' core_data/users.json')
        _a("```")
        _a("")
        _a("---")
        _a(f"*Generated by gws-inspector on {ts}*")

        output.save_markdown("\n".join(lines), "QUICK_REFERENCE.md")
