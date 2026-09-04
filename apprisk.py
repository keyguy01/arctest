#!/usr/bin/env python3

import os
import re
from datetime import datetime

import pandas as pd


# ============================================================
# Configuration
# ============================================================

RUN_DATE = datetime.now().strftime(
    "%Y-%m-%d"
)

ARC_DIR = os.path.join(
    "reports",
    "arc",
    RUN_DATE,
)

os.makedirs(
    ARC_DIR,
    exist_ok=True,
)


# ============================================================
# Helpers
# ============================================================

def normalize_text(value):
    """Normalize a value to lowercase text."""
    if value is None or pd.isna(value):
        return ""

    return str(value).strip().lower()


def normalize_upper(value):
    """Normalize a value to uppercase text."""
    return normalize_text(value).upper()


def normalize_priority(severity):
    """
    Normalize Rapid7/Snyk severity values.
    """
    severity = normalize_upper(
        severity
    )

    if severity in {
        "CRITICAL",
        "URGENT",
        "SEVERE",
    }:
        return "Critical"

    if severity == "HIGH":
        return "High"

    if severity in {
        "MEDIUM",
        "MODERATE",
    }:
        return "Medium"

    return "Low"


def normalize_cwes(value):
    """
    Extract normalized CWE identifiers.
    """
    if value is None or pd.isna(value):
        return set()

    matches = re.findall(
        r"CWE[-_\s]?(\d+)",
        str(value).upper(),
    )

    return {
        f"CWE-{number}"
        for number in matches
    }


# ============================================================
# Vulnerability Classification
# ============================================================

VULNERABILITY_PATTERNS = {

    "Cross-Site Scripting": [
        r"\bcross[- ]site scripting\b",
        r"\bxss\b",
        r"\bcwe[- ]?79\b",
    ],

    "SQL Injection": [
        r"\bsql injection\b",
        r"\bsqli\b",
        r"\bcwe[- ]?89\b",
    ],

    "Command Injection": [
        r"\bcommand injection\b",
        r"\bos command injection\b",
        r"\bcommand execution\b",
        r"\bcwe[- ]?78\b",
    ],

    "Path Traversal": [
        r"\bpath traversal\b",
        r"\bdirectory traversal\b",
        r"\bcwe[- ]?22\b",
    ],

    "Server-Side Request Forgery": [
        r"\bserver[- ]side request forgery\b",
        r"\bssrf\b",
        r"\bcwe[- ]?918\b",
    ],

    "XML External Entity": [
        r"\bxml external entity\b",
        r"\bxxe\b",
        r"\bcwe[- ]?611\b",
    ],

    "Cross-Site Request Forgery": [
        r"\bcross[- ]site request forgery\b",
        r"\bcsrf\b",
        r"\bcwe[- ]?352\b",
    ],

    "Broken Access Control": [
        r"\bbroken access control\b",
        r"\baccess control\b",
        r"\bidor\b",
        r"\binsecure direct object reference\b",
        r"\bcwe[- ]?639\b",
    ],

    "Authentication": [
        r"\bauthentication bypass\b",
        r"\bweak authentication\b",
        r"\bauthentication\b",
    ],

    "Hardcoded Secret": [
        r"\bhardcoded secret\b",
        r"\bhard-coded secret\b",
        r"\bhardcoded credential\b",
        r"\bembedded credential\b",
    ],

    "Weak Cryptography": [
        r"\bweak cryptograph",
        r"\bweak cipher\b",
        r"\binsecure cipher\b",
        r"\bweak encryption\b",
    ],

    "Insecure Deserialization": [
        r"\binsecure deserialization\b",
        r"\bunsafe deserialization\b",
        r"\bdeserialization\b",
        r"\bcwe[- ]?502\b",
    ],

    "Information Disclosure": [
        r"\binformation disclosure\b",
        r"\bsensitive information\b",
        r"\bsensitive data\b",
        r"\bdata exposure\b",
        r"\bcwe[- ]?497\b",
    ],

    "Security Misconfiguration": [
        r"\bsecurity misconfiguration\b",
        r"\bmisconfiguration\b",
    ],

    "Open Redirect": [
        r"\bopen redirect\b",
        r"\bunvalidated redirect\b",
        r"\bcwe[- ]?601\b",
    ],
}


def classify_vulnerability(*values):
    """
    Determine the most likely vulnerability type.
    """
    combined = " ".join(
        normalize_text(value)
        for value in values
        if value is not None
        and not pd.isna(value)
    )

    for vulnerability, patterns in (
        VULNERABILITY_PATTERNS.items()
    ):

        for pattern in patterns:

            if re.search(
                pattern,
                combined,
                flags=re.IGNORECASE,
            ):
                return vulnerability

    return "Security Finding"


# ============================================================
# CWE → Vulnerability Mapping
# ============================================================

CWE_TYPE_MAP = {

    "CWE-22":
        "Path Traversal",

    "CWE-78":
        "Command Injection",

    "CWE-79":
        "Cross-Site Scripting",

    "CWE-89":
        "SQL Injection",

    "CWE-352":
        "Cross-Site Request Forgery",

    "CWE-497":
        "Information Disclosure",

    "CWE-502":
        "Insecure Deserialization",

    "CWE-601":
        "Open Redirect",

    "CWE-611":
        "XML External Entity",

    "CWE-639":
        "Broken Access Control",

    "CWE-918":
        "Server-Side Request Forgery",
}


def classify_from_cwe(value):
    """
    Determine vulnerability type from CWE.
    """
    cwes = normalize_cwes(
        value
    )

    for cwe in cwes:

        if cwe in CWE_TYPE_MAP:
            return CWE_TYPE_MAP[cwe]

    return None


# ============================================================
# Action Generation
# ============================================================

ACTION_MAP = {

    "Cross-Site Scripting":
        (
            "Review the affected input flow and ensure "
            "untrusted data is properly validated and "
            "contextually encoded before being rendered."
        ),

    "SQL Injection":
        (
            "Review the affected database access path. "
            "Use parameterized queries or prepared statements "
            "and validate untrusted input."
        ),

    "Command Injection":
        (
            "Review the affected command execution path. "
            "Avoid passing untrusted input to operating-system "
            "commands and apply strict allow-list validation."
        ),

    "Path Traversal":
        (
            "Review file access logic and prevent user-controlled "
            "paths from escaping the intended application directory."
        ),

    "Server-Side Request Forgery":
        (
            "Review server-side URL/request handling. "
            "Restrict outbound destinations and validate URLs "
            "against an explicit allow-list."
        ),

    "XML External Entity":
        (
            "Disable external entity resolution and unsafe "
            "DTD processing in XML parsers."
        ),

    "Cross-Site Request Forgery":
        (
            "Protect state-changing requests with anti-CSRF "
            "tokens and appropriate SameSite cookie controls."
        ),

    "Broken Access Control":
        (
            "Review authorization checks at the affected "
            "resource and enforce server-side access control "
            "for every sensitive operation."
        ),

    "Authentication":
        (
            "Review the affected authentication flow and "
            "strengthen authentication and session controls."
        ),

    "Hardcoded Secret":
        (
            "Remove secrets from source code and move them "
            "to an approved secret-management mechanism."
        ),

    "Weak Cryptography":
        (
            "Replace deprecated or weak cryptographic algorithms "
            "with currently approved algorithms and configurations."
        ),

    "Insecure Deserialization":
        (
            "Avoid deserializing untrusted data or use a safe "
            "serialization format with strict type validation."
        ),

    "Information Disclosure":
        (
            "Review the affected response and remove unnecessary "
            "system, application, configuration, or sensitive "
            "information from externally accessible responses."
        ),

    "Security Misconfiguration":
        (
            "Review the affected security configuration and "
            "apply the application's approved security baseline."
        ),

    "Open Redirect":
        (
            "Validate redirect destinations against an approved "
            "allow-list and avoid redirecting to user-controlled URLs."
        ),
}


def build_action(vulnerability_type, row):
    """
    Build remediation/action text.
    """

    # Prefer actual Snyk remediation when available.
    remediation = row.get(
        "SNYK_REMEDIATION",
        "",
    )

    if (
        pd.notna(remediation)
        and str(remediation).strip()
    ):
        return str(
            remediation
        ).strip()

    return ACTION_MAP.get(
        vulnerability_type,
        (
            "Review the affected application "
            "component and implement the security "
            "controls recommended by the findings."
        ),
    )


# ============================================================
# Validation Generation
# ============================================================

VALIDATION_MAP = {

    "Cross-Site Scripting":
        (
            "Test the affected input parameter with safe "
            "XSS test strings. Verify output is contextually "
            "encoded and rendered as data rather than executable "
            "HTML or script. Re-run Snyk and Rapid7 scans."
        ),

    "SQL Injection":
        (
            "Test the affected input with safe SQL injection "
            "validation cases. Confirm parameterized queries "
            "are used and no database error or unintended query "
            "behavior occurs. Re-run security scans."
        ),

    "Command Injection":
        (
            "Test the affected input with non-destructive "
            "command-injection validation cases. Confirm "
            "untrusted input cannot alter command execution. "
            "Re-run security scans."
        ),

    "Path Traversal":
        (
            "Test file access using traversal sequences and "
            "encoded traversal variants. Confirm access remains "
            "restricted to the intended directory. Re-run scans."
        ),

    "Server-Side Request Forgery":
        (
            "Test server-side URL handling using approved "
            "non-production endpoints. Confirm requests cannot "
            "reach unauthorized internal or metadata services."
        ),

    "XML External Entity":
        (
            "Submit controlled XML containing external-entity "
            "references in a test environment. Confirm external "
            "entities and DTD processing are disabled."
        ),

    "Cross-Site Request Forgery":
        (
            "Verify state-changing requests require valid "
            "anti-CSRF protections and that invalid or missing "
            "tokens are rejected."
        ),

    "Broken Access Control":
        (
            "Test the affected resource using authorized and "
            "unauthorized identities. Confirm server-side "
            "authorization prevents unauthorized access."
        ),

    "Authentication":
        (
            "Test authentication and session-management controls "
            "using approved negative test cases. Confirm bypass "
            "attempts fail and sessions are handled securely."
        ),

    "Hardcoded Secret":
        (
            "Verify the secret is removed from source code and "
            "repository history where applicable. Confirm the "
            "application retrieves credentials from approved "
            "secret management."
        ),

    "Weak Cryptography":
        (
            "Verify the affected component uses approved "
            "cryptographic algorithms, protocols, and key sizes."
        ),

    "Insecure Deserialization":
        (
            "Test deserialization with controlled untrusted "
            "input. Confirm unsafe object types and unexpected "
            "code execution paths are rejected."
        ),

    "Information Disclosure":
        (
            "Review the affected endpoint response and verify "
            "unnecessary server, framework, configuration, or "
            "sensitive information is no longer exposed."
        ),

    "Security Misconfiguration":
        (
            "Verify the affected security configuration against "
            "the application's approved security baseline."
        ),

    "Open Redirect":
        (
            "Test redirect handling with external and malformed "
            "destinations. Confirm only approved redirect targets "
            "are accepted."
        ),
}


def build_validation(
    vulnerability_type,
    row,
):
    """
    Build validation guidance.
    """

    validation = VALIDATION_MAP.get(
        vulnerability_type,
        (
            "Perform regression testing on the affected "
            "component and re-run Rapid7 and Snyk scans."
        ),
    )

    return validation


# ============================================================
# Correlation Detection
# ============================================================

def is_correlated_row(row):
    """
    Determine whether this row came from the correlation
    engine.
    """
    confidence = row.get(
        "CONFIDENCE",
        "",
    )

    if (
        confidence is not None
        and not pd.isna(confidence)
        and str(confidence).strip()
    ):
        return True

    status = normalize_upper(
        row.get(
            "CORRELATION_STATUS",
            "",
        )
    )

    return status == "MATCHED"


# ============================================================
# Build Correlated Risk Row
# ============================================================

def build_correlated_risk(row):
    """
    Convert a correlation-engine row into a normalized
    risk-report row.
    """

    # --------------------------------------------------------
    # Vulnerability type
    # --------------------------------------------------------

    vulnerability_type = classify_vulnerability(
        row.get(
            "R7_ATTACK_TYPE",
            "",
        ),
        row.get(
            "R7_CWE",
            "",
        ),
        row.get(
            "R7_OWASP",
            "",
        ),
        row.get(
            "R7_PROOF",
            "",
        ),
        row.get(
            "R7_PROOF_DESCRIPTION",
            "",
        ),
        row.get(
            "SNYK_TITLE",
            "",
        ),
        row.get(
            "SNYK_DESCRIPTION",
            "",
        ),
        row.get(
            "SNYK_CWE",
            "",
        ),
    )

    # Prefer direct CWE classification when available.
    cwe_type = classify_from_cwe(
        row.get(
            "R7_CWE",
            "",
        )
    )

    if cwe_type:
        vulnerability_type = cwe_type

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    r7_priority = normalize_priority(
        row.get(
            "R7_SEVERITY",
            "",
        )
    )

    snyk_priority = normalize_priority(
        row.get(
            "SNYK_SEVERITY",
            "",
        )
    )

    priority_order = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    if (
        priority_order[snyk_priority]
        >
        priority_order[r7_priority]
    ):
        priority = snyk_priority
    else:
        priority = r7_priority

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = row.get(
        "CONFIDENCE",
        "",
    )

    # --------------------------------------------------------
    # Build consolidated row
    # --------------------------------------------------------

    return {

        "APP_NAME":
            row.get(
                "APP_NAME",
                row.get(
                    "R7_APP_NAME",
                    "",
                ),
            ),

        "PRIORITY":
            priority,

        "RISK_TYPE":
            vulnerability_type,

        "CORRELATION_STATUS":
            "CORRELATED",

        "CORRELATION_LEVEL":
            row.get(
                "CORRELATION_LEVEL",
                "",
            ),

        "CONFIDENCE":
            confidence,

        "MATCH_REASON":
            row.get(
                "MATCH_REASON",
                "",
            ),

        "SHARED_CWES":
            row.get(
                "SHARED_CWES",
                "",
            ),

        "R7_ATTACK_TYPE":
            row.get(
                "R7_ATTACK_TYPE",
                "",
            ),

        "R7_CWE":
            row.get(
                "R7_CWE",
                "",
            ),

        "R7_OWASP":
            row.get(
                "R7_OWASP",
                "",
            ),

        "R7_SEVERITY":
            row.get(
                "R7_SEVERITY",
                "",
            ),

        "R7_STATUS":
            row.get(
                "R7_STATUS",
                "",
            ),

        "R7_URL":
            row.get(
                "R7_URL",
                "",
            ),

        "R7_METHOD":
            row.get(
                "R7_METHOD",
                "",
            ),

        "R7_PARAMETER":
            row.get(
                "R7_PARAMETER",
                "",
            ),

        "R7_PROOF":
            row.get(
                "R7_PROOF",
                "",
            ),

        "R7_VULNERABILITY_UUID":
            row.get(
                "R7_VULNERABILITY_UUID",
                "",
            ),

        "SNYK_ISSUE_ID":
            row.get(
                "SNYK_ISSUE_ID",
                "",
            ),

        "SNYK_TITLE":
            row.get(
                "SNYK_TITLE",
                "",
            ),

        "SNYK_SEVERITY":
            row.get(
                "SNYK_SEVERITY",
                "",
            ),

        "SNYK_STATUS":
            row.get(
                "SNYK_STATUS",
                "",
            ),

        "SNYK_CWE":
            row.get(
                "SNYK_CWE",
                "",
            ),

        "SNYK_PROJECT":
            row.get(
                "SNYK_PROJECT",
                "",
            ),

        "SNYK_RULE":
            row.get(
                "SNYK_RULE",
                "",
            ),

        "SNYK_FILE_PATH":
            row.get(
                "SNYK_FILE_PATH",
                "",
            ),

        "SNYK_START_LINE":
            row.get(
                "SNYK_START_LINE",
                "",
            ),

        "SNYK_END_LINE":
            row.get(
                "SNYK_END_LINE",
                "",
            ),

        "SNYK_RISK_SCORE":
            row.get(
                "SNYK_RISK_SCORE",
                "",
            ),

        "DESCRIPTION":
            row.get(
                "SNYK_DESCRIPTION",
                row.get(
                    "R7_PROOF_DESCRIPTION",
                    "",
                ),
            ),

        "ACTION":
            build_action(
                vulnerability_type,
                row,
            ),

        "VALIDATION":
            build_validation(
                vulnerability_type,
                row,
            ),
    }


# ============================================================
# Build Unmatched Rapid7 Risk Row
# ============================================================

def build_rapid7_risk(row):
    """
    Convert an unmatched Rapid7 finding into the
    normalized risk-report format.
    """

    vulnerability_type = classify_vulnerability(
        row.get(
            "attackType",
            "",
        ),
        row.get(
            "CWE",
            "",
        ),
        row.get(
            "OWASP",
            "",
        ),
        row.get(
            "proof",
            "",
        ),
        row.get(
            "proof_description",
            "",
        ),
    )

    cwe_type = classify_from_cwe(
        row.get(
            "CWE",
            "",
        )
    )

    if cwe_type:
        vulnerability_type = cwe_type

    return {

        "APP_NAME":
            row.get(
                "app_name",
                "",
            ),

        "PRIORITY":
            normalize_priority(
                row.get(
                    "severity",
                    "",
                )
            ),

        "RISK_TYPE":
            vulnerability_type,

        "CORRELATION_STATUS":
            "RAPID7_ONLY",

        "CORRELATION_LEVEL":
            "Uncorrelated",

        "CONFIDENCE":
            "",

        "MATCH_REASON":
            "",

        "SHARED_CWES":
            "",

        "R7_ATTACK_TYPE":
            row.get(
                "attackType",
                "",
            ),

        "R7_CWE":
            row.get(
                "CWE",
                "",
            ),

        "R7_OWASP":
            row.get(
                "OWASP",
                "",
            ),

        "R7_SEVERITY":
            row.get(
                "severity",
                "",
            ),

        "R7_STATUS":
            row.get(
                "status",
                "",
            ),

        "R7_URL":
            row.get(
                "rootCause_url",
                "",
            ),

        "R7_METHOD":
            row.get(
                "rootCause_method",
                "",
            ),

        "R7_PARAMETER":
            row.get(
                "rootCause_parameter",
                "",
            ),

        "R7_PROOF":
            row.get(
                "proof",
                "",
            ),

        "R7_VULNERABILITY_UUID":
            row.get(
                "vulnerability_uuid",
                "",
            ),

        "SNYK_ISSUE_ID":
            "",

        "SNYK_TITLE":
            "",

        "SNYK_SEVERITY":
            "",

        "SNYK_STATUS":
            "",

        "SNYK_CWE":
            "",

        "SNYK_PROJECT":
            "",

        "SNYK_RULE":
            "",

        "SNYK_FILE_PATH":
            "",

        "SNYK_START_LINE":
            "",

        "SNYK_END_LINE":
            "",

        "SNYK_RISK_SCORE":
            "",

        "DESCRIPTION":
            row.get(
                "proof_description",
                "",
            ),

        "ACTION":
            build_action(
                vulnerability_type,
                row,
            ),

        "VALIDATION":
            build_validation(
                vulnerability_type,
                row,
            ),
    }


# ============================================================
# Build Unmatched Snyk Risk Row
# ============================================================

def build_snyk_risk(row):
    """
    Convert an unmatched Snyk finding into the
    normalized risk-report format.
    """

    vulnerability_type = classify_vulnerability(
        row.get(
            "TITLE",
            "",
        ),
        row.get(
            "DESCRIPTION",
            "",
        ),
        row.get(
            "CWE",
            "",
        ),
        row.get(
            "RULE_KEY",
            "",
        ),
    )

    cwe_type = classify_from_cwe(
        row.get(
            "CWE",
            "",
        )
    )

    if cwe_type:
        vulnerability_type = cwe_type

    return {

        "APP_NAME":
            row.get(
                "PROJECT_NAME",
                "",
            ),

        "PRIORITY":
            normalize_priority(
                row.get(
                    "SEVERITY",
                    "",
                )
            ),

        "RISK_TYPE":
            vulnerability_type,

        "CORRELATION_STATUS":
            "SNYK_ONLY",

        "CORRELATION_LEVEL":
            "Uncorrelated",

        "CONFIDENCE":
            "",

        "MATCH_REASON":
            "",

        "SHARED_CWES":
            "",

        "R7_ATTACK_TYPE":
            "",

        "R7_CWE":
            "",

        "R7_OWASP":
            "",

        "R7_SEVERITY":
            "",

        "R7_STATUS":
            "",

        "R7_URL":
            "",

        "R7_METHOD":
            "",

        "R7_PARAMETER":
            "",

        "R7_PROOF":
            "",

        "R7_VULNERABILITY_UUID":
            "",

        "SNYK_ISSUE_ID":
            row.get(
                "ISSUE_ID",
                "",
            ),

        "SNYK_TITLE":
            row.get(
                "TITLE",
                "",
            ),

        "SNYK_SEVERITY":
            row.get(
                "SEVERITY",
                "",
            ),

        "SNYK_STATUS":
            row.get(
                "STATUS",
                "",
            ),

        "SNYK_CWE":
            row.get(
                "CWE",
                "",
            ),

        "SNYK_PROJECT":
            row.get(
                "PROJECT_NAME",
                "",
            ),

        "SNYK_RULE":
            row.get(
                "RULE_KEY",
                "",
            ),

        "SNYK_FILE_PATH":
            row.get(
                "FILE_PATH",
                "",
            ),

        "SNYK_START_LINE":
            row.get(
                "START_LINE",
                "",
            ),

        "SNYK_END_LINE":
            row.get(
                "END_LINE",
                "",
            ),

        "SNYK_RISK_SCORE":
            row.get(
                "RISK_SCORE",
                "",
            ),

        "DESCRIPTION":
            row.get(
                "DESCRIPTION",
                "",
            ),

        "ACTION":
            build_action(
                vulnerability_type,
                row,
            ),

        "VALIDATION":
            build_validation(
                vulnerability_type,
                row,
            ),
    }


# ============================================================
# Determine Report Type
# ============================================================

def process_report(df):
    """
    Determine whether the input is:

        1. Correlation output
        2. Raw Rapid7/Snyk combined report
        3. Raw Rapid7 report
        4. Raw Snyk report
    """

    columns = set(
        df.columns
    )

    # --------------------------------------------------------
    # Correlation output
    # --------------------------------------------------------

    if (
        "CORRELATION_STATUS" in columns
        and
        "R7_VULNERABILITY_UUID" in columns
        and
        "SNYK_ISSUE_ID" in columns
    ):

        rows = []

        for _, row in df.iterrows():

            rows.append(
                build_correlated_risk(
                    row
                )
            )

        return pd.DataFrame(
            rows
        )

    # --------------------------------------------------------
    # Combined raw report
    # --------------------------------------------------------

    if "SOURCE" in columns:

        source = (
            df["SOURCE"]
            .fillna("")
            .astype(str)
            .str.strip()
            .str.upper()
        )

        rows = []

        for _, row in df.iterrows():

            if source.loc[
                row.name
            ] == "RAPID7":

                rows.append(
                    build_rapid7_risk(
                        row
                    )
                )

            elif source.loc[
                row.name
            ] == "SNYK":

                rows.append(
                    build_snyk_risk(
                        row
                    )
                )

        return pd.DataFrame(
            rows
        )

    # --------------------------------------------------------
    # Raw Rapid7
    # --------------------------------------------------------

    if "vulnerability_uuid" in columns:

        return pd.DataFrame(
            [
                build_rapid7_risk(
                    row
                )
                for _, row
                in df.iterrows()
            ]
        )

    # --------------------------------------------------------
    # Raw Snyk
    # --------------------------------------------------------

    if "ISSUE_ID" in columns:

        return pd.DataFrame(
            [
                build_snyk_risk(
                    row
                )
                for _, row
                in df.iterrows()
            ]
        )

    return pd.DataFrame()


# ============================================================
# Discover Security Reports
# ============================================================

if not os.path.isdir(
    ARC_DIR
):

    print(
        f"Directory does not exist: "
        f"{ARC_DIR}"
    )

    raise SystemExit(1)


security_reports = sorted(
    file
    for file in os.listdir(
        ARC_DIR
    )
    if file.endswith(
        "-security-report.csv"
    )
)


if not security_reports:

    print(
        f"No security reports found in: "
        f"{ARC_DIR}"
    )

    raise SystemExit(0)


# ============================================================
# Process Reports
# ============================================================

for report_file in security_reports:

    input_file = os.path.join(
        ARC_DIR,
        report_file,
    )

    app_name = report_file.replace(
        "-security-report.csv",
        "",
    )

    output_file = os.path.join(
        ARC_DIR,
        f"{app_name}-risk-report.csv",
    )

    print()
    print("=" * 70)
    print(
        f"Processing: {report_file}"
    )
    print("=" * 70)

    # --------------------------------------------------------
    # Read CSV
    # --------------------------------------------------------

    try:

        df = pd.read_csv(
            input_file
        )

    except Exception as exc:

        print(
            f"ERROR reading {input_file}: "
            f"{exc}"
        )

        continue

    if df.empty:

        print(
            f"{app_name}: "
            "No findings found."
        )

        continue

    # --------------------------------------------------------
    # Generate normalized report
    # --------------------------------------------------------

    risk_df = process_report(
        df
    )

    if risk_df.empty:

        print(
            f"{app_name}: "
            "Unable to determine report schema."
        )

        continue

    # --------------------------------------------------------
    # Add numeric sort key
    # --------------------------------------------------------

    priority_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
    }

    risk_df["_PRIORITY_SORT"] = (
        risk_df["PRIORITY"]
        .map(
            priority_order
        )
        .fillna(99)
    )

    # Correlated findings should appear before
    # uncorrelated findings of the same priority.
    correlation_order = {
        "CORRELATED": 1,
        "RAPID7_ONLY": 2,
        "SNYK_ONLY": 3,
        "Uncorrelated": 4,
    }

    risk_df["_CORRELATION_SORT"] = (
        risk_df[
            "CORRELATION_STATUS"
        ]
        .map(
            correlation_order
        )
        .fillna(99)
    )

    # Highest confidence first.
    risk_df["_CONFIDENCE_SORT"] = (
        pd.to_numeric(
            risk_df[
                "CONFIDENCE"
            ],
            errors="coerce",
        )
        .fillna(0)
    )

    risk_df = (
        risk_df
        .sort_values(
            by=[
                "_PRIORITY_SORT",
                "_CORRELATION_SORT",
                "_CONFIDENCE_SORT",
            ],
            ascending=[
                True,
                True,
                False,
            ],
        )
    )

    # --------------------------------------------------------
    # Remove internal sort columns
    # --------------------------------------------------------

    risk_df.drop(
        columns=[
            "_PRIORITY_SORT",
            "_CORRELATION_SORT",
            "_CONFIDENCE_SORT",
        ],
        inplace=True,
    )

    # --------------------------------------------------------
    # Write report
    # --------------------------------------------------------

    try:

        risk_df.to_csv(
            output_file,
            index=False,
        )

    except Exception as exc:

        print(
            f"ERROR writing {output_file}: "
            f"{exc}"
        )

        continue

    # ========================================================
    # Summary
    # ========================================================

    critical_count = (
        risk_df["PRIORITY"]
        == "Critical"
    ).sum()

    high_count = (
        risk_df["PRIORITY"]
        == "High"
    ).sum()

    medium_count = (
        risk_df["PRIORITY"]
        == "Medium"
    ).sum()

    low_count = (
        risk_df["PRIORITY"]
        == "Low"
    ).sum()

    correlated_count = (
        risk_df[
            "CORRELATION_STATUS"
        ]
        == "CORRELATED"
    ).sum()

    rapid7_only_count = (
        risk_df[
            "CORRELATION_STATUS"
        ]
        == "RAPID7_ONLY"
    ).sum()

    snyk_only_count = (
        risk_df[
            "CORRELATION_STATUS"
        ]
        == "SNYK_ONLY"
    ).sum()

    print()
    print(
        f"Created: {output_file}"
    )

    print(
        f"Total Risks:       {len(risk_df)}"
    )

    print(
        f"Critical:           {critical_count}"
    )

    print(
        f"High:               {high_count}"
    )

    print(
        f"Medium:             {medium_count}"
    )

    print(
        f"Low:                {low_count}"
    )

    print(
        f"Correlated:         {correlated_count}"
    )

    print(
        f"Rapid7 Only:        {rapid7_only_count}"
    )

    print(
        f"Snyk Only:          {snyk_only_count}"
    )


# ============================================================
# Complete
# ============================================================

print()
print("=" * 70)
print(
    "Risk report generation complete."
)
print("=" * 70)
