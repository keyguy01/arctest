#!/usr/bin/env python3

import os
import re
from datetime import datetime
from difflib import SequenceMatcher
from urllib.parse import urlparse

import pandas as pd


# ============================================================
# Configuration
# ============================================================

RUN_DATE = datetime.now().strftime("%Y-%m-%d")

ARC_INPUT_DIR = os.path.join(
    "reports",
    "arc",
    RUN_DATE,
)

ARC_OUTPUT_DIR = ARC_INPUT_DIR

os.makedirs(
    ARC_OUTPUT_DIR,
    exist_ok=True,
)


# ============================================================
# Correlation Thresholds
# ============================================================

# Minimum score required to report a correlation.
MIN_CORRELATION_SCORE = 45

# Scores are deliberately weighted so that CWE alone does
# NOT automatically create a high-confidence correlation.
SCORE_CWE = 35
SCORE_ATTACK_TYPE = 30
SCORE_PROOF = 20
SCORE_PARAMETER = 15
SCORE_METHOD = 10
SCORE_OWASP = 10
SCORE_TITLE = 15
SCORE_SEVERITY = 5
SCORE_APPLICATION = 10


# ============================================================
# Column Helpers
# ============================================================

def normalize_text(value):
    """Return normalized lowercase text."""
    if value is None or pd.isna(value):
        return ""

    return str(value).strip().lower()


def normalize_upper(value):
    """Return normalized uppercase text."""
    return normalize_text(value).upper()


def ensure_columns(df, columns):
    """
    Ensure every expected column exists.

    Missing columns are populated with blank values.
    """
    for column in columns:
        if column not in df.columns:
            df[column] = ""

    return df


# ============================================================
# CWE Handling
# ============================================================

def normalize_cwes(value):
    """
    Normalize CWE values.

    Examples:

        CWE-79
        CWE-79;CWE-89
        CWE-79, CWE-89

    become:

        {"CWE-79", "CWE-89"}
    """
    if value is None or pd.isna(value):
        return set()

    text = str(value).upper()

    matches = re.findall(
        r"CWE[-_\s]?(\d+)",
        text,
    )

    return {
        f"CWE-{number}"
        for number in matches
    }


# ============================================================
# OWASP Handling
# ============================================================

def normalize_owasp(value):
    """
    Normalize OWASP identifiers.

    Examples:

        OWASP2017-A7
        OWASP2021-A03
        OWASP2025-A01

    become:

        A7
        A03
        A01
    """
    if value is None or pd.isna(value):
        return set()

    text = str(value).upper()

    matches = re.findall(
        r"(?:OWASP\d{4})?-?A(\d{1,3})",
        text,
    )

    return {
        f"A{number.zfill(2)}"
        for number in matches
    }


# ============================================================
# Generic Similarity
# ============================================================

def similarity(a, b):
    """
    SequenceMatcher similarity from 0-100.
    """
    a = normalize_text(a)
    b = normalize_text(b)

    if not a or not b:
        return 0

    return round(
        SequenceMatcher(
            None,
            a,
            b,
        ).ratio() * 100
    )


# ============================================================
# Vulnerability Classification
# ============================================================

VULNERABILITY_PATTERNS = {
    "XSS": [
        r"\bcross[- ]site scripting\b",
        r"\bxss\b",
    ],

    "SQL_INJECTION": [
        r"\bsql injection\b",
        r"\bsqli\b",
        r"\bsql[- ]injection\b",
    ],

    "COMMAND_INJECTION": [
        r"\bcommand injection\b",
        r"\bos command injection\b",
        r"\bcommand execution\b",
    ],

    "PATH_TRAVERSAL": [
        r"\bpath traversal\b",
        r"\bdirectory traversal\b",
    ],

    "SSRF": [
        r"\bserver[- ]side request forgery\b",
        r"\bssrf\b",
    ],

    "XXE": [
        r"\bxml external entity\b",
        r"\bxxe\b",
    ],

    "CSRF": [
        r"\bcross[- ]site request forgery\b",
        r"\bcsrf\b",
    ],

    "OPEN_REDIRECT": [
        r"\bopen redirect\b",
        r"\bunvalidated redirect\b",
    ],

    "IDOR": [
        r"\binsecure direct object reference\b",
        r"\bidor\b",
    ],

    "BROKEN_ACCESS_CONTROL": [
        r"\bbroken access control\b",
        r"\baccess control\b",
        r"\bauthorization\b",
    ],

    "AUTHENTICATION": [
        r"\bauthentication bypass\b",
        r"\bweak authentication\b",
        r"\bauthentication\b",
    ],

    "HARDCODED_SECRET": [
        r"\bhardcoded secret\b",
        r"\bhard-coded secret\b",
        r"\bhardcoded credential\b",
        r"\bembedded credential\b",
    ],

    "WEAK_CRYPTO": [
        r"\bweak cryptograph",
        r"\bweak cipher\b",
        r"\binsecure cipher\b",
        r"\bweak encryption\b",
    ],

    "INSECURE_DESERIALIZATION": [
        r"\binsecure deserialization\b",
        r"\bunsafe deserialization\b",
        r"\bdeserialization\b",
    ],

    "SENSITIVE_DATA_EXPOSURE": [
        r"\bsensitive data\b",
        r"\binformation disclosure\b",
        r"\bsensitive information\b",
        r"\bdata exposure\b",
    ],

    "SECURITY_MISCONFIGURATION": [
        r"\bsecurity misconfiguration\b",
        r"\bmisconfiguration\b",
    ],
}


def detect_vulnerability_types(*values):
    """
    Identify normalized vulnerability classes from
    titles, descriptions, attack types, rules, and proof.
    """
    combined = " ".join(
        normalize_text(value)
        for value in values
        if value is not None
        and not pd.isna(value)
    )

    found = set()

    for vuln_type, patterns in VULNERABILITY_PATTERNS.items():

        for pattern in patterns:

            if re.search(
                pattern,
                combined,
                flags=re.IGNORECASE,
            ):
                found.add(vuln_type)
                break

    return found


# ============================================================
# Rapid7 Attack Type Mapping
# ============================================================

ATTACK_TYPE_MAP = {
    "SC01": "XSS",
    "SC02": "SQL_INJECTION",
    "SC03": "SENSITIVE_DATA_EXPOSURE",
    "SC04": "COMMAND_INJECTION",
    "SC05": "PATH_TRAVERSAL",
    "SC06": "SSRF",
    "SC07": "CSRF",
}


def normalize_attack_type(value):
    """
    Normalize Rapid7 attackType.

    If a known SCxx identifier exists, map it to a
    vulnerability category.

    Unknown attack types are returned as normalized text.
    """
    attack_type = normalize_upper(value)

    if not attack_type:
        return ""

    return ATTACK_TYPE_MAP.get(
        attack_type,
        attack_type,
    )


# ============================================================
# Method Handling
# ============================================================

VALID_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
}


def normalize_method(value):
    method = normalize_upper(value)

    if method in VALID_METHODS:
        return method

    return ""


# ============================================================
# Parameter Extraction
# ============================================================

def normalize_parameter(value):
    """
    Normalize a Rapid7 parameter name.

    Examples:

        ?q
        query
        "q"
        username
    """
    value = normalize_text(value)

    if not value:
        return ""

    value = value.strip(
        " ?&=\"'`"
    )

    # Remove query-string syntax.
    if "=" in value:
        value = value.split(
            "=",
            1,
        )[0]

    value = value.strip(
        " ?&=\"'`"
    )

    return value


def extract_parameter_names(text):
    """
    Extract likely HTTP parameter names from Snyk
    descriptions and surrounding text.

    This is intentionally conservative.
    """
    text = normalize_text(text)

    if not text:
        return set()

    parameters = set()

    # Common wording:
    #
    #   HTTP parameter 'foo'
    #   parameter "foo"
    #   query parameter foo
    #   request parameter foo
    patterns = [
        r"http parameter ['\"]?([a-zA-Z0-9_.-]+)",
        r"query parameter ['\"]?([a-zA-Z0-9_.-]+)",
        r"request parameter ['\"]?([a-zA-Z0-9_.-]+)",
        r"parameter ['\"]([a-zA-Z0-9_.-]+)['\"]",
    ]

    for pattern in patterns:

        matches = re.findall(
            pattern,
            text,
            flags=re.IGNORECASE,
        )

        for match in matches:

            match = match.lower()

            if len(match) >= 2:
                parameters.add(match)

    return parameters


# ============================================================
# URL Handling
# ============================================================

def extract_url_context(url):
    """
    Extract useful context from a Rapid7 rootCause_url.
    """
    url = normalize_text(url)

    if not url:
        return {
            "host": "",
            "path": "",
            "segments": set(),
        }

    try:

        parsed = urlparse(url)

        host = parsed.netloc.lower()

        path = parsed.path.lower()

        segments = {
            segment
            for segment in path.split("/")
            if segment
        }

        return {
            "host": host,
            "path": path,
            "segments": segments,
        }

    except Exception:

        return {
            "host": "",
            "path": url,
            "segments": set(),
        }


# ============================================================
# Application Matching
# ============================================================

def application_similarity(
    r7_app_name,
    snyk_project,
):
    """
    Compare Rapid7 app_name with Snyk project name.

    Returns:
        score, similarity
    """
    r7_app_name = normalize_text(
        r7_app_name
    )

    snyk_project = normalize_text(
        snyk_project
    )

    if not r7_app_name or not snyk_project:
        return 0, 0

    if r7_app_name == snyk_project:
        return (
            SCORE_APPLICATION,
            100,
        )

    score = similarity(
        r7_app_name,
        snyk_project,
    )

    if score >= 85:
        return (
            SCORE_APPLICATION,
            score,
        )

    if score >= 70:
        return (
            SCORE_APPLICATION // 2,
            score,
        )

    return 0, score


# ============================================================
# CWE Signal
# ============================================================

def calculate_cwe_signal(
    r7_cwes,
    snyk_cwes,
):
    shared = r7_cwes.intersection(
        snyk_cwes
    )

    if not shared:
        return 0, set()

    return (
        SCORE_CWE,
        shared,
    )


# ============================================================
# Vulnerability Type Signal
# ============================================================

def calculate_attack_type_signal(
    r7_attack_type,
    r7_types,
    snyk_types,
):
    """
    Compare Rapid7 attackType against Snyk's
    vulnerability classification.
    """
    attack_type = normalize_attack_type(
        r7_attack_type
    )

    if attack_type in snyk_types:
        return (
            SCORE_ATTACK_TYPE,
            {attack_type},
        )

    shared = r7_types.intersection(
        snyk_types
    )

    if shared:
        return (
            SCORE_ATTACK_TYPE,
            shared,
        )

    return 0, set()


# ============================================================
# Title / Description Signal
# ============================================================

def calculate_text_signal(
    r7_text,
    snyk_text,
):
    """
    Compare Rapid7 proof/description against Snyk
    description/title.

    Used as supporting evidence rather than proof.
    """
    score = similarity(
        r7_text,
        snyk_text,
    )

    if score >= 85:
        return (
            SCORE_PROOF,
            score,
        )

    if score >= 70:
        return (
            round(SCORE_PROOF * 0.75),
            score,
        )

    if score >= 55:
        return (
            round(SCORE_PROOF * 0.5),
            score,
        )

    return 0, score


# ============================================================
# Parameter Signal
# ============================================================

def calculate_parameter_signal(
    r7_parameter,
    snyk_text,
):
    """
    Compare Rapid7's rootCause_parameter with
    parameter references in Snyk's description.
    """
    parameter = normalize_parameter(
        r7_parameter
    )

    if not parameter:
        return 0, False

    snyk_parameters = extract_parameter_names(
        snyk_text
    )

    if parameter in snyk_parameters:
        return (
            SCORE_PARAMETER,
            True,
        )

    # Also check for an explicit parameter occurrence,
    # but require word boundaries to reduce false matches.
    if re.search(
        rf"\b{re.escape(parameter)}\b",
        normalize_text(snyk_text),
    ):
        return (
            SCORE_PARAMETER,
            True,
        )

    return 0, False


# ============================================================
# HTTP Method Signal
# ============================================================

def calculate_method_signal(
    r7_method,
    snyk_method,
    snyk_text,
):
    """
    Prefer an explicit Snyk method if available.

    If Snyk doesn't have a method field, look for
    explicit HTTP method references in the description.
    """
    r7_method = normalize_method(
        r7_method
    )

    snyk_method = normalize_method(
        snyk_method
    )

    if not r7_method:
        return 0, False

    if snyk_method:
        return (
            SCORE_METHOD
            if r7_method == snyk_method
            else 0,
            r7_method == snyk_method,
        )

    # Look for explicit HTTP method references.
    pattern = (
        rf"\b{re.escape(r7_method.lower())}"
        rf"\s+(?:request|method)\b"
    )

    if re.search(
        pattern,
        normalize_text(snyk_text),
    ):
        return (
            SCORE_METHOD,
            True,
        )

    return 0, False


# ============================================================
# OWASP Signal
# ============================================================

OWASP_VULNERABILITY_MAP = {
    "A01": {
        "BROKEN_ACCESS_CONTROL",
        "IDOR",
    },

    "A02": {
        "WEAK_CRYPTO",
    },

    "A03": {
        "XSS",
        "SQL_INJECTION",
        "COMMAND_INJECTION",
        "PATH_TRAVERSAL",
        "SSRF",
        "XXE",
        "CSRF",
    },

    "A05": {
        "SECURITY_MISCONFIGURATION",
    },

    "A07": {
        "AUTHENTICATION",
    },

    "A09": {
        "SECURITY_MISCONFIGURATION",
    },

    "A10": {
        "SSRF",
    },
}


def calculate_owasp_signal(
    r7_owasp,
    snyk_types,
):
    """
    Infer whether Rapid7's OWASP category is
    consistent with the Snyk vulnerability type.
    """
    if not r7_owasp or not snyk_types:
        return 0, set()

    matched_categories = set()

    for category in r7_owasp:

        expected_types = (
            OWASP_VULNERABILITY_MAP
            .get(
                category,
                set(),
            )
        )

        if expected_types.intersection(
            snyk_types
        ):
            matched_categories.add(
                category
            )

    if matched_categories:
        return (
            SCORE_OWASP,
            matched_categories,
        )

    return 0, set()


# ============================================================
# Severity Signal
# ============================================================

def calculate_severity_signal(
    r7_severity,
    snyk_severity,
):
    r7 = normalize_upper(
        r7_severity
    )

    snyk = normalize_upper(
        snyk_severity
    )

    if not r7 or not snyk:
        return 0

    if r7 == snyk:
        return SCORE_SEVERITY

    high = {
        "HIGH",
        "CRITICAL",
    }

    if r7 in high and snyk in high:
        return SCORE_SEVERITY

    return 0


# ============================================================
# Main Correlation Function
# ============================================================

def correlate_findings(
    r7,
    snyk,
):
    """
    Compare one Rapid7 finding against one Snyk finding.

    Returns a detailed correlation record or None.
    """

    # --------------------------------------------------------
    # Basic context
    # --------------------------------------------------------

    r7_app_name = r7["app_name"]

    snyk_project = snyk.get(
        "PROJECT_NAME",
        "",
    )

    # --------------------------------------------------------
    # Application signal
    # --------------------------------------------------------

    application_score, application_similarity_score = (
        application_similarity(
            r7_app_name,
            snyk_project,
        )
    )

    # --------------------------------------------------------
    # CWE signal
    # --------------------------------------------------------

    r7_cwes = normalize_cwes(
        r7["CWE"]
    )

    snyk_cwes = normalize_cwes(
        snyk["CWE"]
    )

    cwe_score, shared_cwes = (
        calculate_cwe_signal(
            r7_cwes,
            snyk_cwes,
        )
    )

    # --------------------------------------------------------
    # Vulnerability classification
    # --------------------------------------------------------

    r7_attack_type = normalize_attack_type(
        r7["attackType"]
    )

    r7_types = detect_vulnerability_types(
        r7["attackType"],
        r7["proof"],
        r7["proof_description"],
        r7["OWASP"],
    )

    if r7_attack_type in ATTACK_TYPE_MAP.values():
        r7_types.add(
            r7_attack_type
        )

    snyk_types = detect_vulnerability_types(
        snyk["TITLE"],
        snyk["DESCRIPTION"],
        snyk["RULE_KEY"],
    )

    attack_score, shared_attack_types = (
        calculate_attack_type_signal(
            r7["attackType"],
            r7_types,
            snyk_types,
        )
    )

    # --------------------------------------------------------
    # Proof / description similarity
    # --------------------------------------------------------

    r7_evidence = " ".join(
        [
            normalize_text(
                r7["proof"]
            ),
            normalize_text(
                r7["proof_description"]
            ),
        ]
    )

    snyk_evidence = " ".join(
        [
            normalize_text(
                snyk["TITLE"]
            ),
            normalize_text(
                snyk["DESCRIPTION"]
            ),
            normalize_text(
                snyk["RULE_KEY"]
            ),
        ]
    )

    proof_score, proof_similarity = (
        calculate_text_signal(
            r7_evidence,
            snyk_evidence,
        )
    )

    # --------------------------------------------------------
    # Parameter
    # --------------------------------------------------------

    parameter_score, parameter_match = (
        calculate_parameter_signal(
            r7["rootCause_parameter"],
            snyk_evidence,
        )
    )

    # --------------------------------------------------------
    # HTTP method
    # --------------------------------------------------------

    method_score, method_match = (
        calculate_method_signal(
            r7["rootCause_method"],
            snyk.get(
                "METHOD",
                "",
            ),
            snyk_evidence,
        )
    )

    # --------------------------------------------------------
    # OWASP
    # --------------------------------------------------------

    r7_owasp = normalize_owasp(
        r7["OWASP"]
    )

    owasp_score, matched_owasp = (
        calculate_owasp_signal(
            r7_owasp,
            snyk_types,
        )
    )

    # --------------------------------------------------------
    # Title similarity
    # --------------------------------------------------------

    title_similarity_score = similarity(
        r7["attackType"],
        snyk["TITLE"],
    )

    title_score = 0

    if title_similarity_score >= 80:
        title_score = SCORE_TITLE

    elif title_similarity_score >= 65:
        title_score = round(
            SCORE_TITLE * 0.5
        )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity_score = (
        calculate_severity_signal(
            r7["severity"],
            snyk["SEVERITY"],
        )
    )

    # --------------------------------------------------------
    # Calculate total
    # --------------------------------------------------------

    confidence = (
        application_score
        + cwe_score
        + attack_score
        + proof_score
        + parameter_score
        + method_score
        + owasp_score
        + title_score
        + severity_score
    )

    confidence = min(
        confidence,
        100,
    )

    # --------------------------------------------------------
    # Build reasons
    # --------------------------------------------------------

    reasons = []

    if application_score:
        reasons.append(
            f"Application match "
            f"({application_similarity_score}%)"
        )

    if shared_cwes:
        reasons.append(
            "Shared CWE: "
            + ", ".join(
                sorted(shared_cwes)
            )
        )

    if shared_attack_types:
        reasons.append(
            "Vulnerability type: "
            + ", ".join(
                sorted(shared_attack_types)
            )
        )

    if parameter_match:
        reasons.append(
            f"Parameter match: "
            f"{normalize_parameter(r7['rootCause_parameter'])}"
        )

    if method_match:
        reasons.append(
            f"HTTP method match: "
            f"{normalize_method(r7['rootCause_method'])}"
        )

    if matched_owasp:
        reasons.append(
            "OWASP category consistent: "
            + ", ".join(
                sorted(matched_owasp)
            )
        )

    if proof_score:
        reasons.append(
            f"Evidence similarity "
            f"({proof_similarity}%)"
        )

    if title_score:
        reasons.append(
            f"Attack/title similarity "
            f"({title_similarity_score}%)"
        )

    if severity_score:
        reasons.append(
            "Severity agreement"
        )

    # --------------------------------------------------------
    # Correlation quality rules
    # --------------------------------------------------------

    # CWE by itself is not enough.
    evidence_signals = sum(
        [
            bool(shared_cwes),
            bool(shared_attack_types),
            bool(parameter_match),
            bool(method_match),
            bool(matched_owasp),
            proof_score > 0,
            title_score > 0,
        ]
    )

    # Reject weak single-signal matches.
    if evidence_signals < 2:
        return None

    if confidence < MIN_CORRELATION_SCORE:
        return None

    # --------------------------------------------------------
    # Determine level
    # --------------------------------------------------------

    if confidence >= 85:
        level = "High"

    elif confidence >= 65:
        level = "Medium"

    else:
        level = "Low"

    # --------------------------------------------------------
    # Return detailed record
    # --------------------------------------------------------

    return {
        "CONFIDENCE": confidence,

        "CORRELATION_LEVEL": level,

        "MATCH_REASON": " | ".join(
            reasons
        ),

        "SHARED_CWES": ";".join(
            sorted(shared_cwes)
        ),

        "VULNERABILITY_TYPES": ";".join(
            sorted(shared_attack_types)
        ),

        "OWASP_MATCH": ";".join(
            sorted(matched_owasp)
        ),

        "APPLICATION_SIMILARITY":
            application_similarity_score,

        "TITLE_SIMILARITY":
            title_similarity_score,

        "PROOF_SIMILARITY":
            proof_similarity,

        "PARAMETER_MATCH":
            parameter_match,

        "METHOD_MATCH":
            method_match,

        "CWE_SCORE":
            cwe_score,

        "ATTACK_TYPE_SCORE":
            attack_score,

        "PROOF_SCORE":
            proof_score,

        "PARAMETER_SCORE":
            parameter_score,

        "METHOD_SCORE":
            method_score,

        "OWASP_SCORE":
            owasp_score,

        "TITLE_SCORE":
            title_score,

        "SEVERITY_SCORE":
            severity_score,
    }


# ============================================================
# Discover Reports
# ============================================================

if not os.path.isdir(
    ARC_INPUT_DIR
):

    print(
        f"Input directory does not exist: "
        f"{ARC_INPUT_DIR}"
    )

    raise SystemExit(1)


security_reports = sorted(
    file
    for file in os.listdir(
        ARC_INPUT_DIR
    )
    if file.endswith(
        "-security-report.csv"
    )
)

if not security_reports:

    print(
        f"No security report files found in: "
        f"{ARC_INPUT_DIR}"
    )

    raise SystemExit(0)


# ============================================================
# Process Each Application
# ============================================================

for report_file in security_reports:

    report_path = os.path.join(
        ARC_INPUT_DIR,
        report_file,
    )

    app_name = report_file.replace(
        "-security-report.csv",
        "",
    )

    output_file = os.path.join(
        ARC_OUTPUT_DIR,
        f"{app_name}-correlated-findings.csv",
    )

    print()
    print("=" * 75)
    print(
        f"Processing: {report_file}"
    )
    print("=" * 75)

    # --------------------------------------------------------
    # Read CSV
    # --------------------------------------------------------

    try:

        df = pd.read_csv(
            report_path
        )

    except Exception as exc:

        print(
            f"ERROR reading {report_file}: "
            f"{exc}"
        )

        continue

    if df.empty:

        print(
            f"{app_name}: "
            "No findings available."
        )

        continue

    # --------------------------------------------------------
    # Expected columns
    # --------------------------------------------------------

    required_columns = [
        # Rapid7
        "app_name",
        "app_description",
        "app_uuid",
        "vulnerability_uuid",
        "severity",
        "status",
        "vulnerabilityScore",
        "moduleName",
        "attackType",
        "rootCause_url",
        "rootCause_method",
        "rootCause_parameter",
        "firstDiscovered",
        "lastDiscovered",
        "scan_uuid",
        "scan_type",
        "scan_submit_time",
        "scan_completion_time",
        "vectorString",
        "insightUrl",
        "variance_count",
        "CWE",
        "OWASP",
        "proof",
        "proof_description",

        # Snyk
        "ISSUE_ID",
        "RULE_KEY",
        "TITLE",
        "SEVERITY",
        "STATUS",
        "DESCRIPTION",
        "CWE",
        "FILE_PATH",
        "START_LINE",
        "START_COLUMN",
        "END_LINE",
        "END_COLUMN",
        "RISK_SCORE",
        "REMEDIATION",
        "CREATED_AT",
        "UPDATED_AT",
        "PROJECT_NAME",
        "METHOD",
    ]

    # NOTE:
    # Rapid7 and Snyk both have a CWE column, but pandas cannot
    # distinguish duplicate column names reliably after reading
    # a combined CSV.
    #
    # If your input CSV contains columns named:
    #
    #   R7_CWE
    #   SNYK_CWE
    #
    # those should be used instead.
    #
    # Otherwise this script expects your upstream correlation
    # process to rename duplicate columns.

    for column in required_columns:

        if column not in df.columns:

            df[column] = ""

    # --------------------------------------------------------
    # Source filtering
    # --------------------------------------------------------

    if "SOURCE" not in df.columns:

        print(
            f"{app_name}: "
            "CSV does not contain SOURCE column."
        )

        continue

    source = (
        df["SOURCE"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.upper()
    )

    rapid7_df = df[
        source == "RAPID7"
    ].copy()

    snyk_df = df[
        source == "SNYK"
    ].copy()

    print(
        f"Rapid7 Findings: {len(rapid7_df)}"
    )

    print(
        f"Snyk Findings:   {len(snyk_df)}"
    )

    if rapid7_df.empty:

        print(
            f"{app_name}: "
            "No Rapid7 findings."
        )

        continue

    if snyk_df.empty:

        print(
            f"{app_name}: "
            "No Snyk findings."
        )

        continue

    # ========================================================
    # Correlate
    # ========================================================

    correlations = []

    for _, r7 in rapid7_df.iterrows():

        for _, snyk in snyk_df.iterrows():

            result = correlate_findings(
                r7,
                snyk,
            )

            if result is None:
                continue

            correlation = {
                "APP_NAME": app_name,

                "CORRELATION_STATUS":
                    "MATCHED",

                # ------------------------------------------------
                # Confidence
                # ------------------------------------------------

                **result,

                # ------------------------------------------------
                # Rapid7
                # ------------------------------------------------

                "R7_APP_NAME":
                    r7.get("app_name", ""),

                "R7_APP_UUID":
                    r7.get("app_uuid", ""),

                "R7_VULNERABILITY_UUID":
                    r7.get(
                        "vulnerability_uuid",
                        "",
                    ),

                "R7_SEVERITY":
                    r7.get(
                        "severity",
                        "",
                    ),

                "R7_STATUS":
                    r7.get(
                        "status",
                        "",
                    ),

                "R7_VULNERABILITY_SCORE":
                    r7.get(
                        "vulnerabilityScore",
                        "",
                    ),

                "R7_MODULE":
                    r7.get(
                        "moduleName",
                        "",
                    ),

                "R7_ATTACK_TYPE":
                    r7.get(
                        "attackType",
                        "",
                    ),

                "R7_URL":
                    r7.get(
                        "rootCause_url",
                        "",
                    ),

                "R7_METHOD":
                    r7.get(
                        "rootCause_method",
                        "",
                    ),

                "R7_PARAMETER":
                    r7.get(
                        "rootCause_parameter",
                        "",
                    ),

                "R7_CWE":
                    r7.get(
                        "CWE",
                        "",
                    ),

                "R7_OWASP":
                    r7.get(
                        "OWASP",
                        "",
                    ),

                "R7_PROOF":
                    r7.get(
                        "proof",
                        "",
                    ),

                "R7_PROOF_DESCRIPTION":
                    r7.get(
                        "proof_description",
                        "",
                    ),

                "R7_FIRST_DISCOVERED":
                    r7.get(
                        "firstDiscovered",
                        "",
                    ),

                "R7_LAST_DISCOVERED":
                    r7.get(
                        "lastDiscovered",
                        "",
                    ),

                "R7_SCAN_UUID":
                    r7.get(
                        "scan_uuid",
                        "",
                    ),

                "R7_SCAN_TYPE":
                    r7.get(
                        "scan_type",
                        "",
                    ),

                "R7_VECTOR":
                    r7.get(
                        "vectorString",
                        "",
                    ),

                "R7_INSIGHT_URL":
                    r7.get(
                        "insightUrl",
                        "",
                    ),

                # ------------------------------------------------
                # Snyk
                # ------------------------------------------------

                "SNYK_ISSUE_ID":
                    snyk.get(
                        "ISSUE_ID",
                        "",
                    ),

                "SNYK_RULE":
                    snyk.get(
                        "RULE_KEY",
                        "",
                    ),

                "SNYK_TITLE":
                    snyk.get(
                        "TITLE",
                        "",
                    ),

                "SNYK_SEVERITY":
                    snyk.get(
                        "SEVERITY",
                        "",
                    ),

                "SNYK_STATUS":
                    snyk.get(
                        "STATUS",
                        "",
                    ),

                "SNYK_DESCRIPTION":
                    snyk.get(
                        "DESCRIPTION",
                        "",
                    ),

                "SNYK_CWE":
                    snyk.get(
                        "CWE",
                        "",
                    ),

                "SNYK_FILE_PATH":
                    snyk.get(
                        "FILE_PATH",
                        "",
                    ),

                "SNYK_START_LINE":
                    snyk.get(
                        "START_LINE",
                        "",
                    ),

                "SNYK_START_COLUMN":
                    snyk.get(
                        "START_COLUMN",
                        "",
                    ),

                "SNYK_END_LINE":
                    snyk.get(
                        "END_LINE",
                        "",
                    ),

                "SNYK_END_COLUMN":
                    snyk.get(
                        "END_COLUMN",
                        "",
                    ),

                "SNYK_RISK_SCORE":
                    snyk.get(
                        "RISK_SCORE",
                        "",
                    ),

                "SNYK_REMEDIATION":
                    snyk.get(
                        "REMEDIATION",
                        "",
                    ),

                "SNYK_PROJECT":
                    snyk.get(
                        "PROJECT_NAME",
                        "",
                    ),

                "SNYK_CREATED_AT":
                    snyk.get(
                        "CREATED_AT",
                        "",
                    ),

                "SNYK_UPDATED_AT":
                    snyk.get(
                        "UPDATED_AT",
                        "",
                    ),
            }

            correlations.append(
                correlation
            )

    # ========================================================
    # Output
    # ========================================================

    correlated_df = pd.DataFrame(
        correlations
    )

    if correlated_df.empty:

        print()
        print(
            f"{app_name}: "
            "No correlations found."
        )

        continue

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    correlated_df = (
        correlated_df
        .drop_duplicates(
            subset=[
                "R7_VULNERABILITY_UUID",
                "SNYK_ISSUE_ID",
            ]
        )
    )

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    correlated_df = (
        correlated_df
        .sort_values(
            by=[
                "CONFIDENCE",
                "CWE_SCORE",
                "ATTACK_TYPE_SCORE",
                "PROOF_SCORE",
            ],
            ascending=False,
        )
    )

    # --------------------------------------------------------
    # Write
    # --------------------------------------------------------

    try:

        correlated_df.to_csv(
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

    high_count = (
        correlated_df[
            "CORRELATION_LEVEL"
        ] == "High"
    ).sum()

    medium_count = (
        correlated_df[
            "CORRELATION_LEVEL"
        ] == "Medium"
    ).sum()

    low_count = (
        correlated_df[
            "CORRELATION_LEVEL"
        ] == "Low"
    ).sum()

    print()
    print(
        f"Created: {output_file}"
    )

    print(
        f"Correlations Found: "
        f"{len(correlated_df)}"
    )

    print(
        f"High:   {high_count}"
    )

    print(
        f"Medium: {medium_count}"
    )

    print(
        f"Low:    {low_count}"
    )


# ============================================================
# Complete
# ============================================================

print()
print("=" * 75)
print("Correlation processing complete.")
print("=" * 75)
