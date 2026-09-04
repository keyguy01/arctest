#!/usr/bin/env python3

import os
import pandas as pd

from datetime import datetime

RUN_DATE = datetime.now().strftime("%Y-%m-%d")

# --------------------------------------------------
# Configuration
# --------------------------------------------------

ARC_DIR = os.path.join(
    "reports",
    "arc",
    RUN_DATE
)

os.makedirs(
    ARC_DIR,
    exist_ok=True
)

prioritized_reports = [

    file

    for file in os.listdir(ARC_DIR)

    if file.endswith("-prioritized-findings.csv")

]

if not prioritized_reports:

    print(
        "No prioritized findings reports found."
    )

    raise SystemExit(0)

    print()

    print("=" * 60)
    print(f"ARC_DIR: {ARC_DIR}")

    print(
        f"Prioritized Reports Found: "
        f"{len(prioritized_reports)}"
    )

    for file in prioritized_reports:
        print(f"  {file}")

    print("=" * 60)
    print()

    os.makedirs(
        ARC_DIR,
        exist_ok=True
    )

for report_file in prioritized_reports:

    INPUT_FILE = os.path.join(
        ARC_DIR,
        report_file
    )

    APP_NAME = (
        report_file
        .replace(
            "-prioritized-findings.csv",
            ""
        )
    )

    MD_OUTPUT = os.path.join(
        ARC_DIR,
        f"{APP_NAME}-remediation-package.md"
    )

    HTML_OUTPUT = os.path.join(
        ARC_DIR,
        f"{APP_NAME}-remediation-package.html"
    )

    print()
    print(
        f"Processing: {APP_NAME}"
    )

# --------------------------------------------------
# Security Knowledge Base
# --------------------------------------------------

    KNOWLEDGE_BASE = {

    "CWE-89": {
        "impact":
            "Potential database manipulation, disclosure of sensitive information, and unauthorized access.",

        "action":
            "Replace dynamic SQL with parameterized queries or prepared statements.",

        "testing":
            "Validate all create, read, update and delete workflows. Re-run Snyk and Rapid7 scans."
    },

    "CWE-79": {
        "impact":
            "Potential execution of malicious client-side scripts and compromise of user sessions.",

        "action":
            "Implement output encoding and input validation. Avoid rendering untrusted content.",

        "testing":
            "Test reflected, stored and DOM-based XSS scenarios. Re-run Snyk and Rapid7 scans."
    },

    "CWE-22": {
        "impact":
            "Potential unauthorized access to files and directories outside intended locations.",

        "action":
            "Normalize and validate paths. Restrict file access to approved locations.",

        "testing":
            "Test path traversal payloads and verify unauthorized files cannot be accessed."
    },

    "CWE-798": {
        "impact":
            "Credentials may be exposed and used to gain unauthorized access.",

        "action":
            "Move credentials to a secure secrets management solution and remove them from source code.",

        "testing":
            "Verify application functionality after secret rotation."
        }
    }

# --------------------------------------------------
# Helpers
# --------------------------------------------------

    def get_kb(cwe):

        if pd.isna(cwe):
            return None

        cwe_string = str(cwe)

        for key, value in KNOWLEDGE_BASE.items():

            if key in cwe_string:
                return value

        return {
            "impact":
                "Review finding with application owner.",

            "action":
                "Review vendor remediation guidance.",

            "testing":
                "Re-run security scans and perform regression testing."
        }

# --------------------------------------------------
# Load Data
# --------------------------------------------------

    print(f"Loading {INPUT_FILE}")

    df = pd.read_csv(INPUT_FILE)

    if df.empty:
        raise Exception(
            "No prioritized findings available."
        )

    # --------------------------------------------------
    # High / Critical Only
    # --------------------------------------------------
    print(df)
    df = df[
        df["PRIORITY"]
        .str.upper()
        .isin(
            [
                "CRITICAL",
                "HIGH"
            ]
        )
    ]

    print(
        f"High/Critical Findings: {len(df)}"
    )

    # --------------------------------------------------
    # Sort Findings
    # --------------------------------------------------

    priority_order = {
        "CRITICAL": 1,
        "HIGH": 2
    }

    df["RANK"] = (
        df["PRIORITY"]
        .str.upper()
        .map(priority_order)
        .fillna(99)
    )

    df = df.sort_values(
        by=[
            "RANK",
            "OCCURRENCES"
        ],
        ascending=[
            True,
            False
        ]
    )

    print()
    print("Top Findings Selected For Remediation Package")
    print(
        df[
            [
                "PRIORITY",
                "TITLE",
                "OCCURRENCES"
            ]
        ]
        .head(10)
    )
    print()

    # --------------------------------------------------
    # Markdown Report
    # --------------------------------------------------

    markdown = f"""# Application Remediation Package

    ## Application

    {APP_NAME}

    ## Scope

    This remediation package contains Critical and High severity findings requiring immediate developer review.

    ---

    """

    for _, row in df.iterrows():

        kb = get_kb(
            row.get("CWE")
        )

        markdown += f"""
    # {row['TITLE']}

    ## Priority

    {row['PRIORITY']}

    ## Source

    {row['SOURCE']}

    ## CWE

    {row.get('CWE', '')}

    ## Occurrences

    {row['OCCURRENCES']}

    ## Remediation Scope

    {row.get('REMEDIATION_SCOPE', '')}

    ## Files Requiring Review

    {row.get('FILE_COUNT', 0)}

    ## Primary Application Areas

    {row.get('TOP_DIRECTORIES', '')}

    ## Business / Security Impact

    {kb['impact']}

    ## Developer Action

    {kb['action']}

    ## Files Requiring Review

    {row.get('AFFECTED_FILES', '')}

    ## URLs Requiring Validation

    {row.get('AFFECTED_URLS', '')}

    ## Validation Requirements

    {kb['testing']}

    ---

    """

    markdown += """

    # Security Engineering Notes

    The findings above represent the highest priority remediation items for this application.

    Recommended workflow:

    1. Address Critical findings first.
    2. Address High findings second.
    3. Perform code review and remediation.
    4. Re-run Snyk scans.
    5. Re-run Rapid7 scans.
    6. Perform regression testing.
    7. Validate business workflows.

    ## Exit Criteria

    Before closure:

    - Snyk findings remediated or accepted.
    - Rapid7 findings remediated or accepted.
    - Validation testing completed.
    - Security Engineering review completed.

    """

    # --------------------------------------------------
    # HTML Report
    # --------------------------------------------------

    html = f"""
    <!DOCTYPE html>
    <html>

    <head>

    <title>{APP_NAME} Remediation Package</title>

    <style>

    body {{
        font-family: Arial, sans-serif;
        margin: 30px;
    }}

    h1 {{
        color: #003366;
    }}

    h2 {{
        border-bottom: 1px solid #dddddd;
        padding-bottom: 5px;
    }}

    .finding {{
        border: 1px solid #cccccc;
        padding: 15px;
        margin-bottom: 20px;
    }}

    .priority {{
        color: #c62828;
        font-weight: bold;
    }}

    pre {{
        background-color: #f7f7f7;
        padding: 10px;
        overflow-x: auto;
    }}

    </style>

    </head>

    <body>

    <h1>Application Remediation Package</h1>

    <h2>{APP_NAME}</h2>

    <p>
    This package contains Critical and High severity findings requiring immediate remediation.
    </p>

    """

    for _, row in df.iterrows():

        kb = get_kb(
            row.get("CWE")
        )

        html += f"""
    <div class="finding">

    <h2>{row['TITLE']}</h2>

    <p>
    <b>Priority:</b>
    <span class="priority">
    {row['PRIORITY']}
    </span>
    </p>

    <p><b>Source:</b> {row['SOURCE']}</p>

    <p><b>CWE:</b> {row.get('CWE', '')}</p>

    <p><b>Occurrences:</b> {row['OCCURRENCES']}</p>

    <p>
    <b>Remediation Scope:</b>
    {row.get('REMEDIATION_SCOPE','')}
    </p>

    <p>
    <b>Files Requiring Review:</b>
    {row.get('FILE_COUNT',0)}
    </p>

    <h3>Primary Application Areas</h3>

    <pre>
    {row.get('TOP_DIRECTORIES','')}
    </pre>

    <h3>Business / Security Impact</h3>

    <p>{kb['impact']}</p>

    <h3>Developer Action</h3>

    <p>{kb['action']}</p>

    <h3>Files Requiring Review</h3>

    <pre>
    {row.get('AFFECTED_FILES', '')}
    </pre>

    <h3>URLs Requiring Validation</h3>

    <pre>
    {row.get('AFFECTED_URLS', '')}
    </pre>

    <h3>Validation Requirements</h3>

    <p>{kb['testing']}</p>

    </div>
    """

    html += """
    </body>
    </html>
    """

    with open(
        MD_OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(markdown)

    with open(
        HTML_OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(html)

    print()
    print("=" * 60)
    print(f"Application: {APP_NAME}")
    print(f"Remediation Items: {len(df)}")
    print(f"Created: {MD_OUTPUT}")
    print(f"Created: {HTML_OUTPUT}")
    print("=" * 60)    
