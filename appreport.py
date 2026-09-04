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
    print("No prioritized findings reports found.")
    raise SystemExit(0)

print()
print("=" * 60)
print(f"ARC_DIR: {ARC_DIR}")
print(f"Prioritized Reports Found: {len(prioritized_reports)}")

for file in prioritized_reports:
    print(f"  {file}")

print("=" * 60)
print()

for report_file in prioritized_reports:

    INPUT_FILE = os.path.join(
        ARC_DIR,
        report_file
    )

    APP_NAME = report_file.replace(
        "-prioritized-findings.csv",
        ""
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
    print(f"Processing: {APP_NAME}")

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
            return {
                "impact": "Review finding with application owner.",
                "action": "Review vendor remediation guidance.",
                "testing": "Re-run security scans and perform regression testing."
            }

        cwe_string = str(cwe)

        for key, value in KNOWLEDGE_BASE.items():
            if key in cwe_string:
                return value

        return {
            "impact": "Review finding with application owner.",
            "action": "Review vendor remediation guidance.",
            "testing": "Re-run security scans and perform regression testing."
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

    required_columns = [
        "TITLE",
        "SOURCE",
        "PRIORITY",
        "OCCURRENCES"
    ]

    missing = [
        c for c in required_columns
        if c not in df.columns
    ]

    if missing:
        raise Exception(
            f"Missing required columns: {missing}"
        )

    df["PRIORITY"] = (
        df["PRIORITY"]
        .fillna("")
        .astype(str)
    )

    # --------------------------------------------------
    # High / Critical Only
    # --------------------------------------------------

    df = df[
        df["PRIORITY"]
        .str.upper()
        .isin([
            "CRITICAL",
            "HIGH"
        ])
    ].copy()

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
        ].head(10)
    )

    print()

    # --------------------------------------------------
    # Developer Markdown
    # --------------------------------------------------

    developer_md = f"""# Developer Security Action Report

    ## Application

    {APP_NAME}

    ## Overall Risk

    {overall_risk}

    ## Risk Reduction Summary

    - Raw Findings Reviewed: {raw_finding_count}
    - Unique Findings: {unique_finding_count}
    - High / Critical Findings: {priority_finding_count}

    ## Finding Summary

    | Priority | Count |
    |-----------|--------|
    | Critical | {critical_count} |
    | High | {high_count} |
    | Medium | {medium_count} |
    | Low | {low_count} |

    ---

    # Fix First (Critical / High)

    """

    for _, row in fix_first.head(15).iterrows():

        developer_md += f"""
    ## {row['NORMALIZED_TITLE']}

    Priority: {row['PRIORITY']}

    Source: {row['SOURCE']}

    Remediation Scope: {row.get('REMEDIATION_SCOPE', '')}

    Occurrences: {row['OCCURRENCES']}

    Files Affected: {row.get('FILE_COUNT', 0)}

    CWE: {row.get('CWE', '')}

    ### Primary Application Areas

    {row.get('TOP_DIRECTORIES', '')}

    ### Files Requiring Review

    {row.get('AFFECTED_FILES', '')}

    ### Affected URLs

    {row.get('AFFECTED_URLS', '')}

    ### Recommended Action

    {row.get('RECOMMENDED_ACTION', '')}

    ### Testing Validation

    {row.get('VALIDATION', '')}

    ---
    """

    developer_md += """

    # Security Engineering Notes

    1. Address Critical and High findings first.
    2. Prioritize code vulnerabilities before runtime hardening.
    3. Re-run Snyk after remediation.
    4. Re-run Rapid7 authenticated scans.
    5. Perform regression testing before production deployment.
    """

    developer_md += """

    # Fix Next (Medium Findings)

    """

    for _, row in fix_next.head(10).iterrows():

        developer_md += f"""
    ## {row['NORMALIZED_TITLE']}

    Priority: {row['PRIORITY']}

    Occurrences: {row['OCCURRENCES']}

    Files Affected: {row.get('FILE_COUNT', 0)}

    URLs Affected: {row.get('URL_COUNT', 0)}

    ---
    """

    developer_md += """

    # Defense In Depth (Low Findings)

    These findings do not typically require immediate remediation but should be included in future hardening efforts.

    """

    for _, row in defense_in_depth.head(10).iterrows():

        developer_md += f"""
    ## {row['NORMALIZED_TITLE']}

    Occurrences: {row['OCCURRENCES']}

    Files Affected: {row.get('FILE_COUNT', 0)}

    URLs Affected: {row.get('URL_COUNT', 0)}

    ---
    """

    # --------------------------------------------------
    # Executive Markdown
    # --------------------------------------------------

    executive_md = f"""# Executive Application Security Report

    ## Application

    {APP_NAME}

    ## Overall Risk

    {overall_risk}

    ## Findings at a Glance

    - Critical Findings: {critical_count}
    - High Findings: {high_count}
    - Medium Findings: {medium_count}
    - Low Findings: {low_count}

    ## Risk Reduction Summary

    - Raw Findings Reviewed: {raw_finding_count}
    - Unique Findings Identified: {unique_finding_count}
    - High / Critical Findings Requiring Action: {priority_finding_count}

    ---

    ## Top Risks

    """

    for _, row in top_findings.head(10).iterrows():

        executive_md += (
        f"- {row['NORMALIZED_TITLE']} | "
        f"Scope: {row.get('REMEDIATION_SCOPE','')} | "
        f"Files: {row.get('FILE_COUNT',0)} | "
        f"Occurrences: {row['OCCURRENCES']}\n"
    )

    executive_md += """

    ## Recommended Actions

    1. Prioritize remediation of Critical and High severity findings.
    2. Address SQL Injection and Cross-Site Scripting findings first.
    3. Implement missing runtime security controls.
    4. Re-scan application after remediation.
    5. Track remediation through Security Engineering review workflow.

    ## Program Notes

    This report consolidates SAST and DAST observations for application risk review and remediation planning.
    """

    # --------------------------------------------------
    # HTML Builder
    # --------------------------------------------------

    def build_developer_html(
        app_name,
        overall_risk,
        critical_count,
        high_count,
        medium_count,
        low_count,
        top_sast,
        top_dast
    ):

        html = f"""
    <!DOCTYPE html>
    <html>

    <head>

    <title>{app_name} Developer Security Report</title>

    <style>

    body {{
        font-family: Arial, sans-serif;
        margin: 30px;
        color: #222;
    }}

    h1 {{
        color: #003366;
    }}

    h2 {{
        border-bottom: 2px solid #dddddd;
        padding-bottom: 4px;
    }}

    .summary {{
        margin-bottom: 25px;
    }}

    .risk-high {{
        color: #c62828;
        font-weight: bold;
    }}

    .risk-medium {{
        color: #f57c00;
        font-weight: bold;
    }}

    .risk-low {{
        color: #2e7d32;
        font-weight: bold;
    }}

    table {{
        border-collapse: collapse;
        width: 600px;
    }}

    table, th, td {{
        border: 1px solid #cccccc;
    }}

    th {{
        background-color: #eeeeee;
    }}

    th, td {{
        padding: 8px;
        text-align: left;
    }}

    .finding {{
        margin-bottom: 8px;
    }}

    </style>

    </head>

    <body>

    <h1>Developer Application Security Report</h1>

    <h2>{app_name}</h2>

    <div class="summary">

    <p>
    <strong>Overall Risk:</strong>
    <span class="risk-high">
    {overall_risk}
    </span>
    </p>

    </div>

    <h2>Findings At A Glance</h2>

    <table>

    <tr>
    <th>Priority</th>
    <th>Count</th>
    </tr>

    <tr>
    <td>Critical</td>
    <td>{critical_count}</td>
    </tr>

    <tr>
    <td>High</td>
    <td>{high_count}</td>
    </tr>

    <tr>
    <td>Medium</td>
    <td>{medium_count}</td>
    </tr>

    <tr>
    <td>Low</td>
    <td>{low_count}</td>
    </tr>

    </table>

    <h2>Risk Reduction Summary</h2>

    <ul>
    <li>Raw Findings Reviewed: {raw_finding_count}</li>
    <li>Unique Findings Identified: {unique_finding_count}</li>
    <li>High/Critical Findings: {priority_finding_count}</li>
    </ul>

    <h2>Top SAST Risks</h2>

    <ul>
    """

        for _, row in top_sast.iterrows():

            html += f"""

    <li>

    <strong>
    {row['NORMALIZED_TITLE']}
    </strong>

    <br>

    Priority:
    {row['PRIORITY']}

    <br>

    Scope:
    {row.get('REMEDIATION_SCOPE','')}

    <br>

    Occurrences:
    {row['OCCURRENCES']}

    <br>

    Files Affected:
    {row.get('FILE_COUNT',0)}

    <br>

    CWE:
    {row.get('CWE','')}

    <br><br>

    <strong>
    Primary Directories
    </strong>

    <pre>
    {row.get('TOP_DIRECTORIES','')}
    </pre>

    <details>

    <summary>
    View Files
    </summary>

    <pre>
    {row.get('AFFECTED_FILES','')}
    </pre>

    </details>

    </li>
    """

        html += """
    </ul>

    <h2>Top DAST Risks</h2>

    <ul>
    """

        for _, row in top_dast.iterrows():

            html += f"""

    <li>
    <strong>{row['NORMALIZED_TITLE']}</strong><br>
    Occurrences: {row['OCCURRENCES']}<br>
    URLs Affected: {row.get('URL_COUNT', 0)}<br>
    </li>
    """

        html += """
    </ul>

    <h2>Recommended Actions</h2>

    <ol>
    <li>Prioritize High severity code vulnerabilities.</li>
    <li>Address SQL Injection and Cross-Site Scripting findings first.</li>
    <li>Implement missing runtime security controls.</li>
    <li>Re-run Snyk and Rapid7 validation scans.</li>
    <li>Perform regression testing before deployment.</li>
    </ol>

    </body>
    </html>
    """
        return html

    def build_executive_html(
        app_name,
        overall_risk,
        critical_count,
        high_count,
        medium_count,
        low_count,
        top_sast,
        top_dast
    ):

        html = f"""
    <!DOCTYPE html>
    <html>

    <head>

    <title>{app_name} Executive Security Report</title>

    <style>

    body {{
        font-family: Arial, sans-serif;
        margin: 30px;
        color: #222;
    }}

    h1 {{
        color: #003366;
    }}

    h2 {{
        border-bottom: 2px solid #dddddd;
        padding-bottom: 4px;
    }}

    .summary {{
        margin-bottom: 25px;
    }}

    .risk-high {{
        color: #c62828;
        font-weight: bold;
    }}

    .risk-medium {{
        color: #f57c00;
        font-weight: bold;
    }}

    .risk-low {{
        color: #2e7d32;
        font-weight: bold;
    }}

    table {{
        border-collapse: collapse;
        width: 600px;
    }}

    table, th, td {{
        border: 1px solid #cccccc;
    }}

    th {{
        background-color: #eeeeee;
    }}

    th, td {{
        padding: 8px;
        text-align: left;
    }}

    .finding {{
        margin-bottom: 8px;
    }}

    </style>

    </head>

    <body>

    <h1>Executive Application Security Report</h1>

    <h2>{app_name}</h2>

    <div class="summary">

    <p>
    <strong>Overall Risk:</strong>
    <span class="risk-high">
    {overall_risk}
    </span>
    </p>

    </div>

    <h2>Findings At A Glance</h2>

    <table>

    <tr>
    <th>Priority</th>
    <th>Count</th>
    </tr>

    <tr>
    <td>Critical</td>
    <td>{critical_count}</td>
    </tr>

    <tr>
    <td>High</td>
    <td>{high_count}</td>
    </tr>

    <tr>
    <td>Medium</td>
    <td>{medium_count}</td>
    </tr>

    <tr>
    <td>Low</td>
    <td>{low_count}</td>
    </tr>

    </table>

    <h2>Top SAST Risks</h2>

    <ul>
    """

        for _, row in top_sast.iterrows():

            html += f"""

    <li>

    <strong>
    {row['NORMALIZED_TITLE']}
    </strong>

    <br>

    Scope:
    {row.get('REMEDIATION_SCOPE','')}

    <br>

    Files:
    {row.get('FILE_COUNT',0)}

    <br>

    Occurrences:
    {row['OCCURRENCES']}

    <br>

    Primary Areas:

    <pre>
    {row.get('TOP_DIRECTORIES','')}
    </pre>

    </li>
    """

        html += """
    </ul>

    <h2>Top DAST Risks</h2>

    <ul>
    """

        for _, row in top_dast.iterrows():

            html += f"""

    <li>
    <strong>{row['NORMALIZED_TITLE']}</strong><br>
    Occurrences: {row['OCCURRENCES']}<br>
    URLs Affected: {row.get('URL_COUNT', 0)}<br>
    </li>
    """

        html += """
    </ul>

    <h2>Recommended Actions</h2>

    <ol>
    <li>Prioritize High severity code vulnerabilities.</li>
    <li>Address SQL Injection and Cross-Site Scripting findings first.</li>
    <li>Implement missing runtime security controls.</li>
    <li>Re-run Snyk and Rapid7 validation scans.</li>
    <li>Perform regression testing before deployment.</li>
    </ol>

    </body>
    </html>
    """

        return html

    # --------------------------------------------------
    # Export Reports
    # --------------------------------------------------

    print(f"Writing: {EXECUTIVE_MD}")
    print(f"Writing: {DEVELOPER_MD}")
    print(f"Writing: {EXECUTIVE_HTML}")
    print(f"Writing: {DEVELOPER_HTML}")

    with open(
        EXECUTIVE_MD,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(executive_md)

    with open(
        DEVELOPER_MD,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(developer_md)

    with open(
        EXECUTIVE_HTML,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            build_executive_html(
                APP_NAME,
                overall_risk,
                critical_count,
                high_count,
                medium_count,
                low_count,
                top_sast,
                top_dast
            )
        )

    with open(
        DEVELOPER_HTML,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            build_developer_html(
                APP_NAME,
                overall_risk,
                critical_count,
                high_count,
                medium_count,
                low_count,
                top_sast,
                top_dast
            )
        )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    print()
    print("=" * 60)
    print(f"Application: {APP_NAME}")
    print(f"Overall Risk: {overall_risk}")
    print(f"Findings: {len(df)}")
    print()
    print(f"Created: {NORMALIZED_CSV}")
    print(f"Created: {DEVELOPER_MD}")
    print(f"Created: {DEVELOPER_HTML}")
    print(f"Created: {EXECUTIVE_MD}")
    print(f"Created: {EXECUTIVE_HTML}")
    print("=" * 60)
