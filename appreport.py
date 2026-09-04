#!/usr/bin/env python3

import os
import html
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

# --------------------------------------------------
# Constants
# --------------------------------------------------

PRIORITY_RANK = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4
}

PRIORITY_SCORE = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25
}

# --------------------------------------------------
# Security Knowledge Base
# --------------------------------------------------

KNOWLEDGE_BASE = {

    "CWE-89": {
        "impact":
            "Potential database manipulation, disclosure of sensitive information, and unauthorized access.",

        "action":
            "Replace dynamic SQL with parameterized queries or prepared statements. Validate all database inputs.",

        "testing":
            "Validate create, read, update and delete workflows. Test malicious SQL input and re-run Snyk and Rapid7 scans."
    },

    "CWE-79": {
        "impact":
            "Potential execution of malicious client-side scripts and compromise of user sessions.",

        "action":
            "Implement context-appropriate output encoding and input validation. Do not render untrusted content as executable HTML or script.",

        "testing":
            "Test reflected, stored and DOM-based XSS scenarios. Verify encoded output and re-run Snyk and Rapid7 scans."
    },

    "CWE-22": {
        "impact":
            "Potential unauthorized access to files and directories outside intended application locations.",

        "action":
            "Normalize and validate file paths. Restrict file access to approved directories and reject traversal sequences.",

        "testing":
            "Test path traversal payloads and verify unauthorized files cannot be accessed."
    },

    "CWE-798": {
        "impact":
            "Hard-coded credentials may be exposed and used to gain unauthorized access.",

        "action":
            "Move credentials to a secure secrets-management solution and remove secrets from source code.",

        "testing":
            "Rotate exposed credentials, verify application functionality, and confirm secrets are no longer present in source control."
    },

    "CWE-502": {
        "impact":
            "Unsafe deserialization may allow manipulation of application state or potentially arbitrary code execution.",

        "action":
            "Avoid deserializing untrusted data. Use safe serialization formats and enforce strict type validation.",

        "testing":
            "Test malformed and malicious serialized input and verify untrusted objects cannot execute application code."
    },

    "CWE-200": {
        "impact":
            "Sensitive information may be disclosed to unauthorized users.",

        "action":
            "Remove unnecessary sensitive information from responses, errors, logs and publicly accessible resources.",

        "testing":
            "Review application responses and error conditions for unintended information disclosure."
    },

    "CWE-327": {
        "impact":
            "Use of weak or outdated cryptographic algorithms may allow protected information to be compromised.",

        "action":
            "Replace deprecated cryptographic algorithms with currently approved cryptographic standards.",

        "testing":
            "Verify supported cryptographic algorithms and confirm deprecated algorithms are no longer accepted."
    },

    "CWE-918": {
        "impact":
            "Server-Side Request Forgery may allow attackers to make unauthorized requests from the application server.",

        "action":
            "Validate and restrict outbound destinations. Use allowlists and block access to internal or cloud metadata endpoints.",

        "testing":
            "Test requests to internal addresses, localhost, cloud metadata services and unauthorized external destinations."
    }
}

DEFAULT_KB = {
    "impact":
        "Review the finding with the application owner and Security Engineering.",

    "action":
        "Review the scanner remediation guidance and implement the appropriate application security control.",

    "testing":
        "Re-run applicable Snyk and Rapid7 security scans and perform regression testing."
}


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def safe_value(value, default=""):
    """
    Convert NaN/None into a clean string.
    """
    if value is None or pd.isna(value):
        return default

    return str(value).strip()


def html_value(value):
    """
    Safely escape report data for HTML output.
    """
    return html.escape(
        safe_value(value)
    )


def markdown_value(value):
    """
    Clean values for Markdown output.
    """
    return safe_value(value)


def get_kb(cwe):
    """
    Return security guidance based on CWE.
    """

    cwe_string = safe_value(cwe).upper()

    if not cwe_string:
        return DEFAULT_KB

    for key, value in KNOWLEDGE_BASE.items():

        if key in cwe_string:
            return value

    return DEFAULT_KB


def normalize_priority(value):

    priority = safe_value(
        value,
        "LOW"
    ).upper()

    if priority in PRIORITY_RANK:
        return priority

    return "LOW"


def normalize_source(value):

    source = safe_value(
        value,
        "UNKNOWN"
    ).upper()

    if source == "SNYK":
        return "SNYK"

    if source == "RAPID7":
        return "RAPID7"

    return source


def finding_title(row):

    title = safe_value(
        row.get("TITLE")
    )

    if title:
        return title

    return "Unnamed Security Finding"


def get_occurrences(row):

    value = row.get(
        "OCCURRENCES",
        1
    )

    try:
        return max(
            int(float(value)),
            1
        )

    except (
        ValueError,
        TypeError
    ):
        return 1


def get_numeric(row, column, default=0):

    value = row.get(
        column,
        default
    )

    try:
        return float(value)

    except (
        ValueError,
        TypeError
    ):
        return default


def calculate_risk_score(row):

    priority = normalize_priority(
        row.get("PRIORITY")
    )

    score = PRIORITY_SCORE.get(
        priority,
        25
    )

    occurrences = get_occurrences(
        row
    )

    # Exposure multiplier.
    score += min(
        occurrences,
        50
    )

    source = normalize_source(
        row.get("SOURCE")
    )

    # Snyk/SAST code vulnerabilities
    # receive a modest priority boost.
    if source == "SNYK":
        score += 25

    # Broad DAST exposure can also
    # increase risk.
    if source == "RAPID7":

        url_count = get_numeric(
            row,
            "URL_COUNT"
        )

        score += min(
            int(url_count),
            25
        )

    # Preserve an existing calculated
    # risk score if it is higher.
    existing_score = get_numeric(
        row,
        "RISK_SCORE"
    )

    return max(
        score,
        int(existing_score)
    )


def remediation_scope(row):

    file_count = int(
        get_numeric(
            row,
            "FILE_COUNT"
        )
    )

    url_count = int(
        get_numeric(
            row,
            "URL_COUNT"
        )
    )

    total_scope = max(
        file_count,
        url_count
    )

    if total_scope > 50:
        return "Large"

    if total_scope > 15:
        return "Medium"

    return "Small"


def overall_risk_level(df):

    if df.empty:
        return "Low"

    priorities = (
        df["PRIORITY"]
        .astype(str)
        .str.upper()
    )

    if "CRITICAL" in priorities.values:
        return "Critical"

    if "HIGH" in priorities.values:
        return "High"

    if "MEDIUM" in priorities.values:
        return "Medium"

    return "Low"


def priority_counts(df):

    priorities = (
        df["PRIORITY"]
        .astype(str)
        .str.upper()
    )

    return {
        "critical": int(
            (priorities == "CRITICAL").sum()
        ),

        "high": int(
            (priorities == "HIGH").sum()
        ),

        "medium": int(
            (priorities == "MEDIUM").sum()
        ),

        "low": int(
            (priorities == "LOW").sum()
        )
    }


def normalize_dataframe(df):

    # Add expected columns if an older
    # prioritization script omitted them.

    defaults = {

        "APP_NAME": "",

        "SOURCE": "UNKNOWN",

        "PRIORITY": "LOW",

        "TITLE": "Unnamed Security Finding",

        "CWE": "",

        "OCCURRENCES": 1,

        "FILE_COUNT": 0,

        "URL_COUNT": 0,

        "REMEDIATION_SCOPE": "",

        "TOP_DIRECTORIES": "",

        "AFFECTED_FILES": "",

        "AFFECTED_URLS": "",

        "DESCRIPTION": "",

        "RECOMMENDED_ACTION": "",

        "VALIDATION": "",

        "RISK_SCORE": 0
    }

    for column, default in defaults.items():

        if column not in df.columns:

            df[column] = default

    df["PRIORITY"] = (
        df["PRIORITY"]
        .apply(normalize_priority)
    )

    df["SOURCE"] = (
        df["SOURCE"]
        .apply(normalize_source)
    )

    df["TITLE"] = (
        df["TITLE"]
        .apply(
            lambda x:
                safe_value(
                    x,
                    "Unnamed Security Finding"
                )
        )
    )

    df["OCCURRENCES"] = (
        df["OCCURRENCES"]
        .apply(
            lambda x:
                get_occurrences(
                    {"OCCURRENCES": x}
                )
        )
    )

    df["FILE_COUNT"] = (
        pd.to_numeric(
            df["FILE_COUNT"],
            errors="coerce"
        )
        .fillna(0)
        .astype(int)
    )

    df["URL_COUNT"] = (
        pd.to_numeric(
            df["URL_COUNT"],
            errors="coerce"
        )
        .fillna(0)
        .astype(int)
    )

    # Some versions of the previous script
    # generated RISK_SCORE. Recalculate so
    # this report remains reliable.

    df["CALCULATED_RISK_SCORE"] = (
        df.apply(
            calculate_risk_score,
            axis=1
        )
    )

    df["REMEDIATION_SCOPE"] = (
        df.apply(
            remediation_scope,
            axis=1
        )
    )

    # Use the title directly. This fixes
    # the old undefined NORMALIZED_TITLE field.

    df["NORMALIZED_TITLE"] = (
        df["TITLE"]
        .str.strip()
    )

    return df


def build_sections(df):

    fix_first = df[
        df["PRIORITY"]
        .isin([
            "CRITICAL",
            "HIGH"
        ])
    ].copy()

    fix_next = df[
        df["PRIORITY"]
        == "MEDIUM"
    ].copy()

    defense_in_depth = df[
        df["PRIORITY"]
        == "LOW"
    ].copy()

    sort_columns = [
        "CALCULATED_RISK_SCORE",
        "OCCURRENCES"
    ]

    for section in [
        fix_first,
        fix_next,
        defense_in_depth
    ]:

        if not section.empty:

            section.sort_values(
                by=sort_columns,
                ascending=[
                    False,
                    False
                ],
                inplace=True
            )

    return (
        fix_first,
        fix_next,
        defense_in_depth
    )


def top_by_source(df, source, limit=10):

    result = df[
        df["SOURCE"]
        == source
    ].copy()

    if result.empty:
        return result

    return (
        result
        .sort_values(
            by=[
                "CALCULATED_RISK_SCORE",
                "OCCURRENCES"
            ],
            ascending=[
                False,
                False
            ]
        )
        .head(limit)
    )


def get_description(row):

    description = safe_value(
        row.get("DESCRIPTION")
    )

    if description:
        return description

    kb = get_kb(
        row.get("CWE")
    )

    return kb["impact"]


def get_action(row):

    action = safe_value(
        row.get(
            "RECOMMENDED_ACTION"
        )
    )

    if action:
        return action

    kb = get_kb(
        row.get("CWE")
    )

    return kb["action"]


def get_validation(row):

    validation = safe_value(
        row.get("VALIDATION")
    )

    if validation:
        return validation

    kb = get_kb(
        row.get("CWE")
    )

    return kb["testing"]


# --------------------------------------------------
# Markdown Builders
# --------------------------------------------------

def build_developer_markdown(
    app_name,
    df,
    fix_first,
    fix_next,
    defense_in_depth
):

    counts = priority_counts(df)

    overall_risk = overall_risk_level(
        df
    )

    priority_finding_count = len(
        fix_first
    )

    lines = [

        "# Developer Security Action Report",
        "",
        f"## Application",
        "",
        app_name,
        "",
        "## Overall Risk",
        "",
        f"**{overall_risk}**",
        "",
        "## Risk Reduction Summary",
        "",
        f"- Raw Findings Reviewed: {len(df)}",
        f"- Unique Findings: {len(df)}",
        f"- Critical / High Findings: {priority_finding_count}",
        "",
        "## Finding Summary",
        "",
        "| Priority | Count |",
        "|---|---:|",
        f"| Critical | {counts['critical']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |",
        f"| Low | {counts['low']} |",
        "",
        "---",
        "",
        "# Fix First — Critical / High",
        ""
    ]

    if fix_first.empty:

        lines.extend([
            "No Critical or High findings identified.",
            ""
        ])

    else:

        for _, row in fix_first.head(15).iterrows():

            kb = get_kb(
                row.get("CWE")
            )

            lines.extend([

                f"## {markdown_value(row['NORMALIZED_TITLE'])}",
                "",
                f"**Priority:** {row['PRIORITY']}",
                "",
                f"**Source:** {row['SOURCE']}",
                "",
                f"**Risk Score:** {row['CALCULATED_RISK_SCORE']}",
                "",
                f"**Remediation Scope:** {row['REMEDIATION_SCOPE']}",
                "",
                f"**Occurrences:** {row['OCCURRENCES']}",
                "",
                f"**Files Affected:** {row['FILE_COUNT']}",
                "",
                f"**URLs Affected:** {row['URL_COUNT']}",
                "",
                f"**CWE:** {markdown_value(row.get('CWE', ''))}",
                "",
                "### Risk / Impact",
                "",
                markdown_value(
                    get_description(row)
                ),
                "",
                "### Primary Application Areas",
                "",
                "```text",
                markdown_value(
                    row.get(
                        "TOP_DIRECTORIES",
                        ""
                    )
                ),
                "```",
                "",
                "### Files Requiring Review",
                "",
                "```text",
                markdown_value(
                    row.get(
                        "AFFECTED_FILES",
                        ""
                    )
                ),
                "```",
                "",
                "### Affected URLs",
                "",
                "```text",
                markdown_value(
                    row.get(
                        "AFFECTED_URLS",
                        ""
                    )
                ),
                "```",
                "",
                "### Recommended Action",
                "",
                markdown_value(
                    get_action(row)
                ),
                "",
                "### Testing Validation",
                "",
                markdown_value(
                    get_validation(row)
                ),
                "",
                "---",
                ""
            ])

    lines.extend([

        "# Security Engineering Notes",
        "",
        "1. Address Critical findings first.",
        "2. Address High severity code vulnerabilities immediately after Critical findings.",
        "3. Prioritize exploitable application-code vulnerabilities before lower-impact hardening items.",
        "4. Re-run Snyk after SAST remediation.",
        "5. Re-run Rapid7 authenticated scans after DAST/runtime remediation.",
        "6. Perform regression testing before production deployment.",
        "",
        "# Fix Next — Medium",
        ""
    ])

    if fix_next.empty:

        lines.append(
            "No Medium findings identified."
        )

        lines.append("")

    else:

        for _, row in fix_next.head(15).iterrows():

            lines.extend([

                f"## {markdown_value(row['NORMALIZED_TITLE'])}",
                "",
                f"- Source: {row['SOURCE']}",
                f"- Risk Score: {row['CALCULATED_RISK_SCORE']}",
                f"- Occurrences: {row['OCCURRENCES']}",
                f"- Files Affected: {row['FILE_COUNT']}",
                f"- URLs Affected: {row['URL_COUNT']}",
                f"- CWE: {markdown_value(row.get('CWE', ''))}",
                "",
                f"**Recommended Action:** {markdown_value(get_action(row))}",
                "",
                "---",
                ""
            ])

    lines.extend([

        "# Defense in Depth — Low",
        "",
        "These findings generally do not require immediate remediation but should be tracked as part of application security hardening.",
        ""
    ])

    if defense_in_depth.empty:

        lines.append(
            "No Low findings identified."
        )

        lines.append("")

    else:

        for _, row in defense_in_depth.head(15).iterrows():

            lines.extend([

                f"## {markdown_value(row['NORMALIZED_TITLE'])}",
                "",
                f"- Source: {row['SOURCE']}",
                f"- Risk Score: {row['CALCULATED_RISK_SCORE']}",
                f"- Occurrences: {row['OCCURRENCES']}",
                f"- Files Affected: {row['FILE_COUNT']}",
                f"- URLs Affected: {row['URL_COUNT']}",
                "",
                "---",
                ""
            ])

    return "\n".join(lines)


def build_executive_markdown(
    app_name,
    df,
    fix_first
):

    counts = priority_counts(df)

    overall_risk = overall_risk_level(
        df
    )

    top_findings = (
        df
        .sort_values(
            by="CALCULATED_RISK_SCORE",
            ascending=False
        )
        .head(10)
    )

    lines = [

        "# Executive Application Security Report",
        "",
        "## Application",
        "",
        app_name,
        "",
        "## Overall Risk",
        "",
        f"**{overall_risk}**",
        "",
        "## Findings at a Glance",
        "",
        f"- Critical Findings: {counts['critical']}",
        f"- High Findings: {counts['high']}",
        f"- Medium Findings: {counts['medium']}",
        f"- Low Findings: {counts['low']}",
        "",
        "## Risk Reduction Summary",
        "",
        f"- Raw Findings Reviewed: {len(df)}",
        f"- Unique Findings Identified: {len(df)}",
        f"- Critical / High Findings Requiring Action: {len(fix_first)}",
        "",
        "---",
        "",
        "## Top Risks",
        ""
    ]

    if top_findings.empty:

        lines.append(
            "No findings available."
        )

    else:

        for _, row in top_findings.iterrows():

            lines.append(
                f"- **{markdown_value(row['NORMALIZED_TITLE'])}** — "
                f"{row['PRIORITY']} | "
                f"Source: {row['SOURCE']} | "
                f"Occurrences: {row['OCCURRENCES']} | "
                f"Files: {row['FILE_COUNT']} | "
                f"URLs: {row['URL_COUNT']} | "
                f"Risk Score: {row['CALCULATED_RISK_SCORE']}"
            )

    lines.extend([

        "",
        "## Recommended Actions",
        "",
        "1. Remediate Critical findings immediately.",
        "2. Address High severity application-code vulnerabilities next.",
        "3. Address SQL Injection and Cross-Site Scripting findings with priority when present.",
        "4. Implement required runtime security controls.",
        "5. Re-run Snyk and Rapid7 validation scans.",
        "6. Perform regression testing before production deployment.",
        "",
        "## Program Notes",
        "",
        "This report consolidates SAST and DAST observations for application risk review and remediation planning."
    ])

    return "\n".join(lines)


# --------------------------------------------------
# HTML Builders
# --------------------------------------------------

HTML_STYLE = """
<style>

body {
    font-family: Arial, Helvetica, sans-serif;
    margin: 40px;
    color: #222;
    line-height: 1.5;
}

h1 {
    color: #003366;
    border-bottom: 3px solid #003366;
    padding-bottom: 10px;
}

h2 {
    color: #003366;
    border-bottom: 1px solid #dddddd;
    padding-bottom: 6px;
    margin-top: 30px;
}

h3 {
    color: #444;
}

.summary {
    background: #f5f7fa;
    border-left: 5px solid #003366;
    padding: 15px;
    margin-bottom: 25px;
}

.risk-critical {
    color: #8b0000;
    font-weight: bold;
}

.risk-high {
    color: #c62828;
    font-weight: bold;
}

.risk-medium {
    color: #f57c00;
    font-weight: bold;
}

.risk-low {
    color: #2e7d32;
    font-weight: bold;
}

table {
    border-collapse: collapse;
    width: 100%;
    max-width: 800px;
    margin-bottom: 25px;
}

th,
td {
    border: 1px solid #cccccc;
    padding: 9px;
    text-align: left;
}

th {
    background-color: #eeeeee;
}

.finding {
    border: 1px solid #dddddd;
    border-radius: 6px;
    padding: 18px;
    margin-bottom: 20px;
}

.meta {
    color: #555;
}

pre {
    background: #f4f4f4;
    border: 1px solid #ddd;
    padding: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
}

.action {
    background: #eef6ff;
    border-left: 4px solid #1976d2;
    padding: 12px;
}

.validation {
    background: #f2f8f2;
    border-left: 4px solid #388e3c;
    padding: 12px;
}

</style>
"""


def risk_class(risk):

    value = str(
        risk
    ).upper()

    if value == "CRITICAL":
        return "risk-critical"

    if value == "HIGH":
        return "risk-high"

    if value == "MEDIUM":
        return "risk-medium"

    return "risk-low"


def build_finding_html(row):

    title = html_value(
        row["NORMALIZED_TITLE"]
    )

    return f"""
<div class="finding">

<h3>{title}</h3>

<p class="meta">
<strong>Priority:</strong>
{html_value(row["PRIORITY"])}
&nbsp; | &nbsp;

<strong>Source:</strong>
{html_value(row["SOURCE"])}
&nbsp; | &nbsp;

<strong>Risk Score:</strong>
{html_value(row["CALCULATED_RISK_SCORE"])}
</p>

<p>
<strong>Occurrences:</strong>
{html_value(row["OCCURRENCES"])}
<br>

<strong>Files Affected:</strong>
{html_value(row["FILE_COUNT"])}
<br>

<strong>URLs Affected:</strong>
{html_value(row["URL_COUNT"])}
<br>

<strong>Remediation Scope:</strong>
{html_value(row["REMEDIATION_SCOPE"])}
<br>

<strong>CWE:</strong>
{html_value(row.get("CWE", ""))}
</p>

<h4>Risk / Impact</h4>

<p>
{html_value(get_description(row))}
</p>

<h4>Primary Application Areas</h4>

<pre>
{html_value(row.get("TOP_DIRECTORIES", ""))}
</pre>

<h4>Files Requiring Review</h4>

<details>

<summary>
View affected files
</summary>

<pre>
{html_value(row.get("AFFECTED_FILES", ""))}
</pre>

</details>

<h4>Affected URLs</h4>

<details>

<summary>
View affected URLs
</summary>

<pre>
{html_value(row.get("AFFECTED_URLS", ""))}
</pre>

</details>

<h4>Recommended Action</h4>

<div class="action">
{html_value(get_action(row))}
</div>

<h4>Testing Validation</h4>

<div class="validation">
{html_value(get_validation(row))}
</div>

</div>
"""


def build_developer_html(
    app_name,
    df,
    fix_first,
    fix_next,
    defense_in_depth
):

    counts = priority_counts(df)

    overall_risk = overall_risk_level(
        df
    )

    risk_css = risk_class(
        overall_risk
    )

    html_output = f"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<title>
{html_value(app_name)}
Developer Security Report
</title>

{HTML_STYLE}

</head>

<body>

<h1>
Developer Application Security Report
</h1>

<h2>
{html_value(app_name)}
</h2>

<div class="summary">

<p>
<strong>Overall Risk:</strong>
<span class="{risk_css}">
{html_value(overall_risk)}
</span>
</p>

</div>

<h2>
Findings At A Glance
</h2>

<table>

<tr>
<th>Priority</th>
<th>Count</th>
</tr>

<tr>
<td>Critical</td>
<td>{counts["critical"]}</td>
</tr>

<tr>
<td>High</td>
<td>{counts["high"]}</td>
</tr>

<tr>
<td>Medium</td>
<td>{counts["medium"]}</td>
</tr>

<tr>
<td>Low</td>
<td>{counts["low"]}</td>
</tr>

</table>

<h2>
Risk Reduction Summary
</h2>

<ul>

<li>
Raw Findings Reviewed:
{len(df)}
</li>

<li>
Unique Findings:
{len(df)}
</li>

<li>
Critical / High Findings:
{len(fix_first)}
</li>

</ul>

<h2>
Fix First — Critical / High
</h2>
"""

    if fix_first.empty:

        html_output += """
<p>
No Critical or High findings identified.
</p>
"""

    else:

        for _, row in fix_first.head(15).iterrows():

            html_output += (
                build_finding_html(
                    row
                )
            )

    html_output += """

<h2>
Fix Next — Medium
</h2>
"""

    if fix_next.empty:

        html_output += """
<p>
No Medium findings identified.
</p>
"""

    else:

        for _, row in fix_next.head(15).iterrows():

            html_output += (
                build_finding_html(
                    row
                )
            )

    html_output += """

<h2>
Defense in Depth — Low
</h2>

<p>
Low findings should be tracked as part of future application security hardening.
</p>
"""

    if defense_in_depth.empty:

        html_output += """
<p>
No Low findings identified.
</p>
"""

    else:

        for _, row in defense_in_depth.head(15).iterrows():

            html_output += (
                build_finding_html(
                    row
                )
            )

    html_output += """

<h2>
Security Engineering Notes
</h2>

<ol>

<li>
Address Critical findings first.
</li>

<li>
Address High severity application vulnerabilities next.
</li>

<li>
Prioritize exploitable code vulnerabilities before lower-impact hardening.
</li>

<li>
Re-run Snyk after SAST remediation.
</li>

<li>
Re-run Rapid7 authenticated scans after DAST/runtime remediation.
</li>

<li>
Perform regression testing before production deployment.
</li>

</ol>

</body>
</html>
"""

    return html_output


def build_executive_html(
    app_name,
    df,
    fix_first
):

    counts = priority_counts(
        df
    )

    overall_risk = overall_risk_level(
        df
    )

    risk_css = risk_class(
        overall_risk
    )

    top_sast = top_by_source(
        df,
        "SNYK",
        10
    )

    top_dast = top_by_source(
        df,
        "RAPID7",
        10
    )

    html_output = f"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<title>
{html_value(app_name)}
Executive Security Report
</title>

{HTML_STYLE}

</head>

<body>

<h1>
Executive Application Security Report
</h1>

<h2>
{html_value(app_name)}
</h2>

<div class="summary">

<p>
<strong>Overall Risk:</strong>

<span class="{risk_css}">
{html_value(overall_risk)}
</span>

</p>

</div>

<h2>
Findings At A Glance
</h2>

<table>

<tr>
<th>Priority</th>
<th>Count</th>
</tr>

<tr>
<td>Critical</td>
<td>{counts["critical"]}</td>
</tr>

<tr>
<td>High</td>
<td>{counts["high"]}</td>
</tr>

<tr>
<td>Medium</td>
<td>{counts["medium"]}</td>
</tr>

<tr>
<td>Low</td>
<td>{counts["low"]}</td>
</tr>

</table>

<h2>
Risk Reduction Summary
</h2>

<ul>

<li>
Raw Findings Reviewed:
{len(df)}
</li>

<li>
Unique Findings:
{len(df)}
</li>

<li>
Critical / High Findings Requiring Action:
{len(fix_first)}
</li>

</ul>

<h2>
Top SAST Risks
</h2>
"""

    if top_sast.empty:

        html_output += """
<p>
No Snyk/SAST findings identified.
</p>
"""

    else:

        for _, row in top_sast.iterrows():

            html_output += f"""

<div class="finding">

<h3>
{html_value(row["NORMALIZED_TITLE"])}
</h3>

<p>

<strong>Priority:</strong>
{html_value(row["PRIORITY"])}

<br>

<strong>Risk Score:</strong>
{html_value(row["CALCULATED_RISK_SCORE"])}

<br>

<strong>Scope:</strong>
{html_value(row["REMEDIATION_SCOPE"])}

<br>

<strong>Files:</strong>
{html_value(row["FILE_COUNT"])}

<br>

<strong>Occurrences:</strong>
{html_value(row["OCCURRENCES"])}

<br>

<strong>CWE:</strong>
{html_value(row.get("CWE", ""))}

</p>

</div>
"""

    html_output += """

<h2>
Top DAST Risks
</h2>
"""

    if top_dast.empty:

        html_output += """
<p>
No Rapid7/DAST findings identified.
</p>
"""

    else:

        for _, row in top_dast.iterrows():

            html_output += f"""

<div class="finding">

<h3>
{html_value(row["NORMALIZED_TITLE"])}
</h3>

<p>

<strong>Priority:</strong>
{html_value(row["PRIORITY"])}

<br>

<strong>Risk Score:</strong>
{html_value(row["CALCULATED_RISK_SCORE"])}

<br>

<strong>Occurrences:</strong>
{html_value(row["OCCURRENCES"])}

<br>

<strong>URLs Affected:</strong>
{html_value(row["URL_COUNT"])}

</p>

</div>
"""

    html_output += """

<h2>
Recommended Actions
</h2>

<ol>

<li>
Remediate Critical findings immediately.
</li>

<li>
Address High severity application vulnerabilities.
</li>

<li>
Address SQL Injection and Cross-Site Scripting findings with priority when present.
</li>

<li>
Implement missing runtime security controls.
</li>

<li>
Re-run Snyk and Rapid7 validation scans.
</li>

<li>
Perform regression testing before production deployment.
</li>

</ol>

<h2>
Program Notes
</h2>

<p>
This report consolidates SAST and DAST observations for application risk review and remediation planning.
</p>

</body>
</html>
"""

    return html_output


# --------------------------------------------------
# Discover Prioritized Reports
# --------------------------------------------------

prioritized_reports = [

    file

    for file in os.listdir(
        ARC_DIR
    )

    if file.endswith(
        "-prioritized-findings.csv"
    )

]

if not prioritized_reports:

    print(
        "No prioritized findings reports found."
    )

    raise SystemExit(0)


# --------------------------------------------------
# Report Discovery Summary
# --------------------------------------------------

print()
print("=" * 70)
print(
    f"ARC_DIR: {ARC_DIR}"
)
print(
    f"Prioritized Reports Found: "
    f"{len(prioritized_reports)}"
)

for file in prioritized_reports:

    print(
        f"  {file}"
    )

print("=" * 70)
print()


# --------------------------------------------------
# Process Reports
# --------------------------------------------------

for report_file in prioritized_reports:

    input_file = os.path.join(
        ARC_DIR,
        report_file
    )

    app_name = report_file.replace(
        "-prioritized-findings.csv",
        ""
    )

    executive_md_file = os.path.join(
        ARC_DIR,
        f"{app_name}-executive-security-report.md"
    )

    developer_md_file = os.path.join(
        ARC_DIR,
        f"{app_name}-developer-security-report.md"
    )

    executive_html_file = os.path.join(
        ARC_DIR,
        f"{app_name}-executive-security-report.html"
    )

    developer_html_file = os.path.join(
        ARC_DIR,
        f"{app_name}-developer-security-report.html"
    )

    print()
    print("=" * 70)

    print(
        f"Processing: {report_file}"
    )

    print(
        f"Loading: {input_file}"
    )

    # --------------------------------------------------
    # Load CSV
    # --------------------------------------------------

    try:

        df = pd.read_csv(
            input_file
        )

    except Exception as exc:

        print(
            f"ERROR loading {input_file}: "
            f"{exc}"
        )

        continue

    if df.empty:

        print(
            f"{app_name}: "
            f"No findings available."
        )

        continue

    print(
        f"Loaded findings: {len(df)}"
    )

    # --------------------------------------------------
    # Normalize
    # --------------------------------------------------

    df = normalize_dataframe(
        df
    )

    # --------------------------------------------------
    # Build Sections
    # --------------------------------------------------

    (
        fix_first,
        fix_next,
        defense_in_depth
    ) = build_sections(
        df
    )

    # --------------------------------------------------
    # Counts
    # --------------------------------------------------

    counts = priority_counts(
        df
    )

    overall_risk = overall_risk_level(
        df
    )

    # --------------------------------------------------
    # Source Summary
    # --------------------------------------------------

    snyk_count = int(
        (
            df["SOURCE"]
            == "SNYK"
        ).sum()
    )

    rapid7_count = int(
        (
            df["SOURCE"]
            == "RAPID7"
        ).sum()
    )

    # --------------------------------------------------
    # Build Markdown
    # --------------------------------------------------

    developer_md = build_developer_markdown(
        app_name,
        df,
        fix_first,
        fix_next,
        defense_in_depth
    )

    executive_md = build_executive_markdown(
        app_name,
        df,
        fix_first
    )

    # --------------------------------------------------
    # Build HTML
    # --------------------------------------------------

    developer_html = build_developer_html(
        app_name,
        df,
        fix_first,
        fix_next,
        defense_in_depth
    )

    executive_html = build_executive_html(
        app_name,
        df,
        fix_first
    )

    # --------------------------------------------------
    # Write Files
    # --------------------------------------------------

    print(
        f"Writing: "
        f"{developer_md_file}"
    )

    with open(
        developer_md_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            developer_md
        )

    print(
        f"Writing: "
        f"{executive_md_file}"
    )

    with open(
        executive_md_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            executive_md
        )

    print(
        f"Writing: "
        f"{developer_html_file}"
    )

    with open(
        developer_html_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            developer_html
        )

    print(
        f"Writing: "
        f"{executive_html_file}"
    )

    with open(
        executive_html_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            executive_html
        )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    print()
    print("-" * 70)

    print(
        f"Application: {app_name}"
    )

    print(
        f"Overall Risk: {overall_risk}"
    )

    print(
        f"Total Findings: {len(df)}"
    )

    print(
        f"  Critical: {counts['critical']}"
    )

    print(
        f"  High: {counts['high']}"
    )

    print(
        f"  Medium: {counts['medium']}"
    )

    print(
        f"  Low: {counts['low']}"
    )

    print(
        f"Snyk/SAST Findings: {snyk_count}"
    )

    print(
        f"Rapid7/DAST Findings: {rapid7_count}"
    )

    print(
        f"Fix First: {len(fix_first)}"
    )

    print(
        f"Fix Next: {len(fix_next)}"
    )

    print(
        f"Defense in Depth: "
        f"{len(defense_in_depth)}"
    )

    print()
    print(
        f"Created: {developer_md_file}"
    )

    print(
        f"Created: {developer_html_file}"
    )

    print(
        f"Created: {executive_md_file}"
    )

    print(
        f"Created: {executive_html_file}"
    )

    print("-" * 70)


# --------------------------------------------------
# Complete
# --------------------------------------------------

print()
print("=" * 70)
print(
    "Security remediation package generation complete."
)
print("=" * 70)
