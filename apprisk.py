#!/usr/bin/env python3

import os
import pandas as pd

from datetime import datetime

RUN_DATE = datetime.now().strftime(
    "%Y-%m-%d"
)

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
# Helpers
# --------------------------------------------------

def normalize_priority(severity):

    if pd.isna(severity):
        return "Low"

    severity = str(severity).upper()

    if severity == "CRITICAL":
        return "Critical"

    if severity == "HIGH":
        return "High"

    if severity == "MEDIUM":
        return "Medium"

    return "Low"


def build_validation(title):

    title = str(title)

    if "SQL" in title.upper():

        return (
            "Validate search, insert, "
            "update and delete workflows. "
            "Re-run Snyk and Rapid7 scans."
        )

    if "SCRIPT" in title.upper():

        return (
            "Validate input fields, "
            "encoded output and browser rendering."
        )

    if "FRAME" in title.upper():

        return (
            "Verify X-Frame-Options "
            "and CSP frame-ancestors headers."
        )

    if "HSTS" in title.upper():

        return (
            "Verify Strict-Transport-Security "
            "header exists."
        )

    return (
        "Perform regression testing "
        "and re-run security scans."
    )


def determine_action(row):

    source = str(
        row.get("SOURCE", "")
    )

    if source.upper() == "SNYK":

        remediation = row.get(
            "REMEDIATION",
            ""
        )

        if (
            pd.notna(remediation)
            and
            str(remediation).strip()
        ):

            return remediation

        return (
            "Review vulnerable code path "
            "and remediate according "
            "to SAST guidance."
        )

    return (
        "Review and implement "
        "recommended application "
        "security controls."
    )

# --------------------------------------------------
# Discover Security Reports
# --------------------------------------------------

security_reports = [

    file

    for file in os.listdir(
        ARC_DIR
    )

    if file.endswith(
        "-security-report.csv"
    )

]

if not security_reports:

    print(
        "No security reports found."
    )

    raise SystemExit(0)

# --------------------------------------------------
# Process Each App
# --------------------------------------------------

for report_file in security_reports:

    input_file = os.path.join(
        ARC_DIR,
        report_file
    )

    app_name = (
        report_file
        .replace(
            "-security-report.csv",
            ""
        )
    )

    output_file = os.path.join(
        ARC_DIR,
        f"{app_name}-risk-report.csv"
    )

    print()
    print("=" * 60)

    print(
        f"Processing: "
        f"{report_file}"
    )

    df = pd.read_csv(
        input_file
    )

    if df.empty:

        print(
            f"{app_name}: "
            f"No findings found."
        )

        continue

    report_rows = []

    for _, row in df.iterrows():

        report_rows.append({

            "APP_NAME":
                row.get(
                    "APP_NAME"
                ),

            "SOURCE":
                row.get(
                    "SOURCE"
                ),

            "PRIORITY":
                normalize_priority(
                    row.get(
                        "SEVERITY"
                    )
                ),

            "TITLE":
                row.get(
                    "TITLE"
                ),

            "CWE":
                row.get(
                    "CWE"
                ),

            "URL":
                row.get(
                    "URL"
                ),

            "FILE_PATH":
                row.get(
                    "FILE_PATH"
                ),
            "DESCRIPTION":
                row.get(
                    "DESCRIPTION"
                ),

            "ACTION":
                determine_action(
                    row
                ),

            "VALIDATION":
                build_validation(
                    row.get(
                        "TITLE"
                    )
                )
        })

    risk_df = pd.DataFrame(
        report_rows
    )

    if risk_df.empty:

        print(
            f"{app_name}: "
            f"No risk rows generated."
        )

        continue

    priority_order = {

        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4

    }

    risk_df["SORT"] = (
        risk_df["PRIORITY"]
        .map(priority_order)
    )

    risk_df = risk_df.sort_values(
        by="SORT"
    )

    risk_df.drop(
        columns=["SORT"],
        inplace=True
    )

    risk_df.to_csv(
        output_file,
        index=False
    )

    print(
        f"Created: "
        f"{output_file}"
    )

    print(
        f"Total Findings: "
        f"{len(risk_df)}"
    )

print()
print("=" * 60)
print("Risk report generation complete.")
print("=" * 60)
        
