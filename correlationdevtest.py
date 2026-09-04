#!/usr/bin/env python3

import os
import pandas as pd
from difflib import SequenceMatcher

from datetime import datetime

RUN_DATE = datetime.now().strftime("%Y-%m-%d")

# --------------------------------------------------
# Configuration
# --------------------------------------------------

ARC_INPUT_DIR = os.path.join(
    "reports",
    "arc",
    RUN_DATE
)

ARC_OUTPUT_DIR = ARC_INPUT_DIR

os.makedirs(
    ARC_OUTPUT_DIR,
    exist_ok=True
)

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def path_similarity(a, b):

    if not a or not b:
        return 0

    return round(
        SequenceMatcher(
            None,
            normalize_text(a),
            normalize_text(b)
        ).ratio() * 100
    )

def normalize_text(value):

    if pd.isna(value):
        return ""

    return str(value).strip().lower()


def normalize_cwes(cwe_value):

    if pd.isna(cwe_value):
        return set()

    cwes = []

    for cwe in str(cwe_value).split(";"):

        cwe = cwe.strip()

        if cwe:

            cwes.append(
                cwe.upper()
            )

    return set(cwes)


def title_similarity(a, b):

    if not a or not b:

        return 0

    return round(
        SequenceMatcher(
            None,
            normalize_text(a),
            normalize_text(b)
        ).ratio() * 100
    )


def severity_bonus(
    r7_sev,
    snyk_sev
):

    high_levels = {
        "HIGH",
        "CRITICAL"
    }

    if (

        str(r7_sev).upper()
        in high_levels

        and

        str(snyk_sev).upper()
        in high_levels

    ):

        return 5

    return 0


# --------------------------------------------------
# Discover Security Reports
# --------------------------------------------------

security_reports = [

    file

    for file in os.listdir(
        ARC_INPUT_DIR
    )

    if file.endswith(
        "-security-report.csv"
    )

]

if not security_reports:

    print(
        "No security report files found."
    )

    raise SystemExit(0)

# --------------------------------------------------
# Process Each Application
# --------------------------------------------------

for report_file in security_reports:

    report_path = os.path.join(
        ARC_INPUT_DIR,
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
        ARC_OUTPUT_DIR,
        f"{app_name}-correlated-findings.csv"
    )

    print()
    print("=" * 60)

    print(
        f"Processing: "
        f"{report_file}"
    )

    # --------------------------------------------------
    # Load Security Report
    # --------------------------------------------------

    df = pd.read_csv(
        report_path
    )

    if df.empty:

        print(
            f"{app_name}: "
            f"No findings available."
        )

        continue

    rapid7_df = df[
        df["SOURCE"]
        .astype(str)
        .str.upper()
        == "RAPID7"
    ].copy()

    snyk_df = df[
        df["SOURCE"]
        .astype(str)
        .str.upper()
        == "SNYK"
    ].copy()

    print(
        f"Rapid7 Findings: "
        f"{len(rapid7_df)}"
    )

    print(
        f"Snyk Findings: "
        f"{len(snyk_df)}"
    )

    correlations = []

    # --------------------------------------------------
    # Correlation Logic
    # --------------------------------------------------

    for _, r7 in rapid7_df.iterrows():

        r7_cwes = normalize_cwes(
            r7.get("CWE")
        )

        r7_title = r7.get(
            "TITLE",
            ""
        )

        for _, snyk in snyk_df.iterrows():

            snyk_cwes = normalize_cwes(
                snyk.get("CWE")
            )

            snyk_title = snyk.get(
                "TITLE",
                ""
            )

            r7_url = str(
                r7.get("URL", "")
            )

            snyk_file = str(
                snyk.get("FILE_PATH", "")
            )

            confidence = 0
            reason = None

            # ------------------------------------------
            # Rule 1 - CWE Match
            # ------------------------------------------

            shared_cwes = (
                r7_cwes.intersection(
                    snyk_cwes
                )
            )

            if shared_cwes:

                confidence = 95

                reason = (
                    "CWE Match"
                )

            else:

                # --------------------------------------
                # Rule 2 - Title Match
                # --------------------------------------

                score = title_similarity(
                    r7_title,
                    snyk_title
                )

                if score >= 75:

                    confidence = 80

                    reason = (
                        "Title Match"
                    )

            if not reason:

                continue

            confidence += severity_bonus(

                r7.get(
                    "SEVERITY"
                ),

                snyk.get(
                    "SEVERITY"
                )

            )

            confidence = min(
                confidence,
                100
            )

            correlations.append({

                "APP_NAME":
                    app_name,

                "CORRELATION_STATUS":
                    "MATCHED",

                "CONFIDENCE":
                    confidence,

                "MATCH_REASON":
                    reason,

                "R7_TITLE":
                    r7.get(
                        "TITLE"
                    ),

                "R7_SEVERITY":
                    r7.get(
                        "SEVERITY"
                    ),

                "R7_CWE":
                    r7.get(
                        "CWE"
                    ),

                "R7_URL":
                    r7.get(
                        "URL"
                    ),

                "R7_METHOD":
                    r7.get(
                        "METHOD"
                    ),

                "SNYK_TITLE":
                    snyk.get(
                        "TITLE"
                    ),

                "SNYK_SEVERITY":
                    snyk.get(
                        "SEVERITY"
                    ),

                "SNYK_CWE":
                    snyk.get(
                        "CWE"
                    ),

                "SNYK_FILE_PATH":
                    snyk.get(
                        "FILE_PATH"
                    ),

                "REMEDIATION":
                    snyk.get(
                        "REMEDIATION"
                    ),

                "SNYK_PROJECT":
                    snyk.get(
                        "PROJECT_NAME"
                    ),

                "SNYK_RULE":
                    snyk.get(
                        "RULE_KEY"
                    ),

                "R7_ATTACK_TYPE":
                    r7.get(
                        "TITLE"
                    )

            })

            file_score = path_similarity(
                r7_url,
                snyk_file
            )

            if file_score >= 60:

                confidence = max(
                    confidence,
                    70
                )

                reason = (
                    "URL/File Similarity"
                )

    # --------------------------------------------------
    # Output
    # --------------------------------------------------

    correlated_df = pd.DataFrame(
        correlations
    )

    if correlated_df.empty:

        print(
            f"{app_name}: "
            f"No correlations found."
        )

        continue

    correlated_df = (
        correlated_df
        .sort_values(
            by="CONFIDENCE",
            ascending=False
        )
    )

    correlated_df["CORRELATION_LEVEL"] = (
        correlated_df["CONFIDENCE"]
        .apply(
            lambda x:
                "High"
                if x >= 90
                else (
                    "Medium"
                    if x >= 75
                    else "Low"
                )
        )
    )

    correlated_df.to_csv(
        output_file,
        index=False
    )

    print(
        f"Created: "
        f"{output_file}"
    )

    print(
        f"Correlations: "
        f"{len(correlated_df)}"
    )

    print()
    print("=" * 60)
    print(
        "Correlation processing complete."
    )
    print("=" * 60)

    print()

    print(
        f"Rapid7 Findings: "
        f"{len(rapid7_df)}"
    )

    print(
        f"Snyk Findings: "
        f"{len(snyk_df)}"
    )

    print(
        f"Correlations Found: "
        f"{len(correlated_df)}"
    )
