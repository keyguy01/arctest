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
# Priority Ranking
# --------------------------------------------------

PRIORITY_RANK = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4
}

# --------------------------------------------------
# Discover Risk Reports
# --------------------------------------------------

risk_reports = [

    file

    for file in os.listdir(
        ARC_DIR
    )

    if file.endswith(
        "-risk-report.csv"
    )

]

if not risk_reports:

    print(
        "No risk reports found."
    )

    raise SystemExit(0)

# --------------------------------------------------
# Process Each Report
# --------------------------------------------------

print()
print("=" * 60)
print(f"ARC_DIR: {ARC_DIR}")
print(f"Risk Reports Found: {len(risk_reports)}")

for file in risk_reports:
    print(f"  {file}")

print("=" * 60)
print()

for report_file in risk_reports:

    INPUT_FILE = os.path.join(
        ARC_DIR,
        report_file
    )

    app_name = (
        report_file
        .replace(
            "-risk-report.csv",
            ""
        )
    )

    OUTPUT_FILE = os.path.join(
        ARC_DIR,
        f"{app_name}-prioritized-findings.csv"
    )

    print()
    print("=" * 60)
    print(
        f"Processing: {report_file}"
    )

    # --------------------------------------------------
    # Load Data
    # --------------------------------------------------

    print(
        f"Loading {INPUT_FILE}"
    )

    df = pd.read_csv(
        INPUT_FILE
    )

    if df.empty:

        print(
            f"{app_name}: No findings found."
        )

        continue

    print(
        f"Loaded {len(df)} findings"
    )

    # --------------------------------------------------
    # Noise Filtering
    # --------------------------------------------------

    NOISE_PATTERNS = [

        # tests
        "/test/",
        "/tests/",
        "\\test\\",
        "\\tests\\",

        "/spec/",
        "/specs/",
        "\\spec\\",
        "\\specs\\",

        ".test.",
        ".spec.",

        # build output
        "/obj/",
        "\\obj\\",

        "/bin/",
        "\\bin\\",

        "/package/",
        "\\package\\",

        "/tempbuilddir/",
        "\\tempbuilddir\\",

        # dependencies
        "/dependencies/",
        "\\dependencies\\",

        "/packages/",
        "\\packages\\",

        "node_modules",

        "/vendor/",
        "\\vendor\\",

        # wordpress plugins
        "/wp-content/plugins/",
        "\\wp-content\\plugins\\",

        "/wordfence/",
        "/duplicator/",

        # coverage
        "/coverage/",
        "\\coverage\\"
    ]

    def is_noise(path):

        if pd.isna(path):
            return False

        path = str(path).lower()

        return any(
            pattern in path
            for pattern in NOISE_PATTERNS
        )

    before_count = len(df)

    if "FILE_PATH" in df.columns:

        df = df[
            ~df["FILE_PATH"]
            .apply(is_noise)
        ]

    after_count = len(df)

    print(
        f"Filtered Noise Findings: "
        f"{before_count - after_count}"
    )

    # --------------------------------------------------
    # Filter Low Value Rapid7 Findings
    # --------------------------------------------------

    LOW_VALUE_R7 = [

        "BROWSERCACHECHECK01",
        "XContentTypeAttack_1",
        "XFrameAttack_1",
        "HSTSAttack_4"

    ]

    # --------------------------------------------------
# Filter Low Value Rapid7 Findings
# --------------------------------------------------

    LOW_VALUE_R7 = {
        "BROWSERCACHECHECK01",
        "XContentTypeAttack_1",
        "XFrameAttack_1",
        "HSTSAttack_4",
    }
    
    # Normalize SOURCE and TITLE safely
    if "SOURCE" not in df.columns:
        print(
            "WARNING: SOURCE column missing. "
            "Skipping Rapid7-specific low-value filtering."
        )
        df["SOURCE"] = ""
    
    if "TITLE" not in df.columns:
        print(
            "ERROR: TITLE column missing. "
            "Cannot perform finding prioritization."
        )
        continue
    
    df["SOURCE"] = (
        df["SOURCE"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.upper()
    )
    
    df["TITLE"] = (
        df["TITLE"]
        .fillna("")
        .astype(str)
        .str.strip()
    )
    
    r7_low = (
        df["SOURCE"].eq("RAPID7")
        &
        df["TITLE"].isin(LOW_VALUE_R7)
    )
    
    removed_r7 = int(r7_low.sum())
    
    df = df.loc[~r7_low].copy()
    
    print(
        f"Filtered Low-Value Rapid7 Findings: "
        f"{removed_r7}"
    )


    print(
        f"Remaining Findings: "
        f"{len(df)}"
    )

    # --------------------------------------------------
    # Group Findings
    # --------------------------------------------------

    grouped = []

    group_columns = [

        "APP_NAME",
        "SOURCE",
        "TITLE",
        "CWE"

    ]

    for keys, group in df.groupby(
        group_columns,
        dropna=False
    ):

        app_name_group, source, title, cwe = keys

        priorities = (
            group["PRIORITY"]
            .fillna("LOW")
            .astype(str)
            .str.upper()
        )

        highest_priority = min(
            priorities,
            key=lambda x: PRIORITY_RANK.get(
                x,
                99
            )
        )

        file_paths = sorted(
            set(
                str(x)
                for x in group[
                    "FILE_PATH"
                ].dropna()
                if str(x).strip()
            )
        )

        urls = sorted(
            set(
                str(x)
                for x in group[
                    "URL"
                ].dropna()
                if str(x).strip()
            )
        )

        # ----------------------------------------------
        # Directory Analysis
        # ----------------------------------------------

        directory_counts = {}

        for file_path in file_paths:

            normalized_path = (
                str(file_path)
                .replace("\\", "/")
            )

            parts = normalized_path.split("/")

            if len(parts) > 1:

                directory = parts[0]

                directory_counts[
                    directory
                ] = (
                    directory_counts.get(
                        directory,
                        0
                    ) + 1
                )

        top_directories = sorted(
            directory_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        directory_summary = "\n".join(
            [
                f"{directory} ({count} files)"
                for directory, count
                in top_directories[:10]
            ]
        )

        # ----------------------------------------------
        # Remediation Scope
        # ----------------------------------------------

        if len(file_paths) > 50:

            remediation_scope = "Large"

        elif len(file_paths) > 15:

            remediation_scope = "Medium"

        else:

            remediation_scope = "Small"

        # ----------------------------------------------
        # Trim File List
        # ----------------------------------------------

        display_files = file_paths[:15]

        affected_files = "\n".join(
            display_files
        )

        extra_files = max(
            0,
            len(file_paths) - 15
        )

        if extra_files > 0:

            affected_files += (
                f"\n\n... and "
                f"{extra_files} additional files"
            )

        descriptions = (
            group["DESCRIPTION"]
            .dropna()
            .astype(str)
        )

        actions = (
            group["ACTION"]
            .dropna()
            .astype(str)
        )

        validations = (
            group["VALIDATION"]
            .dropna()
            .astype(str)
        )

        grouped.append({

            "APP_NAME":
                app_name_group,

            "PRIORITY":
                highest_priority,

            "SOURCE":
                source,

            "TITLE":
                title,

            "CWE":
                cwe,

            "OCCURRENCES":
                len(group),

            "FILE_COUNT":
                len(file_paths),

            "URL_COUNT":
                len(urls),

            "REMEDIATION_SCOPE":
                remediation_scope,

            "TOP_DIRECTORIES":
                directory_summary,

            "AFFECTED_FILES":
                affected_files,

            "AFFECTED_URLS":
                "\n".join(
                    urls[:20]
                ),

            "DESCRIPTION":
                descriptions.iloc[0]
                if len(descriptions) > 0
                else "",

            "RECOMMENDED_ACTION":
                actions.iloc[0]
                if len(actions) > 0
                else "",

            "VALIDATION":
                validations.iloc[0]
                if len(validations) > 0
                else ""

        })

    # --------------------------------------------------
    # Create DataFrame
    # --------------------------------------------------

    output_df = pd.DataFrame(
        grouped
    )

    if output_df.empty:

        print(
            f"{app_name}: No grouped findings."
        )

        continue

    # --------------------------------------------------
    # Risk Scoring
    # --------------------------------------------------

    def calculate_score(row):

        score = 0

        priority = str(
            row["PRIORITY"]
        ).upper()

        if priority == "CRITICAL":

            score += 100

        elif priority == "HIGH":

            score += 75

        elif priority == "MEDIUM":

            score += 50

        else:

            score += 25

        score += min(
            row["OCCURRENCES"],
            50
        )

        if (
            str(row["SOURCE"])
            .upper()
            == "SNYK"
        ):

            score += 25

        return score

    output_df["RISK_SCORE"] = (
        output_df.apply(
            calculate_score,
            axis=1
        )
    )

    output_df = output_df.sort_values(
        by="RISK_SCORE",
        ascending=False
    )

    # --------------------------------------------------
    # Export
    # --------------------------------------------------

    print(
        f"Writing: {OUTPUT_FILE}"
    )

    output_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    print(
        f"Created: {OUTPUT_FILE}"
    )

    print(
        f"Prioritized Findings: "
        f"{len(output_df)}"
    )

    print()

    print(
        output_df[
            [
                "PRIORITY",
                "SOURCE",
                "TITLE",
                "CWE",
                "FILE_COUNT",
                "REMEDIATION_SCOPE",
                "OCCURRENCES",
                "RISK_SCORE"
            ]
        ]
        .head(10)
    )

print()
print("=" * 60)
print("Prioritization complete.")
print("=" * 60)
