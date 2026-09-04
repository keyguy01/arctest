#!/usr/bin/env python3

import os
import re
import pandas as pd
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================

RUN_DATE = datetime.now().strftime("%Y-%m-%d")

ARC_DIR = os.path.join(
    "reports",
    "arc",
    RUN_DATE
)

os.makedirs(
    ARC_DIR,
    exist_ok=True
)

# ============================================================
# PRIORITY RANKING
# ============================================================

PRIORITY_RANK = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4
}

# ============================================================
# NOISE PATTERNS
# ============================================================

NOISE_PATTERNS = [

    # Tests
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

    # Build output
    "/obj/",
    "\\obj\\",

    "/bin/",
    "\\bin\\",

    "/package/",
    "\\package\\",

    "/tempbuilddir/",
    "\\tempbuilddir\\",

    # Dependencies
    "/dependencies/",
    "\\dependencies\\",

    "/packages/",
    "\\packages\\",

    "node_modules",

    "/vendor/",
    "\\vendor\\",

    # WordPress plugins
    "/wp-content/plugins/",
    "\\wp-content\\plugins\\",

    "/wordfence/",
    "\\wordfence\\",

    "/duplicator/",
    "\\duplicator\\",

    # Coverage
    "/coverage/",
    "\\coverage\\"
]

# ============================================================
# RAPID7 LOW-VALUE FINDINGS
# ============================================================

LOW_VALUE_R7 = {
    "BROWSERCACHECHECK01",
    "XCONTENTTYPEATTACK_1",
    "XFRAMEATTACK_1",
    "HSTSATTACK_4"
}

# ============================================================
# HELPERS
# ============================================================

def clean_string(value):
    """
    Safely convert a CSV value to a clean string.
    """

    if pd.isna(value):
        return ""

    return str(value).strip()


def normalize_priority(value):
    """
    Normalize priority values.
    """

    value = clean_string(value).upper()

    if value in PRIORITY_RANK:
        return value

    return "LOW"


def normalize_source(value):
    """
    Normalize security scanner source.
    """

    value = clean_string(value).upper()

    if value in {"RAPID7", "INSIGHTVM", "R7"}:
        return "RAPID7"

    if value == "SNYK":
        return "SNYK"

    return value


def is_noise(path):
    """
    Determine whether a file path represents
    test/build/dependency noise.
    """

    path = clean_string(path)

    if not path:
        return False

    path = path.lower()

    return any(
        pattern in path
        for pattern in NOISE_PATTERNS
    )


def safe_column(df, column, default=""):
    """
    Return a column if it exists, otherwise create
    a safe default Series.
    """

    if column in df.columns:
        return df[column]

    return pd.Series(
        [default] * len(df),
        index=df.index
    )


def first_nonempty(series):
    """
    Return the first meaningful value from a Series.
    """

    for value in series:

        value = clean_string(value)

        if value:
            return value

    return ""


def unique_values(series):
    """
    Return sorted unique non-empty values.
    """

    values = set()

    for value in series:

        value = clean_string(value)

        if value:
            values.add(value)

    return sorted(values)


def extract_source(row):
    """
    Determine source safely.

    Newer risk reports should contain SOURCE, but this
    function prevents the script from crashing if SOURCE
    is missing.

    If SOURCE is unavailable, we infer Snyk when Snyk-specific
    fields exist and Rapid7 when Rapid7-specific fields exist.
    """

    source = clean_string(
        row.get("SOURCE", "")
    )

    if source:
        return normalize_source(source)

    # Snyk-specific fields
    snyk_fields = [
        "ISSUE_ID",
        "RULE_KEY",
        "RISK_SCORE",
        "START_LINE",
        "START_COLUMN",
        "END_LINE",
        "END_COLUMN"
    ]

    for field in snyk_fields:

        value = clean_string(
            row.get(field, "")
        )

        if value:
            return "SNYK"

    # Rapid7-specific fields
    rapid7_fields = [
        "APP_UUID",
        "VULNERABILITY_UUID",
        "VULNERABILITY_SCORE",
        "MODULE_NAME",
        "ATTACK_TYPE",
        "ROOTCAUSE_URL",
        "ROOTCAUSE_METHOD",
        "SCAN_UUID",
        "SCAN_TYPE",
        "VECTOR_STRING",
        "INSIGHT_URL",
        "PROOF",
        "PROOF_DESCRIPTION"
    ]

    for field in rapid7_fields:

        value = clean_string(
            row.get(field, "")
        )

        if value:
            return "RAPID7"

    return "UNKNOWN"


def get_title(row):
    """
    Get the best available finding title.

    Supports both the older normalized risk-report
    structure and the newer scanner CSV structure.
    """

    candidates = [
        "TITLE",
        "NORMALIZED_TITLE",
        "RULE_KEY",
        "ATTACK_TYPE",
        "MODULE_NAME"
    ]

    for column in candidates:

        value = clean_string(
            row.get(column, "")
        )

        if value:
            return value

    return "Security Finding"


def get_cwe(row):
    """
    Get CWE from either scanner.
    """

    return clean_string(
        row.get("CWE", "")
    )


def get_file_path(row):
    """
    Get file path from the available CSV structure.
    """

    return clean_string(
        row.get("FILE_PATH", "")
    )


def get_url(row):
    """
    Get URL from either scanner structure.
    """

    candidates = [
        "URL",
        "ROOTCAUSE_URL",
        "INSIGHT_URL"
    ]

    for column in candidates:

        value = clean_string(
            row.get(column, "")
        )

        if value:
            return value

    return ""


def get_occurrence_count(row):
    """
    Safely calculate occurrence count.

    Uses OCCURRENCES when available.

    Otherwise defaults to 1 because each row represents
    one finding.
    """

    value = row.get(
        "OCCURRENCES",
        1
    )

    try:

        if pd.isna(value):
            return 1

        return max(
            int(float(value)),
            1
        )

    except (
        ValueError,
        TypeError
    ):

        return 1


def get_file_count(row):
    """
    Safely determine affected file count.
    """

    value = row.get(
        "FILE_COUNT",
        None
    )

    if value is not None:

        try:

            if not pd.isna(value):
                return max(
                    int(float(value)),
                    0
                )

        except (
            ValueError,
            TypeError
        ):
            pass

    file_path = get_file_path(row)

    return 1 if file_path else 0


def get_url_count(row):
    """
    Safely determine affected URL count.
    """

    value = row.get(
        "URL_COUNT",
        None
    )

    if value is not None:

        try:

            if not pd.isna(value):
                return max(
                    int(float(value)),
                    0
                )

        except (
            ValueError,
            TypeError
        ):
            pass

    url = get_url(row)

    return 1 if url else 0


def remediation_scope(file_count):
    """
    Determine remediation size.
    """

    if file_count > 50:
        return "Large"

    if file_count > 15:
        return "Medium"

    return "Small"


def calculate_risk_score(row):
    """
    Calculate a prioritization score.

    Priority provides the largest contribution.
    Occurrence count, affected files, source and scope
    provide additional context.
    """

    priority = normalize_priority(
        row.get("PRIORITY", "LOW")
    )

    base_scores = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25
    }

    score = base_scores.get(
        priority,
        25
    )

    occurrences = get_occurrence_count(
        row
    )

    file_count = get_file_count(
        row
    )

    source = extract_source(
        row
    )

    # Finding prevalence
    score += min(
        occurrences,
        50
    )

    # Code impact
    score += min(
        file_count * 2,
        30
    )

    # Snyk code findings receive additional weight
    if source == "SNYK":
        score += 25

    # Rapid7 runtime findings receive slightly less
    # weight than source-code findings when otherwise equal
    elif source == "RAPID7":
        score += 10

    # Large remediation scope deserves additional attention
    if file_count > 50:
        score += 20

    elif file_count > 15:
        score += 10

    return score


def group_key(row):
    """
    Build a stable grouping key.

    Group by application, source, title and CWE.

    This prevents duplicate findings from producing
    dozens of nearly identical remediation records.
    """

    app_name = clean_string(
        row.get("APP_NAME", "")
    )

    source = extract_source(
        row
    )

    title = get_title(
        row
    )

    cwe = get_cwe(
        row
    )

    return (
        app_name,
        source,
        title,
        cwe
    )


# ============================================================
# DISCOVER RISK REPORTS
# ============================================================

risk_reports = sorted(
    [
        file
        for file in os.listdir(
            ARC_DIR
        )
        if file.endswith(
            "-risk-report.csv"
        )
    ]
)

if not risk_reports:

    print(
        "No risk reports found."
    )

    raise SystemExit(0)


# ============================================================
# REPORT DISCOVERY
# ============================================================

print()
print("=" * 70)
print(
    f"ARC_DIR: {ARC_DIR}"
)
print(
    f"Risk Reports Found: {len(risk_reports)}"
)

for file in risk_reports:

    print(
        f"  {file}"
    )

print("=" * 70)
print()


# ============================================================
# PROCESS EACH APPLICATION
# ============================================================

for report_file in risk_reports:

    INPUT_FILE = os.path.join(
        ARC_DIR,
        report_file
    )

    APP_NAME = report_file.replace(
        "-risk-report.csv",
        ""
    )

    OUTPUT_FILE = os.path.join(
        ARC_DIR,
        f"{APP_NAME}-prioritized-findings.csv"
    )

    print()
    print("=" * 70)

    print(
        f"Processing: {report_file}"
    )

    print(
        f"Loading {INPUT_FILE}"
    )

    # --------------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------------

    try:

        df = pd.read_csv(
            INPUT_FILE
        )

    except Exception as exc:

        print(
            f"ERROR loading {INPUT_FILE}: {exc}"
        )

        continue

    if df.empty:

        print(
            f"{APP_NAME}: No findings found."
        )

        continue

    print(
        f"Loaded {len(df)} findings"
    )

    print(
        "Columns detected:"
    )

    print(
        ", ".join(df.columns)
    )

    # --------------------------------------------------------
    # NORMALIZE REQUIRED FIELDS
    # --------------------------------------------------------

    if "APP_NAME" not in df.columns:

        df["APP_NAME"] = APP_NAME

    else:

        df["APP_NAME"] = (
            df["APP_NAME"]
            .fillna(APP_NAME)
            .astype(str)
        )

    if "PRIORITY" not in df.columns:

        print(
            "WARNING: PRIORITY column missing. "
            "Defaulting findings to LOW."
        )

        df["PRIORITY"] = "LOW"

    else:

        df["PRIORITY"] = (
            df["PRIORITY"]
            .apply(normalize_priority)
        )

    if "SOURCE" not in df.columns:

        print(
            "WARNING: SOURCE column missing. "
            "Source will be inferred from scanner-specific fields."
        )

        df["SOURCE"] = df.apply(
            extract_source,
            axis=1
        )

    else:

        df["SOURCE"] = (
            df["SOURCE"]
            .apply(normalize_source)
        )

    if "TITLE" not in df.columns:

        print(
            "WARNING: TITLE column missing. "
            "Finding titles will be inferred."
        )

        df["TITLE"] = df.apply(
            get_title,
            axis=1
        )

    if "CWE" not in df.columns:

        df["CWE"] = ""

    if "FILE_PATH" not in df.columns:

        df["FILE_PATH"] = ""

    if "URL" not in df.columns:

        df["URL"] = ""

    if "DESCRIPTION" not in df.columns:

        df["DESCRIPTION"] = ""

    if "ACTION" not in df.columns:

        df["ACTION"] = ""

    if "VALIDATION" not in df.columns:

        df["VALIDATION"] = ""

    if "RECOMMENDED_ACTION" not in df.columns:

        df["RECOMMENDED_ACTION"] = df[
            "ACTION"
        ]

    if "OCCURRENCES" not in df.columns:

        df["OCCURRENCES"] = 1

    # --------------------------------------------------------
    # NOISE FILTERING
    # --------------------------------------------------------

    before_count = len(df)

    if "FILE_PATH" in df.columns:

        df = df[
            ~df["FILE_PATH"].apply(
                is_noise
            )
        ].copy()

    after_count = len(df)

    print(
        f"Filtered Noise Findings: "
        f"{before_count - after_count}"
    )

    if df.empty:

        print(
            f"{APP_NAME}: "
            "All findings were filtered as noise."
        )

        continue

    # --------------------------------------------------------
    # RAPID7 LOW-VALUE FILTERING
    # --------------------------------------------------------

    def is_low_value_r7(row):

        source = normalize_source(
            row.get("SOURCE", "")
        )

        title = clean_string(
            row.get("TITLE", "")
        ).upper()

        return (
            source == "RAPID7"
            and
            title in LOW_VALUE_R7
        )

    before_r7 = len(df)

    df = df[
        ~df.apply(
            is_low_value_r7,
            axis=1
        )
    ].copy()

    print(
        f"Filtered Low-Value Rapid7 Findings: "
        f"{before_r7 - len(df)}"
    )

    if df.empty:

        print(
            f"{APP_NAME}: "
            "No findings remain after filtering."
        )

        continue

    # ========================================================
    # GROUP FINDINGS
    # ========================================================

    grouped = []

    grouped_rows = {}

    for _, row in df.iterrows():

        key = group_key(
            row
        )

        if key not in grouped_rows:

            grouped_rows[key] = []

        grouped_rows[key].append(
            row
        )

    print(
        f"Unique Finding Groups: "
        f"{len(grouped_rows)}"
    )

    # --------------------------------------------------------
    # PROCESS GROUPS
    # --------------------------------------------------------

    for key, rows in grouped_rows.items():

        group = pd.DataFrame(
            rows
        )

        app_name_group = clean_string(
            group.iloc[0].get(
                "APP_NAME",
                APP_NAME
            )
        )

        source = clean_string(
            group.iloc[0].get(
                "SOURCE",
                ""
            )
        )

        title = clean_string(
            group.iloc[0].get(
                "TITLE",
                "Security Finding"
            )
        )

        cwe = clean_string(
            group.iloc[0].get(
                "CWE",
                ""
            )
        )

        # ----------------------------------------------------
        # PRIORITY
        # ----------------------------------------------------

        priorities = [
            normalize_priority(value)
            for value in group[
                "PRIORITY"
            ]
        ]

        highest_priority = min(
            priorities,
            key=lambda value:
                PRIORITY_RANK.get(
                    value,
                    99
                )
        )

        # ----------------------------------------------------
        # FILES
        # ----------------------------------------------------

        file_paths = unique_values(
            group["FILE_PATH"]
        )

        # ----------------------------------------------------
        # URLS
        # ----------------------------------------------------

        urls = unique_values(
            group["URL"]
        )

        # ----------------------------------------------------
        # OCCURRENCES
        # ----------------------------------------------------

        occurrence_total = 0

        for value in group[
            "OCCURRENCES"
        ]:

            try:

                if pd.isna(value):
                    occurrence_total += 1

                else:
                    occurrence_total += max(
                        int(float(value)),
                        1
                    )

            except (
                ValueError,
                TypeError
            ):

                occurrence_total += 1

        # ----------------------------------------------------
        # DIRECTORY ANALYSIS
        # ----------------------------------------------------

        directory_counts = {}

        for file_path in file_paths:

            normalized_path = (
                file_path
                .replace(
                    "\\",
                    "/"
                )
                .strip("/")
            )

            parts = normalized_path.split(
                "/"
            )

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
            key=lambda item:
                item[1],
            reverse=True
        )

        directory_summary = "\n".join(
            [
                f"{directory} ({count} files)"
                for directory, count
                in top_directories[:10]
            ]
        )

        # ----------------------------------------------------
        # REMEDIATION SCOPE
        # ----------------------------------------------------

        file_count = len(
            file_paths
        )

        if file_count > 50:

            scope = "Large"

        elif file_count > 15:

            scope = "Medium"

        else:

            scope = "Small"

        # ----------------------------------------------------
        # AFFECTED FILES
        # ----------------------------------------------------

        display_files = file_paths[
            :15
        ]

        affected_files = "\n".join(
            display_files
        )

        extra_files = max(
            0,
            file_count - 15
        )

        if extra_files:

            affected_files += (
                f"\n\n... and "
                f"{extra_files} additional files"
            )

        # ----------------------------------------------------
        # AFFECTED URLS
        # ----------------------------------------------------

        affected_urls = "\n".join(
            urls[:20]
        )

        # ----------------------------------------------------
        # DESCRIPTION
        # ----------------------------------------------------

        description = first_nonempty(
            group[
                "DESCRIPTION"
            ]
        )

        # ----------------------------------------------------
        # ACTION
        # ----------------------------------------------------

        action = first_nonempty(
            group[
                "RECOMMENDED_ACTION"
            ]
        )

        if not action:

            action = first_nonempty(
                group[
                    "ACTION"
                ]
            )

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        validation = first_nonempty(
            group[
                "VALIDATION"
            ]
        )

        # ----------------------------------------------------
        # BUILD GROUP ROW
        # ----------------------------------------------------

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
                occurrence_total,

            "FILE_COUNT":
                file_count,

            "URL_COUNT":
                len(urls),

            "REMEDIATION_SCOPE":
                scope,

            "TOP_DIRECTORIES":
                directory_summary,

            "AFFECTED_FILES":
                affected_files,

            "AFFECTED_URLS":
                affected_urls,

            "DESCRIPTION":
                description,

            "RECOMMENDED_ACTION":
                action,

            "VALIDATION":
                validation

        })

    # ========================================================
    # CREATE OUTPUT DATAFRAME
    # ========================================================

    output_df = pd.DataFrame(
        grouped
    )

    if output_df.empty:

        print(
            f"{APP_NAME}: "
            "No grouped findings generated."
        )

        continue

    # ========================================================
    # RISK SCORING
    # ========================================================

    output_df[
        "RISK_SCORE"
    ] = output_df.apply(
        calculate_risk_score,
        axis=1
    )

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    def risk_level(score):

        if score >= 125:
            return "Critical"

        if score >= 90:
            return "High"

        if score >= 60:
            return "Medium"

        return "Low"

    output_df[
        "RISK_LEVEL"
    ] = output_df[
        "RISK_SCORE"
    ].apply(
        risk_level
    )

    # ========================================================
    # SORT
    # ========================================================

    output_df[
        "_PRIORITY_RANK"
    ] = output_df[
        "PRIORITY"
    ].map(
        PRIORITY_RANK
    ).fillna(99)

    output_df = output_df.sort_values(
        by=[
            "_PRIORITY_RANK",
            "RISK_SCORE",
            "OCCURRENCES",
            "FILE_COUNT"
        ],
        ascending=[
            True,
            False,
            False,
            False
        ]
    )

    output_df.drop(
        columns=[
            "_PRIORITY_RANK"
        ],
        inplace=True
    )

    # ========================================================
    # EXPORT
    # ========================================================

    print(
        f"Writing: {OUTPUT_FILE}"
    )

    output_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    critical_count = len(
        output_df[
            output_df["PRIORITY"]
            == "CRITICAL"
        ]
    )

    high_count = len(
        output_df[
            output_df["PRIORITY"]
            == "HIGH"
        ]
    )

    medium_count = len(
        output_df[
            output_df["PRIORITY"]
            == "MEDIUM"
        ]
    )

    low_count = len(
        output_df[
            output_df["PRIORITY"]
            == "LOW"
        ]
    )

    print()
    print(
        f"Created: {OUTPUT_FILE}"
    )

    print(
        f"Prioritized Findings: "
        f"{len(output_df)}"
    )

    print(
        f"Critical: {critical_count}"
    )

    print(
        f"High: {high_count}"
    )

    print(
        f"Medium: {medium_count}"
    )

    print(
        f"Low: {low_count}"
    )

    print()
    print(
        "Top Findings:"
    )

    display_columns = [
        "PRIORITY",
        "SOURCE",
        "TITLE",
        "CWE",
        "FILE_COUNT",
        "REMEDIATION_SCOPE",
        "OCCURRENCES",
        "RISK_SCORE",
        "RISK_LEVEL"
    ]

    available_display_columns = [
        column
        for column in display_columns
        if column in output_df.columns
    ]

    print(
        output_df[
            available_display_columns
        ].head(10).to_string(
            index=False
        )
    )

    print(
        "=" * 70
    )


# ============================================================
# COMPLETE
# ============================================================

print()
print("=" * 70)
print(
    "Prioritization complete."
)
print("=" * 70)
