#!/usr/bin/env python3

import os
import re
import pandas as pd

from datetime import datetime
from urllib.parse import urlparse

RUN_DATE = datetime.now().strftime("%Y-%m-%d")

# --------------------------------------------------
# Configuration
# --------------------------------------------------

APP_REPO_MAPPING_FILE = "Application_Repo_Mapping.csv"

mapping_df = pd.read_csv(
    APP_REPO_MAPPING_FILE
)

print("Mapping Columns:")
print(mapping_df.columns.tolist())

RAPID7_DIR = os.path.join(
    "reports",
    "rapid7",
    RUN_DATE
)

SNYK_FILE = os.path.join(
    "reports",
    "snyk",
    RUN_DATE,
    "snyk-sast-findings.csv"
)

ARC_DIR = os.path.join(
    "reports",
    "arc",
    RUN_DATE
)

os.makedirs(ARC_DIR, exist_ok=True)

# Load Snyk once. Findings are filtered per application
# using the repositories discovered from the mapping CSV.
snyk_df = pd.read_csv(
    SNYK_FILE
)

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def get_mapped_repositories(
    mapping_df,
    search_terms
):

    repos = set()

    if not search_terms:
        return repos

    for search_term in search_terms:

        matches = mapping_df[
            mapping_df["SearchTerm"]
            .astype(str)
            .str.strip()
            .str.lower()
            == str(search_term).strip().lower()
        ]

        repos.update(
            matches["Repo"]
            .dropna()
            .astype(str)
            .str.strip()
            .tolist()
        )

    return repos


def get_application_repositories(
    mapping_df,
    app_name
):

    repos = set()

    if not app_name:
        return repos

    if "Application" not in mapping_df.columns:
        return repos

    app_matches = mapping_df[
        mapping_df["Application"]
        .astype(str)
        .str.lower()
        .str.contains(
            re.escape(app_name.lower()),
            na=False
        )
    ]

    repos.update(
        app_matches["Repo"]
        .dropna()
        .astype(str)
        .str.strip()
        .tolist()
    )

    return repos


def get_hostname(url):

    if pd.isna(url):
        return ""

    url = str(url).strip().lower()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:

        hostname = urlparse(url).hostname

        if hostname:
            return hostname.lower().rstrip(".")

    except Exception:
        pass

    return ""


def get_application_name(
    rapid7_df,
    rapid7_file
):

    # Prefer an application-name field if Rapid7 provides one.
    application_columns = [
        "app_name",
        "appName",
        "application",
        "application_name",
        "applicationName"
    ]

    for column in application_columns:

        if column in rapid7_df.columns:

            values = (
                rapid7_df[column]
                .dropna()
                .astype(str)
                .str.strip()
            )

            values = values[
                values != ""
            ]

            if not values.empty:
                return values.iloc[0]

    # Otherwise use the Rapid7 CSV filename.
    return os.path.splitext(
        rapid7_file
    )[0]


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


def sort_findings(df):

    severity_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4
    }

    if df.empty:
        return df

    df = df.copy()

    df["SORT"] = (
        df["RISK_PRIORITY"]
        .map(severity_order)
        .fillna(5)
    )

    df = df.sort_values(
        by="SORT"
    )

    return df.drop(
        columns=["SORT"]
    )


# --------------------------------------------------
# Discover Rapid7 Applications
# --------------------------------------------------

rapid7_files = [

    file

    for file in os.listdir(
        RAPID7_DIR
    )

    if file.endswith(".csv")

]

if not rapid7_files:

    raise Exception(
        f"No Rapid7 CSV files found in "
        f"{RAPID7_DIR}"
    )

# --------------------------------------------------
# Process Each App
# --------------------------------------------------

for rapid7_file in rapid7_files:

    rapid7_path = os.path.join(
        RAPID7_DIR,
        rapid7_file
    )

    print()
    print("=" * 60)

    print(f"Loading {rapid7_file}")

    rapid7_df = pd.read_csv(
        rapid7_path
    )

    if rapid7_df.empty:

        print(
            f"{rapid7_file}: "
            f"No Rapid7 findings."
        )

        continue

    # --------------------------------------------------
    # Identify Application
    # --------------------------------------------------

    app_name = get_application_name(
        rapid7_df,
        rapid7_file
    )

    if "app_uuid" in rapid7_df.columns:

        uuid_values = (
            rapid7_df["app_uuid"]
            .dropna()
        )

        if not uuid_values.empty:
            app_uuid = uuid_values.iloc[0]
        else:
            app_uuid = ""

    else:

        app_uuid = ""

    # --------------------------------------------------
    # Discover Application Domains
    # --------------------------------------------------

    rapid7_search_terms = set()

    if "rootCause_url" in rapid7_df.columns:

        for url in (
            rapid7_df["rootCause_url"]
            .dropna()
            .astype(str)
        ):

            hostname = get_hostname(
                url
            )

            if hostname:
                rapid7_search_terms.add(
                    hostname
                )

    # --------------------------------------------------
    # Map Domains / Application to Repositories
    # --------------------------------------------------

    domain_repos = get_mapped_repositories(
        mapping_df,
        rapid7_search_terms
    )

    application_repos = get_application_repositories(
        mapping_df,
        app_name
    )

    mapped_repos = (
        domain_repos
        | application_repos
    )

    print()
    print("=" * 60)

    print(
        f"Application: {app_name}"
    )

    print(
        f"Application UUID: {app_uuid}"
    )

    print()

    print(
        f"Search Terms: "
        f"{len(rapid7_search_terms)}"
    )

    for term in sorted(
        rapid7_search_terms
    ):
        print(f"  {term}")

    print()

    print(
        f"Repositories from Domain Mapping: "
        f"{len(domain_repos)}"
    )

    for repo in sorted(
        domain_repos
    ):
        print(f"  {repo}")

    print()

    print(
        f"Repositories from Application Mapping: "
        f"{len(application_repos)}"
    )

    for repo in sorted(
        application_repos
    ):
        print(f"  {repo}")

    print()

    print(
        f"Total Mapped Repositories: "
        f"{len(mapped_repos)}"
    )

    for repo in sorted(
        mapped_repos
    ):
        print(f"  {repo}")

    print("=" * 60)
    print()

    # --------------------------------------------------
    # Build Rapid7 Findings
    # --------------------------------------------------

    rapid7_records = []

    for _, row in rapid7_df.iterrows():

        title = (

            row.get(
                "attackType"
            )

            or

            row.get(
                "moduleName"
            )

            or

            "Rapid7 Finding"

        )

        rapid7_records.append({

            "APP_NAME":
                app_name,

            "APP_UUID":
                app_uuid,

            "SOURCE":
                "Rapid7",

            "SEVERITY":
                row.get(
                    "severity"
                ),

            "RISK_PRIORITY":
                normalize_priority(
                    row.get(
                        "severity"
                    )
                ),

            "TITLE":
                title,

            "CWE":
                "",

            "URL":
                row.get(
                    "rootCause_url"
                ),

            "METHOD":
                row.get(
                    "rootCause_method"
                ),

            "FILE_PATH":
                "",

            "DESCRIPTION":
                row.get(
                    "moduleName"
                ),

            "REMEDIATION":
                "",

            "HTTP_REQUEST":
                row.get(
                    "http_request",
                    ""
                ),

            "HTTP_RESPONSE":
                row.get(
                    "http_response",
                    ""
                )

        })

    # --------------------------------------------------
    # Build Snyk Findings
    # --------------------------------------------------

    snyk_records = []

    if mapped_repos:

        snyk_subset = snyk_df[

            snyk_df["PROJECT_NAME"]
            .astype(str)
            .str.lower()
            .apply(

                lambda project:

                any(
                    str(repo).lower()
                    in project
                    for repo in mapped_repos
                )

            )

        ].copy()

    else:

        # Do NOT attach all Snyk findings when no
        # repository can be associated with the app.
        snyk_subset = pd.DataFrame(
            columns=snyk_df.columns
        )

    for _, row in snyk_subset.iterrows():

        snyk_records.append({

            "APP_NAME":
                app_name,

            "APP_UUID":
                app_uuid,

            "SOURCE":
                "Snyk",

            "SEVERITY":
                row.get(
                    "SEVERITY"
                ),

            "RISK_PRIORITY":
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
                "",

            "METHOD":
                "",

            "FILE_PATH":
                row.get(
                    "FILE_PATH"
                ),

            "DESCRIPTION":
                row.get(
                    "DESCRIPTION"
                ),

            "REMEDIATION":
                row.get(
                    "REMEDIATION"
                )

        })

    print(
        f"Snyk Findings Before Filter: "
        f"{len(snyk_df)}"
    )

    print(
        f"Snyk Findings After Filter: "
        f"{len(snyk_subset)}"
    )

    matched_snyk_project_count = (
        snyk_subset["PROJECT_NAME"].nunique()
        if not snyk_subset.empty
        else 0
    )

    print(
        f"Matched Snyk Projects: "
        f"{matched_snyk_project_count}"
    )

    if not snyk_subset.empty:

        for project in sorted(
            snyk_subset["PROJECT_NAME"]
            .dropna()
            .astype(str)
            .unique()
        ):

            print(
                f"  {project}"
            )

    # --------------------------------------------------
    # Merge
    # --------------------------------------------------

    combined = pd.DataFrame(
        rapid7_records +
        snyk_records
    )

    snyk_only = pd.DataFrame(
        snyk_records
    )

    combined = sort_findings(
        combined
    )

    snyk_only = sort_findings(
        snyk_only
    )

    # --------------------------------------------------
    # Export
    # --------------------------------------------------

    safe_name = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        app_name
    ).strip("-")

    if not safe_name:
        safe_name = "unknown-application"

    output_file = os.path.join(
        ARC_DIR,
        f"{safe_name}-security-report.csv"
    )

    snyk_only_output_file = os.path.join(
        ARC_DIR,
        f"{safe_name}-snyk-only-security-report.csv"
    )

    combined.to_csv(
        output_file,
        index=False
    )

    snyk_only.to_csv(
        snyk_only_output_file,
        index=False
    )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    rapid7_count = len(
        rapid7_records
    )

    snyk_count = len(
        snyk_records
    )

    total_count = len(
        combined
    )

    print()

    print(
        f"Rapid7 Findings: "
        f"{rapid7_count}"
    )

    print(
        f"Snyk Findings: "
        f"{snyk_count}"
    )

    print(
        f"Total Findings: "
        f"{total_count}"
    )

    print()

    print(
        f"Created: "
        f"{output_file}"
    )

    print(
        f"Created: "
        f"{snyk_only_output_file}"
    )

    print()

    print("=" * 60)
    print(
        f"Application: {app_name}"
    )

    print(
        f"Mapped Repositories: "
        f"{len(mapped_repos)}"
    )

    for repo in sorted(
        mapped_repos
    ):
        print(f"  {repo}")

    print("=" * 60)
    print()


print("Processing complete.")
