#!/usr/bin/env python3
#
# AI Application Security Analysis
#
# Reads the current day's prioritized findings CSV files and sends
# them to Azure OpenAI in manageable chunks for security analysis.
#
# Pipeline:
#
#   security-report.csv
#          ↓
#   correlated-findings.csv
#          ↓
#   risk-report.csv
#          ↓
#   prioritized-findings.csv  ← THIS SCRIPT
#          ↓
#   AI analysis
#
# Requirements:
#
#   pip install pandas openai azure-identity
#
# Azure authentication:
#
#   Uses DefaultAzureCredential.
#
# Configuration environment variables:
#
#   AZURE_OPENAI_ENDPOINT
#   AZURE_OPENAI_API_VERSION
#   AZURE_OPENAI_MODEL
#
# Example:
#
#   export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com/"
#   export AZURE_OPENAI_API_VERSION="2024-10-21"
#   export AZURE_OPENAI_MODEL="gpt-5.4-mini"
#

import os
import time
from datetime import datetime

import pandas as pd

from azure.identity import (
    DefaultAzureCredential,
    get_bearer_token_provider
)

from openai import AzureOpenAI


# ============================================================
# Configuration
# ============================================================

RUN_DATE = datetime.now().strftime("%Y-%m-%d")

ARC_DIR = os.path.join(
    "reports",
    "arc",
    RUN_DATE
)

PROMPT_FILE = "APPSEC_ANALYSIS_PROMPT.md"

CHUNK_SIZE = 25

CHUNK_DELAY_SECONDS = 3

AZURE_OPENAI_ENDPOINT = os.getenv(
    "AZURE_OPENAI_ENDPOINT"
)

AZURE_OPENAI_API_VERSION = os.getenv(
    "AZURE_OPENAI_API_VERSION",
    "2024-10-21"
)

AZURE_OPENAI_MODEL = os.getenv(
    "AZURE_OPENAI_MODEL",
    "gpt-5.4-mini"
)


# ============================================================
# Validation
# ============================================================

if not AZURE_OPENAI_ENDPOINT:

    raise RuntimeError(
        "AZURE_OPENAI_ENDPOINT environment variable is not set."
    )


if not os.path.exists(ARC_DIR):

    raise FileNotFoundError(
        f"ARC directory does not exist: {ARC_DIR}"
    )


if not os.path.exists(PROMPT_FILE):

    raise FileNotFoundError(
        f"Application security prompt not found: {PROMPT_FILE}"
    )


# ============================================================
# Load Prompt
# ============================================================

with open(
    PROMPT_FILE,
    "r",
    encoding="utf-8"
) as fd:

    appsec_prompt = fd.read()


if not appsec_prompt.strip():

    raise RuntimeError(
        f"{PROMPT_FILE} is empty."
    )


# ============================================================
# Discover Prioritized Reports
# ============================================================

prioritized_reports = sorted(
    [
        file
        for file in os.listdir(ARC_DIR)
        if file.endswith(
            "-prioritized-findings.csv"
        )
    ]
)


if not prioritized_reports:

    print(
        f"No prioritized findings reports found in {ARC_DIR}"
    )

    raise SystemExit(0)


# ============================================================
# Azure OpenAI Client
# ============================================================

credential = DefaultAzureCredential()

token_provider = get_bearer_token_provider(
    credential,
    "https://cognitiveservices.azure.com/.default"
)

client = AzureOpenAI(
    azure_endpoint=AZURE_OPENAI_ENDPOINT,
    azure_ad_token_provider=token_provider,
    api_version=AZURE_OPENAI_API_VERSION
)


# ============================================================
# Display Configuration
# ============================================================

print()
print("=" * 70)
print("AI APPLICATION SECURITY ANALYSIS")
print("=" * 70)

print(
    f"Run Date:              {RUN_DATE}"
)

print(
    f"ARC Directory:         {ARC_DIR}"
)

print(
    f"Prompt:                {PROMPT_FILE}"
)

print(
    f"Model:                 {AZURE_OPENAI_MODEL}"
)

print(
    f"Chunk Size:            {CHUNK_SIZE}"
)

print(
    f"Prioritized Reports:   {len(prioritized_reports)}"
)

print("=" * 70)

for report in prioritized_reports:

    print(
        f"  {report}"
    )

print()


# ============================================================
# Process Each Application
# ============================================================

for report_file in prioritized_reports:

    input_file = os.path.join(
        ARC_DIR,
        report_file
    )

    app_name = report_file.replace(
        "-prioritized-findings.csv",
        ""
    )

    output_file = os.path.join(
        ARC_DIR,
        f"{app_name}-ai-security-analysis.md"
    )

    print()
    print("=" * 70)
    print(
        f"Processing Application: {app_name}"
    )
    print(
        f"Input: {input_file}"
    )
    print(
        f"Output: {output_file}"
    )
    print("=" * 70)


    # --------------------------------------------------------
    # Load CSV
    # --------------------------------------------------------

    try:

        df = pd.read_csv(
            input_file
        )

    except Exception as exc:

        print(
            f"ERROR: Unable to read {input_file}: {exc}"
        )

        continue


    if df.empty:

        print(
            f"{app_name}: No prioritized findings."
        )

        continue


    print(
        f"Loaded Findings: {len(df)}"
    )


    # --------------------------------------------------------
    # Validate Expected Columns
    # --------------------------------------------------------

    expected_columns = [

        "APP_NAME",
        "PRIORITY",
        "SOURCE",
        "TITLE",
        "CWE",
        "OCCURRENCES",
        "FILE_COUNT",
        "URL_COUNT",
        "REMEDIATION_SCOPE",
        "TOP_DIRECTORIES",
        "AFFECTED_FILES",
        "AFFECTED_URLS",
        "DESCRIPTION",
        "RECOMMENDED_ACTION",
        "VALIDATION",
        "RISK_SCORE"

    ]

    missing_columns = [
        column
        for column in expected_columns
        if column not in df.columns
    ]


    if missing_columns:

        print(
            "WARNING: Missing expected columns:"
        )

        for column in missing_columns:

            print(
                f"  - {column}"
            )

        print(
            "Continuing with available columns."
        )


    # --------------------------------------------------------
    # Normalize Data
    # --------------------------------------------------------

    df = df.fillna("")


    # --------------------------------------------------------
    # AI Analysis Output
    # --------------------------------------------------------

    analysis_parts = []

    analysis_parts.append(
        f"# AI Application Security Analysis\n\n"
    )

    analysis_parts.append(
        f"## Application\n\n"
        f"{app_name}\n\n"
    )

    analysis_parts.append(
        f"## Analysis Date\n\n"
        f"{RUN_DATE}\n\n"
    )

    analysis_parts.append(
        f"## Findings Submitted For Analysis\n\n"
        f"{len(df)}\n\n"
    )

    analysis_parts.append(
        "---\n\n"
    )


    # --------------------------------------------------------
    # Chunk Processing
    # --------------------------------------------------------

    total_chunks = (
        (len(df) + CHUNK_SIZE - 1)
        // CHUNK_SIZE
    )


    for chunk_number, start in enumerate(
        range(
            0,
            len(df),
            CHUNK_SIZE
        ),
        start=1
    ):

        end = min(
            start + CHUNK_SIZE,
            len(df)
        )

        chunk = df.iloc[
            start:end
        ]


        print(
            f"Analyzing chunk "
            f"{chunk_number}/{total_chunks} "
            f"({start + 1}-{end} of {len(df)})"
        )


        csv_data = chunk.to_csv(
            index=False
        )


        user_prompt = f"""
Application: {app_name}

This is chunk {chunk_number} of {total_chunks}
from the application's prioritized security findings.

Analyze the findings using the application security instructions
provided in the system prompt.

Pay particular attention to:

- Critical and High priority findings
- Risk score
- Finding frequency
- SAST vs DAST source
- CWE
- Remediation scope
- Affected files
- Affected URLs
- Primary application areas
- Recommended remediation
- Validation requirements
- Potential duplicate or related findings
- Developer remediation priorities
- Security engineering concerns

Do not invent findings that are not present in the supplied data.

Return actionable security analysis that can be incorporated
into the application's remediation package.

CSV DATA:

{csv_data}
"""


        # ----------------------------------------------------
        # Azure OpenAI Request
        # ----------------------------------------------------

        try:

            response = client.chat.completions.create(

                model=AZURE_OPENAI_MODEL,

                max_completion_tokens=10000,

                messages=[

                    {
                        "role": "system",
                        "content": appsec_prompt
                    },

                    {
                        "role": "user",
                        "content": user_prompt
                    }

                ]
            )


        except Exception as exc:

            error_message = (
                f"ERROR analyzing chunk "
                f"{chunk_number}: {exc}"
            )

            print(
                error_message
            )

            analysis_parts.append(
                f"## Chunk {chunk_number} Error\n\n"
                f"{error_message}\n\n"
            )

            continue


        # ----------------------------------------------------
        # Capture Response
        # ----------------------------------------------------

        content = (
            response.choices[0]
            .message.content
        )


        if not content:

            content = (
                "No analysis was returned "
                "for this chunk."
            )


        analysis_parts.append(
            f"## AI Analysis — Chunk {chunk_number}\n\n"
        )

        analysis_parts.append(
            content
        )

        analysis_parts.append(
            "\n\n---\n\n"
        )


        # ----------------------------------------------------
        # Usage Information
        # ----------------------------------------------------

        if response.usage:

            print(
                f"  Tokens: "
                f"{response.usage.total_tokens}"
            )


        # ----------------------------------------------------
        # Delay Between Requests
        # ----------------------------------------------------

        if end < len(df):

            print(
                f"  Waiting "
                f"{CHUNK_DELAY_SECONDS} seconds..."
            )

            time.sleep(
                CHUNK_DELAY_SECONDS
            )


    # ========================================================
    # Final Report
    # ========================================================

    analysis_parts.append(
        "\n## Analysis Complete\n\n"
    )

    analysis_parts.append(
        f"Application: {app_name}\n\n"
    )

    analysis_parts.append(
        f"Total prioritized findings analyzed: {len(df)}\n\n"
    )

    analysis_parts.append(
        "This analysis should be reviewed by Security Engineering "
        "and application owners before remediation decisions are finalized.\n"
    )


    final_report = "".join(
        analysis_parts
    )


    # ========================================================
    # Write Markdown
    # ========================================================

    try:

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as fd:

            fd.write(
                final_report
            )

    except Exception as exc:

        print(
            f"ERROR writing {output_file}: {exc}"
        )

        continue


    # ========================================================
    # Summary
    # ========================================================

    print()
    print("-" * 70)

    print(
        f"Application:       {app_name}"
    )

    print(
        f"Findings:          {len(df)}"
    )

    print(
        f"Chunks Analyzed:   {total_chunks}"
    )

    print(
        f"Created:           {output_file}"
    )

    print("-" * 70)


print()
print("=" * 70)
print("AI SECURITY ANALYSIS COMPLETE")
print("=" * 70)
