#!/usr/bin/env python3
#
# ============================================================
# Two-Pass AI Application Security Analysis
# ============================================================
#
# Current ARC pipeline:
#
#   security-report.csv
#          |
#          v
#   correlated-findings.csv
#          |
#          v
#   risk-report.csv
#          |
#          v
#   prioritized-findings.csv
#          |
#          +----------------------+
#          |                      |
#          v                      v
#       PASS 1                 PASS 2
#    Finding/Chunk            Application
#      Analysis               Synthesis
#          |                      |
#          +----------+-----------+
#                     |
#                     v
#          ai-security-analysis.md
#
# PASS 1:
#   Analyze prioritized findings in chunks.
#
# PASS 2:
#   Analyze the complete application picture using:
#     - prioritized findings
#     - Pass 1 analyses
#     - risk scores
#     - SAST/DAST sources
#     - remediation scope
#     - affected files
#     - affected URLs
#     - CWE
#     - recommended actions
#     - validation requirements
#
# Authentication:
#   Azure AD / DefaultAzureCredential
#
# Requirements:
#
#   pip install pandas openai azure-identity
#
# Environment variables:
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

RUN_DATE = datetime.now().strftime(
    "%Y-%m-%d"
)

ARC_DIR = os.path.join(
    "reports",
    "arc",
    RUN_DATE
)

PROMPT_FILE = (
    "APPSEC_ANALYSIS_PROMPT.md"
)

CHUNK_SIZE = 25

CHUNK_DELAY_SECONDS = 3

PASS2_DELAY_SECONDS = 3

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
        "AZURE_OPENAI_ENDPOINT environment variable "
        "is not set."
    )


if not os.path.exists(ARC_DIR):

    raise FileNotFoundError(
        f"ARC directory does not exist: {ARC_DIR}"
    )


if not os.path.exists(PROMPT_FILE):

    raise FileNotFoundError(
        f"Application security prompt not found: "
        f"{PROMPT_FILE}"
    )


# ============================================================
# Load Application Security Prompt
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
# Helpers
# ============================================================

def safe_value(value):

    if pd.isna(value):
        return ""

    return str(value)


def dataframe_to_csv(df):

    return df.to_csv(
        index=False
    )


def call_ai(
    system_prompt,
    user_prompt,
    max_completion_tokens=10000
):

    response = client.chat.completions.create(

        model=AZURE_OPENAI_MODEL,

        max_completion_tokens=max_completion_tokens,

        messages=[

            {
                "role": "system",
                "content": system_prompt
            },

            {
                "role": "user",
                "content": user_prompt
            }

        ]
    )

    content = (
        response.choices[0]
        .message
        .content
    )

    if not content:

        content = (
            "No analysis was returned."
        )

    return response, content


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
        f"No prioritized findings reports found "
        f"in {ARC_DIR}"
    )

    raise SystemExit(0)


# ============================================================
# Startup Information
# ============================================================

print()
print("=" * 70)
print(
    "TWO-PASS AI APPLICATION SECURITY ANALYSIS"
)
print("=" * 70)

print(
    f"Run Date:             {RUN_DATE}"
)

print(
    f"ARC Directory:        {ARC_DIR}"
)

print(
    f"Prompt:               {PROMPT_FILE}"
)

print(
    f"Model:                {AZURE_OPENAI_MODEL}"
)

print(
    f"Pass 1 Chunk Size:    {CHUNK_SIZE}"
)

print(
    f"Pass 1 Delay:         {CHUNK_DELAY_SECONDS}s"
)

print(
    f"Pass 2 Delay:         {PASS2_DELAY_SECONDS}s"
)

print(
    f"Applications Found:   {len(prioritized_reports)}"
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

    pass1_output_file = os.path.join(
        ARC_DIR,
        f"{app_name}-ai-pass1-analysis.md"
    )


    print()
    print("=" * 70)
    print(
        f"APPLICATION: {app_name}"
    )
    print(
        f"Input:       {input_file}"
    )
    print(
        f"Final:       {output_file}"
    )
    print("=" * 70)


    # ========================================================
    # Load Prioritized CSV
    # ========================================================

    try:

        df = pd.read_csv(
            input_file
        )

    except Exception as exc:

        print(
            f"ERROR loading {input_file}: {exc}"
        )

        continue


    if df.empty:

        print(
            f"{app_name}: No prioritized findings."
        )

        continue


    df = df.fillna("")


    print(
        f"Prioritized Findings Loaded: {len(df)}"
    )


    # ========================================================
    # Validate Columns
    # ========================================================

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

        print()
        print(
            "WARNING: Expected columns missing:"
        )

        for column in missing_columns:

            print(
                f"  - {column}"
            )

        print(
            "The available columns will still be used."
        )


    # ========================================================
    # Basic Application Statistics
    # ========================================================

    critical_count = len(
        df[
            df["PRIORITY"]
            .astype(str)
            .str.upper()
            == "CRITICAL"
        ]
    ) if "PRIORITY" in df.columns else 0


    high_count = len(
        df[
            df["PRIORITY"]
            .astype(str)
            .str.upper()
            == "HIGH"
        ]
    ) if "PRIORITY" in df.columns else 0


    medium_count = len(
        df[
            df["PRIORITY"]
            .astype(str)
            .str.upper()
            == "MEDIUM"
        ]
    ) if "PRIORITY" in df.columns else 0


    low_count = len(
        df[
            df["PRIORITY"]
            .astype(str)
            .str.upper()
            == "LOW"
        ]
    ) if "PRIORITY" in df.columns else 0


    print()
    print("Priority Distribution:")
    print(
        f"  Critical: {critical_count}"
    )
    print(
        f"  High:     {high_count}"
    )
    print(
        f"  Medium:   {medium_count}"
    )
    print(
        f"  Low:      {low_count}"
    )


    # ========================================================
    # PASS 1
    # ========================================================

    print()
    print("=" * 70)
    print(
        "PASS 1 — FINDING / CHUNK ANALYSIS"
    )
    print("=" * 70)


    pass1_results = []


    total_chunks = (
        (
            len(df)
            + CHUNK_SIZE
            - 1
        )
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


        print()
        print(
            f"Pass 1 Chunk "
            f"{chunk_number}/{total_chunks} "
            f""
            f"[rows {start + 1}-{end}]"
        )


        csv_data = dataframe_to_csv(
            chunk
        )


        pass1_system_prompt = f"""
You are performing Pass 1 of an application
security analysis.

Your job is to analyze a subset of prioritized
security findings for one application.

The findings have already gone through the
organization's correlation, risk, and prioritization
pipeline.

Use the supplied application security instructions
as the primary analysis guidance.

IMPORTANT:

- Do not invent vulnerabilities.
- Do not invent affected files.
- Do not invent URLs.
- Do not assume a finding exists if it is not in
  the supplied data.
- Distinguish SAST findings from DAST findings.
- Treat the supplied PRIORITY and RISK_SCORE as
  authoritative inputs.
- Look for relationships between findings.
- Identify recurring CWEs and root causes.
- Identify remediation patterns.
- Identify areas where multiple findings may be
  addressed by one engineering change.
- Identify validation requirements.

Produce useful structured analysis that can later
be synthesized into an application-level report.

Original application security instructions:

{appsec_prompt}
"""


        pass1_user_prompt = f"""
Application:
{app_name}

This is Pass 1, chunk {chunk_number}
of {total_chunks}.

Analyze the following prioritized findings.

Focus on:

1. Highest-risk findings
2. Critical and High findings
3. Repeated vulnerabilities
4. Common CWE patterns
5. SAST versus DAST observations
6. Shared affected application areas
7. Remediation scope
8. Developer remediation actions
9. Security validation requirements
10. Opportunities to fix multiple findings
    through one engineering change
11. Potential security themes or root causes

Return concise but actionable analysis.

CSV DATA:

{csv_data}
"""


        try:

            response, content = call_ai(
                pass1_system_prompt,
                pass1_user_prompt,
                max_completion_tokens=10000
            )

        except Exception as exc:

            print(
                f"ERROR in Pass 1 chunk "
                f"{chunk_number}: {exc}"
            )

            content = (
                f"Pass 1 chunk {chunk_number} "
                f"failed: {exc}"
            )


        pass1_results.append({

            "chunk":
                chunk_number,

            "start":
                start + 1,

            "end":
                end,

            "analysis":
                content

        })


        if "response" in locals():

            if response.usage:

                print(
                    f"  Tokens: "
                    f"{response.usage.total_tokens}"
                )


        if end < len(df):

            print(
                f"  Waiting "
                f"{CHUNK_DELAY_SECONDS} seconds..."
            )

            time.sleep(
                CHUNK_DELAY_SECONDS
            )


    # ========================================================
    # Save Pass 1 Results
    # ========================================================

    pass1_document = []

    pass1_document.append(
        f"# Pass 1 AI Security Analysis\n\n"
    )

    pass1_document.append(
        f"## Application\n\n"
        f"{app_name}\n\n"
    )

    pass1_document.append(
        f"## Findings\n\n"
        f"{len(df)}\n\n"
    )

    pass1_document.append(
        f"## Chunks\n\n"
        f"{total_chunks}\n\n"
    )

    pass1_document.append(
        "---\n\n"
    )


    for result in pass1_results:

        pass1_document.append(
            f"## Chunk {result['chunk']}\n\n"
        )

        pass1_document.append(
            f"Rows: "
            f"{result['start']}-"
            f"{result['end']}\n\n"
        )

        pass1_document.append(
            result["analysis"]
        )

        pass1_document.append(
            "\n\n---\n\n"
        )


    with open(
        pass1_output_file,
        "w",
        encoding="utf-8"
    ) as fd:

        fd.write(
            "".join(pass1_document)
        )


    print()
    print(
        f"Pass 1 saved: "
        f"{pass1_output_file}"
    )


    # ========================================================
    # PASS 2 — APPLICATION SYNTHESIS
    # ========================================================

    print()
    print("=" * 70)
    print(
        "PASS 2 — APPLICATION-LEVEL SYNTHESIS"
    )
    print("=" * 70)


    # --------------------------------------------------------
    # Build Pass 1 Context
    # --------------------------------------------------------

    pass1_context_parts = []


    for result in pass1_results:

        pass1_context_parts.append(

            f"""
--- PASS 1 CHUNK {result['chunk']} ---
Rows:
{result['start']}-{result['end']}

ANALYSIS:

{result['analysis']}

"""
        )


    pass1_context = "\n".join(
        pass1_context_parts
    )


    # --------------------------------------------------------
    # Build Complete Prioritized Data
    # --------------------------------------------------------

    complete_csv = dataframe_to_csv(
        df
    )


    # --------------------------------------------------------
    # Pass 2 System Prompt
    # --------------------------------------------------------

    pass2_system_prompt = f"""
You are performing Pass 2 of an application
security assessment.

Pass 1 analyzed individual chunks of prioritized
security findings.

Your task now is to synthesize those observations
into ONE coherent application-level security
assessment.

You must consider the complete application,
not just individual findings.

Use the original application security instructions
as your governing security guidance.

IMPORTANT:

- Do not invent findings.
- Do not invent vulnerabilities.
- Do not invent affected files.
- Do not invent URLs.
- Do not invent business functionality.
- Do not change the supplied priority or risk score.
- Clearly distinguish observed facts from
  recommendations.
- Treat the prioritized CSV as the authoritative
  finding inventory.
- Use Pass 1 analysis as supporting analysis,
  not as a replacement for the actual findings.

Your final assessment should be useful to:

1. Developers
2. Security Engineering
3. Application owners
4. Technical leadership

The goal is to turn the prioritized vulnerability
inventory into an actionable remediation strategy.

Original application security instructions:

{appsec_prompt}
"""


    # --------------------------------------------------------
    # Pass 2 User Prompt
    # --------------------------------------------------------

    pass2_user_prompt = f"""
Application:
{app_name}

============================================================
APPLICATION STATISTICS
============================================================

Total prioritized findings:
{len(df)}

Critical:
{critical_count}

High:
{high_count}

Medium:
{medium_count}

Low:
{low_count}


============================================================
COMPLETE PRIORITIZED FINDINGS
============================================================

{complete_csv}


============================================================
PASS 1 CHUNK ANALYSES
============================================================

{pass1_context}


============================================================
PASS 2 REQUIRED OUTPUT
============================================================

Produce a single application-level security assessment.

Use the following structure:

# Application Security Assessment

## 1. Executive Security Summary

Provide a concise explanation of the application's
current security posture based only on the supplied
findings.

Explain what matters most and why.

## 2. Overall Risk Assessment

Classify the overall application risk as:

- Critical
- High
- Medium
- Low

Explain the reasoning.

Base this on the actual prioritized findings,
risk scores, severity, frequency, scope, and
security impact.

## 3. Risk Snapshot

Summarize:

- Total prioritized findings
- Critical
- High
- Medium
- Low
- SAST findings
- DAST findings
- Major recurring CWEs
- Largest remediation scopes

## 4. Top Risks Requiring Immediate Action

Identify the most important risks.

For each:

- Finding
- Priority
- Source
- CWE
- Risk Score
- Occurrences
- Files affected
- URLs affected
- Remediation scope
- Why it matters
- Recommended action

## 5. Common Root Causes

Identify patterns across the findings.

Examples may include:

- Missing input validation
- Unsafe output handling
- Injection risks
- Missing security headers
- Authentication weaknesses
- Secrets management
- Insecure application configuration

Only identify a root cause when supported by
the supplied findings.

## 6. SAST Risk Analysis

Analyze Snyk/code findings.

Identify:

- Most important code vulnerabilities
- Common CWEs
- Most affected directories
- Files with repeated issues
- Opportunities to fix multiple findings
  with common code changes

## 7. DAST / Runtime Risk Analysis

Analyze Rapid7/runtime findings.

Identify:

- Externally observable risks
- Affected URLs
- Runtime configuration weaknesses
- Repeated attack types
- Validation requirements

## 8. Remediation Strategy

Provide an ordered remediation plan.

Use this general priority:

1. Critical vulnerabilities
2. High-risk exploitable vulnerabilities
3. Issues affecting large portions of the application
4. Repeated vulnerabilities with common root causes
5. Medium findings
6. Low-risk hardening

For each phase explain what engineering
should accomplish.

## 9. Developer Action Plan

Create concrete developer actions.

Prefer actions that remediate multiple findings
at once.

Examples:

- Centralize input validation
- Introduce parameterized database access
- Standardize output encoding
- Implement secure headers globally
- Remove secrets from source
- Introduce shared security middleware

Only recommend actions supported by the data.

## 10. Security Engineering Validation Plan

Describe how Security Engineering should verify
the remediation.

Include:

- Snyk re-scan
- Rapid7 re-scan
- Regression testing
- Positive testing
- Negative testing
- Relevant vulnerability-specific validation

## 11. Recommended Remediation Order

Provide a concise numbered list showing exactly
what should be fixed first, second, third, etc.

## 12. Residual Risk

Explain what risk may remain after the recommended
remediation and what should be monitored.

## 13. Security Engineering Conclusion

Provide a concise final assessment of the
application's security posture and remediation
readiness.

Do not merely repeat the CSV.

Synthesize the findings into a practical
engineering decision document.
"""


    print(
        "Submitting complete application "
        "for Pass 2 synthesis..."
    )


    try:

        pass2_response, pass2_content = call_ai(
            pass2_system_prompt,
            pass2_user_prompt,
            max_completion_tokens=15000
        )

    except Exception as exc:

        print(
            f"ERROR in Pass 2: {exc}"
        )

        pass2_content = (
            f"Pass 2 application synthesis failed:\n\n"
            f"{exc}"
        )

        pass2_response = None


    # ========================================================
    # Build Final Report
    # ========================================================

    final_document = []

    final_document.append(
        "# AI Application Security Analysis\n\n"
    )

    final_document.append(
        f"## Application\n\n"
        f"{app_name}\n\n"
    )

    final_document.append(
        f"## Analysis Date\n\n"
        f"{RUN_DATE}\n\n"
    )

    final_document.append(
        "## Analysis Method\n\n"
        "This report was generated using a two-pass "
        "security analysis process.\n\n"
    )

    final_document.append(
        "- **Pass 1:** Individual prioritized finding "
        "and chunk analysis.\n"
    )

    final_document.append(
        "- **Pass 2:** Application-level synthesis "
        "of the complete prioritized finding set "
        "and Pass 1 observations.\n\n"
    )

    final_document.append(
        "## Finding Inventory\n\n"
    )

    final_document.append(
        f"- Total prioritized findings: {len(df)}\n"
    )

    final_document.append(
        f"- Critical: {critical_count}\n"
    )

    final_document.append(
        f"- High: {high_count}\n"
    )

    final_document.append(
        f"- Medium: {medium_count}\n"
    )

    final_document.append(
        f"- Low: {low_count}\n\n"
    )

    final_document.append(
        "---\n\n"
    )

    final_document.append(
        pass2_content
    )

    final_document.append(
        "\n\n---\n\n"
    )

    final_document.append(
        "## Analysis Metadata\n\n"
    )

    final_document.append(
        f"- Model: {AZURE_OPENAI_MODEL}\n"
    )

    final_document.append(
        f"- Pass 1 chunks: {total_chunks}\n"
    )

    final_document.append(
        f"- Pass 1 chunk size: {CHUNK_SIZE}\n"
    )

    final_document.append(
        "- Source: prioritized findings CSV\n"
    )

    final_document.append(
        "\n"
    )

    final_document.append(
        "This report is an AI-assisted security analysis "
        "and should be reviewed by Security Engineering "
        "before final remediation decisions are made.\n"
    )


    # ========================================================
    # Write Final Report
    # ========================================================

    try:

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as fd:

            fd.write(
                "".join(final_document)
            )

    except Exception as exc:

        print(
            f"ERROR writing final report: {exc}"
        )

        continue


    # ========================================================
    # Pass 2 Usage
    # ========================================================

    if pass2_response is not None:

        if pass2_response.usage:

            print()
            print(
                "Pass 2 Token Usage:"
            )

            print(
                f"  Total: "
                f"{pass2_response.usage.total_tokens}"
            )


    # ========================================================
    # Complete Application
    # ========================================================

    print()
    print("=" * 70)
    print(
        f"APPLICATION COMPLETE: {app_name}"
    )
    print("=" * 70)

    print(
        f"Prioritized Findings: {len(df)}"
    )

    print(
        f"Pass 1 Chunks:        {total_chunks}"
    )

    print(
        f"Critical:             {critical_count}"
    )

    print(
        f"High:                 {high_count}"
    )

    print(
        f"Medium:               {medium_count}"
    )

    print(
        f"Low:                  {low_count}"
    )

    print()
    print(
        f"Pass 1 Report:        {pass1_output_file}"
    )

    print(
        f"Final AI Report:      {output_file}"
    )

    print("=" * 70)


print()
print("=" * 70)
print(
    "TWO-PASS AI SECURITY ANALYSIS COMPLETE"
)
print("=" * 70)
