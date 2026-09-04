#!/usr/bin/env python3
#
# This script is a stub. This code needs significant work & development, but this is a good start
#

import os
import pandas as pd
import json
import time
from openai import OpenAI
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AzureOpenAI


csv_content = pd.read_csv("./reports/arc/2026-09-02/Grain-Bid-Prod-security-report.csv")
with open("./APPSEC_ANALYSIS_PROMPT.md") as fd:
    appsec_prompt = fd.read()

print(appsec_prompt)
print(csv_content)

#client = OpenAI(api_key=OPENAI_API_KEY, base_url=API_BASE_URL)
client = AzureOpenAI(
    azure_endpoint="https://aif-sbd-securityrisk-prod-eastus2.openai.azure.com/",
    azure_ad_token_provider=get_bearer_token_provider(
        DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
    ),
    api_version="2024-10-21",
)


chunk_size = 25

for start in range(0, len(csv_content), chunk_size):
    print(start)
    time.sleep(3)

    chunk = csv_content.iloc[start:start + chunk_size]
    response = client.chat.completions.create(model="gpt-5.4-mini", max_completion_tokens=10000,
    
      messages=[
                 {"role": "system", "content": f"{appsec_prompt}"},
                 {"role": "user", "content": f"Here is the CSV Content from one of the relevant reports: \n\n{chunk.to_csv(index=False)}\n\n."}
               ]
     )

    print(response.choices[0].message.content)

    print("\n\n\n ********** MODEL INFO ********** \n\n\n")
    print(json.dumps(response.model_dump()))
