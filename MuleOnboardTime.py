#!/usr/bin/env python3
"""
--- WARNING -- WARNING -- WARNING -- WARNING -- WARNING -- WARNING -- WARNING ---
This is example code only and has not been fully tested. Under no circumstance should
this code be run in a production environment.
---------------------------------------------------------------------------------
MIT License
Copyright (c) 2025 [fullname]
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
---------------------------------------------------------------------------------

Calculate API onboarding time in MuleSoft Anypoint Platform.

User story:
As a project manager, I want to know the time between an API specification is created
in Anypoint exchange and when the MuleSoft API specification implementation goes into
production, so that I can calculate the time it takes to onboard an API.  I also want
to know the maximum and average times.
- Since this is an API specification the definition of production is when the API is
  published in the API Manager production environment (PROD)
- For large numbers of APIs, this report will need to use page sizes to limit the
  number of APIs returned on each call and multiple calls for each page is required.

This version links Exchange API definition name to API Manager instances name:
- Exchange asset "assetId" (or name if assetId missing)
- API Manager instance name (name)
"""

import sys
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Optional

# --- WARNING -- WARNING -- WARNING -- WARNING -- WARNING -- WARNING -- WARNING ---
# This is example code only and has not been tested. Under no circumstance should
# this code be run in a production environment.

# ----------------------------------------------------
# HARD-CODED CONFIGURATION
# ----------------------------------------------------

ANYPOINT_BASE_URL = "https://anypoint.mulesoft.com"

# Asset types we consider as API specifications in Exchange
EXCHANGE_ASSET_TYPES = ["rest-api", "http-api", "soap-api"]

# Pagination
EXCHANGE_PAGE_SIZE = 100
APIM_PAGE_SIZE = 100


# ----------------------------------------------------
# Helper Functions
# ----------------------------------------------------

def iso_to_datetime(value: str) -> Optional[datetime]:
    """Convert ISO8601 string to datetime safely."""
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except OverflowError or OSError:
        return None


def normalize_name(name: Optional[str]) -> Optional[str]:
    """Normalize names for comparison (lowercase, stripped)."""
    if not name:
        return None
    return name.strip().lower()


# ----------------------------------------------------
# Authentication
# ----------------------------------------------------

def get_access_token(client_id: str, client_secret: str) -> str:
    """Use client_credentials to obtain a bearer token."""
    url = f"{ANYPOINT_BASE_URL}/accounts/api/v2/oauth2/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=data)
    if resp.status_code != 200:
        print(f"ERROR retrieving access token: {resp.status_code}\n{resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()["access_token"]


# ----------------------------------------------------
# Exchange
# ----------------------------------------------------

def fetch_exchange_specs_by_name(token: str, org_id: str) -> Dict[str, dict]:
    """
    Fetch Exchange assets and return a map keyed by normalized name:

        normalized_name -> {
            "name": display_name,
            "assetId": assetId,
            "groupId": groupId,
            "version": version,
            "created": datetime
        }

    If multiple assets share the same name, we keep the earliest createdDate.
    """
    headers = {"Authorization": f"Bearer {token}"}
    results: Dict[str, dict] = {}

    offset = 0
    while True:
        params = [
            ("organizationId", org_id),
            ("search", ""),
            ("includeSnapshots", "true"),
            ("offset", str(offset)),
            ("limit", str(EXCHANGE_PAGE_SIZE)),
        ] + [("types", t) for t in EXCHANGE_ASSET_TYPES]

        url = f"{ANYPOINT_BASE_URL}/exchange/api/v2/assets"
        resp = requests.get(url, headers=headers, params=params)

        if resp.status_code != 200:
            print(f"ERROR fetching Exchange assets: {resp.status_code}\n{resp.text}", file=sys.stderr)
            break

        data = resp.json()
        # v2 can return a list or wrap in 'assets' / 'items' depending on context
        if isinstance(data, list):
            items = data
        else:
            items = data.get("assets") or data.get("items") or []

        if not items:
            break

        for item in items:
            asset_id = item.get("assetId") or item.get("asset_id")
            group_id = item.get("groupId") or item.get("group_id")
            version = item.get("version") or item.get("assetVersion")
            display_name = item.get("name") or asset_id

            created_raw = (
                item.get("createdDate")
                or item.get("createdAt")
                or (item.get("version") or {}).get("createdDate")
            )
            created_dt = iso_to_datetime(created_raw) if created_raw else None

            norm_name = normalize_name(display_name)
            if not (norm_name and created_dt):
                continue

            existing = results.get(norm_name)
            # Keep the earliest creation date for that name
            if not existing or created_dt < existing["created"]:
                results[norm_name] = {
                    "name": display_name,
                    "assetId": asset_id,
                    "groupId": group_id,
                    "version": version,
                    "created": created_dt,
                }

        if len(items) < EXCHANGE_PAGE_SIZE:
            break

        offset += EXCHANGE_PAGE_SIZE

    return results


# ----------------------------------------------------
# API Manager
# ----------------------------------------------------

def get_api_name(inst: dict) -> Optional[str]:
    """
    Extract a reasonable display name for an API Manager instance.

    Depending on tenant / region / API Manager version, the field might be:
      - endpointName
      - name
      - assetName
      - instanceLabel
    """
    name = (
        inst.get("assetId")
        or inst.get("name")
    )
    return name


def fetch_env_api_instances(token: str, org_id: str, env_id: str) -> List[dict]:
    """Fetch all API instances in the given environment."""
    headers = {"Authorization": f"Bearer {token}"}
    results: List[dict] = []

    offset = 0
    while True:
        params = {
            "ascending": "false",
            "offset": offset,
            "limit": APIM_PAGE_SIZE,
            "sort": "createdDate",
        }

        url = (
            f"{ANYPOINT_BASE_URL}/apimanager/api/v1/organizations/"
            f"{org_id}/environments/{env_id}/apis"
        )

        resp = requests.get(url, headers=headers, params=params)

        if resp.status_code != 200:
            print(f"ERROR fetching API instances: {resp.status_code}\n{resp.text}", file=sys.stderr)
            break

        data = resp.json()
        # Depending on region/version, might be raw list or wrapped in "apis"/"items"
        if isinstance(data, list):
            items = data
        else:
            items = data.get("assets") or []

        if not items:
            break

        results.extend(items)

        if len(items) < APIM_PAGE_SIZE:
            break

        offset += APIM_PAGE_SIZE

    return results


# ----------------------------------------------------
# Processing
# ----------------------------------------------------

def calculate_onboarding_times(
    specs_by_name: Dict[str, dict],
    instances: List[dict]
) -> List[dict]:
    """
    Link API instances to Exchange specs by NAME and compute onboarding days.

    Returns list of:
      {
        "name": api_name,
        "spec_created": datetime,
        "env_created": datetime,
        "onboarding_days": float,
        "api_instance_id": str,
        "instance_label": str,
        "groupId": str,
        "assetId": str,
        "version": str
      }
    """
    output: List[dict] = []

    for inst in instances:
        raw_name = get_api_name(inst)
        norm_name = normalize_name(raw_name)
        if not norm_name:
            continue

        spec_info = specs_by_name.get(norm_name)
        if not spec_info:
            # No matching Exchange spec with same name
            continue

        inst_created_raw = inst.get("audit").get("created").get("date")
        inst_created = iso_to_datetime(inst_created_raw)
        if not inst_created:
            continue

        spec_created = spec_info["created"]
        delta_days = (inst_created - spec_created).total_seconds() / 86400.0

        output.append(
            {
                "name": spec_info["name"],
                "spec_created": spec_created,
                "env_created": inst_created,
                "onboarding_days": delta_days,
                "api_instance_id": inst.get("id"),
                "instance_label": inst.get("instanceLabel") or raw_name,
                "groupId": spec_info.get("groupId"),
                "assetId": spec_info.get("assetId"),
                "version": spec_info.get("version"),
            }
        )

    return output


def summarize(results: List[dict]) -> dict:
    if not results:
        return {
            "count": 0,
            "avg_days": None,
            "max_days": None,
            "max_item": None,
        }

    durations = [r["onboarding_days"] for r in results]
    avg_days = sum(durations) / len(durations)
    max_days = max(durations)
    max_item = max(results, key=lambda x: x["onboarding_days"])

    return {
        "count": len(results),
        "avg_days": avg_days,
        "max_days": max_days,
        "max_item": max_item,
    }


# ----------------------------------------------------
# Main
# ----------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Calculate MuleSoft API onboarding duration (Exchange → environment) by name."
    )
    parser.add_argument("--client_id", required=True, help="Connected App client_id")
    parser.add_argument("--client_secret", required=True, help="Connected App client_secret")
    parser.add_argument("--org_id", required=True, help="Anypoint Organization ID")
    parser.add_argument("--env_id", required=True, help="Anypoint Environment ID")

    args = parser.parse_args()

    print(
      "--- WARNING ---\n"
      " This is example code only and has not been\n"
      " fully tested.  Under no circumstance should\n"
      " this code be run in a production environment.\n"
      "---------------\n"
    )

    print("Authenticating...")
    token = get_access_token(args.client_id, args.client_secret)

    print("Fetching Exchange specs (by name)...")
    specs_by_name = fetch_exchange_specs_by_name(token, args.org_id)
    print(f"  Found {len(specs_by_name)} unique API spec names with creation dates.")

    print(f"Fetching API Manager instances in environment {args.env_id}...")
    env_instances = fetch_env_api_instances(token, args.org_id, args.env_id)
    print(f"  Found {len(env_instances)} API instances.")

    print("Calculating onboarding times (by matching names)...")
    joined = calculate_onboarding_times(specs_by_name, env_instances)
    summary = summarize(joined)

    if not joined:
        print(
            "\nNo API instances could be matched to Exchange specs by name.\n"
            "Check that:\n"
            "  - Exchange asset 'name' matches the API Manager instance name\n"
            "  - You are querying the correct ORG and environment\n"
            "  - Connected App has Exchange Viewer and API Manager permissions\n"
        )
        sys.exit(0)

    print("\nPer-API onboarding times (days):")
    print("-------------------------------------------------------------")
    for r in sorted(joined, key=lambda x: x["onboarding_days"]):
        print(
            f"{r['name']} "
            f"-> {r['onboarding_days']:.2f} days "
            f"[spec: {r['spec_created'].isoformat()} | env: {r['env_created'].isoformat()}]"
        )

    print("\nSummary:")
    print(f"  APIs counted     : {summary['count']}")
    if summary["avg_days"] is not None:
        print(f"  Average duration : {summary['avg_days']:.2f} days")
    else:
        print("  Average duration : N/A")
    if summary["max_days"] is not None:
        print(f"  Maximum duration : {summary['max_days']:.2f} days")
    else:
        print("  Maximum duration : N/A")

    if summary["max_item"]:
        m = summary["max_item"]
        print("\nSlowest onboarding API:")
        print(f"  Name             : {m['name']}")
        print(f"  Group / Asset    : {m.get('groupId')} / {m.get('assetId')}:{m.get('version')}")
        print(f"  API instance ID  : {m['api_instance_id']}")
        print(f"  Instance label   : {m['instance_label']}")
        print(f"  Spec created     : {m['spec_created'].isoformat()}")
        print(f"  Env instance    : {m['env_created'].isoformat()}")
        print(f"  Duration         : {m['onboarding_days']:.2f} days")


if __name__ == "__main__":
    main()
