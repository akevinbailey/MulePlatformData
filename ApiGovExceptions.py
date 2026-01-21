#!/usr/bin/env python3
"""
--- WARNING -- WARNING -- WARNING -- WARNING -- WARNING -- WARNING -- WARNING ---
This is example code only and has not been fully tested. Under no circumstance should
this code be run in a production environment.
---------------------------------------------------------------------------------
MIT License
Copyright (c) 2026 Andrew Kevin Bailey

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

List APIs that are governed by Anypoint API Governance but are NOT conformant.

User story:
As an API platform owner, I want to know which published or implemented API
specifications that are monitored by MuleSoft API Governance do NOT conform to
my defined governance code or API policies, so that I can prioritize remediation.

What this script does (high-level):
1) Authenticates via client credentials against Access Management.
2) Calls the API Governance Experience API /stats/organization/targets endpoint to retrieve
   org-wide governance stats and governed API targets.
3) Extracts all API "targets" from the response.
4) Filters:
     - Only APIs whose conformance status is NOT "CONFORMANT".
     - Optionally (best-effort) restrict to "published" or "implemented"
       APIs based on lifecycle fields if they are present.
5) Prints:
     - A list of non-conformant APIs (groupId, assetId, version, name,
       conformance status).
     - Total governed APIs vs non-conformant APIs.

Notes / assumptions:
- Uses the API Governance Experience API described here:
    https://anypoint.mulesoft.com/exchange/68ef9520-24e9-4cf2-b2f5-620025690913/api-governance-xapi/
- As per the spec, every request must send:
    Authorization: Bearer <access_token>
    x-organization-id: <org or business group id>
    x-owner-id: <owner id, usually the same business group id>
- The exact JSON shape of /stats/organization/targets responses can vary. This script uses
  defensive parsing and you may need to adjust field names (see the functions:
  extract_targets(), get_conformance_status(), get_lifecycle_state()).
"""

import sys
import argparse
import requests
from typing import Dict, List, Optional, Tuple


# ----------------------------------------------------
# HARD-CODED CONFIGURATION
# ----------------------------------------------------

ANYPOINT_BASE_URL = "https://anypoint.mulesoft.com"

# API Governance Experience API base, per Salesforce KB:
#   https://anypoint.mulesoft.com/governance/xapi/api/v1/...
GOV_BASE = f"{ANYPOINT_BASE_URL}/governance/xapi/api/v1"


# ----------------------------------------------------
# Helper Functions
# ----------------------------------------------------

def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def normalize(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def safe_get(d: dict, path: List[str]) -> Optional[object]:
    cur: object = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def governance_headers(token: str, org_id: str, owner_id: str) -> Dict[str, str]:
    """
    Build headers required by the API Governance Experience API.

    From the Exchange spec ("General headers"):

      - Authorization: Bearer <access_token>
      - x-organization-id: <orgId>
      - x-owner-id: <ownerId>

    orgId and ownerId are typically your business group (organization) IDs.
    """
    return {
        "Authorization": f"Bearer {token}",
        "x-organization-id": org_id,
        "x-owner-id": owner_id,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# ----------------------------------------------------
# Authentication (Access Management)
# ----------------------------------------------------

def get_access_token(client_id: str, client_secret: str) -> str:
    """
    Obtain an access token using OAuth2 client_credentials.

    Endpoint:
      POST /accounts/api/v2/oauth2/token
    """
    url = f"{ANYPOINT_BASE_URL}/accounts/api/v2/oauth2/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=data, timeout=60)
    if resp.status_code != 200:
        die(f"ERROR retrieving access token: {resp.status_code}\n{resp.text}")
    j = resp.json()
    tok = j.get("access_token")
    if not tok:
        die(f"ERROR retrieving access token: missing access_token\n{resp.text}")
    return tok


# ----------------------------------------------------
# API Governance Experience API calls
# ----------------------------------------------------

def fetch_organization_stats(token: str, org_id: str, owner_id: str) -> dict:
    """
    Call /stats/organization/targets to obtain statistics and governed API targets.

    As described in the Exchange asset:

      - To obtain stats for the organization and any API, use the `/organization`
        and `/organization/targets/{orgId}/{groupId}/{assetId}` endpoints.

    Here we use the org-level `/stats/organization/targets` endpoint and then get the
    "targets" (or similar) to identify governed APIs.
    """
    #url = f"{GOV_BASE}/organization"
    url = f"{GOV_BASE}/stats/organization/targets"
    headers = governance_headers(token, org_id, owner_id)
    data = None

    resp = requests.get(url, headers=headers, timeout=60)
    if resp.status_code != 200:
        die(f"ERROR calling API Governance /stats/organization/targets: {resp.status_code}\n{resp.text}")

    try:
        data = resp.json()
    except Exception as e:
        die(f"ERROR parsing JSON from /stats/organization/targets: {e}")

    return data


def extract_targets(org_payload: dict) -> List[dict]:
    """
    Extract the list of governed API "targets" from the /stats/organization/targets payload.

    The exact shape is not publicly documented here, so we use defensive parsing:

    We try, in order:
      - payload["targets"]
      - payload["apis"]
      - payload["assets"]
      - payload["items"]
      - payload["data"]
      - or payload itself if it is already a list.

    If none are lists, we return [].
    """
    if isinstance(org_payload, list):
        return org_payload

    # common container keys
    for key in ("targets", "apis", "assets", "items", "data"):
        val = org_payload.get(key)
        if isinstance(val, list):
            return val

    # nothing obvious found
    return []


def get_conformance_status(target: dict) -> str:
    """
    Extract a conformance status from a target entry.

    Possible fields (tenant-dependent, best-effort):
      - "conformanceStatus"
      - "status" (if clearly governance-related)
      - "governanceStatus"
      - target["conformance"]["status"]

    Common values (case-insensitive):
      - "CONFORMANT"
      - "NOT_CONFORMANT"
      - "NOT_VALIDATED"
      - "IN_VALIDATION"
    """
    # Most likely
    v = target.get("conformanceStatus")
    if isinstance(v, str):
        return v.upper()

    # Some payloads might just have "status" for conformance
    v = target.get("governanceStatus")
    if isinstance(v, str):
        return v.upper()

    v = target.get("status")
    if isinstance(v, str):
        # Heuristic: if value looks like a conformance label
        norm = v.upper()
        if any(x in norm for x in ("CONFORMANT", "VALIDATED", "NOT_CONFORMANT", "NOT_VALIDATED")):
            return norm

    # Nested "conformance": { "status": "..." }
    conf = target.get("conformance") or safe_get(target, ["governance", "conformance"])
    if isinstance(conf, dict):
        v = conf.get("status")
        if isinstance(v, str):
            return v.upper()
    elif isinstance(conf, str):
        return conf.upper()

    return "UNKNOWN"


def get_lifecycle_state(target: dict) -> str:
    """
    Best-effort extraction of lifecycle / publication state.

    Potential fields:
      - "lifecycleState"
      - "lifecycleStatus"
      - "assetState"
      - "state"
      - nested under "asset" or "spec"

    This is used only as a *filter hint*; if we can't determine it, we treat
    the target as included (because it is already governed by API Governance).
    """
    for key in ("lifecycleState", "lifecycleStatus", "assetState", "state"):
        v = target.get(key)
        if isinstance(v, str):
            return v

    # Look inside nested asset/spec structures if present
    nested = safe_get(target, ["asset", "lifecycleState"])
    if isinstance(nested, str):
        return nested

    nested = safe_get(target, ["spec", "lifecycleState"])
    if isinstance(nested, str):
        return nested

    return ""


def is_published_or_implemented(target: dict) -> bool:
    """
    Decide whether the target should count as "published or implemented".

    Because the exact field names are tenant-dependent, this is intentionally
    conservative: if we can detect a lifecycle state, and it clearly says
    "published" or "implemented", we keep it. If we can't detect any lifecycle
    info at all, we *also* keep it, because API Governance already filters to
    real governed APIs.

    Adjust this function if you want stricter behavior in your tenant.
    """
    state = normalize(get_lifecycle_state(target))
    if not state:
        # Unknown: include rather than accidentally excluding governed APIs
        return True

    if "publish" in state:
        return True
    if "implement" in state:
        return True

    # Example: some tenants might use "active" or other labels; you can expand here
    return False


def get_api_identity(target: dict) -> Tuple[str, str, str, str]:
    """
    Extract (groupId, assetId, version, name) from a governance target.

    The Experience API is built on top of Exchange, so groupId/assetId/version
    should typically match Exchange asset coordinates.

    We use several fallbacks to increase the odds of success.
    """
    group_id = (
        target.get("asset_id")
        or target.get("id")
        or target.get("group")
        or safe_get(target, ["asset_id", "groupId"])
        or ""
    )
    target_type = (
        target.get("targetType")
        or target.get("target_type")
        or ""
    )
    version = (
        target.get("version")
        or target.get("assetVersion")
        or safe_get(target, ["asset", "version"])
        or safe_get(target, ["asset", "assetVersion"])
        or ""
    )

    name = (
        target.get("label")
        or target.get("name")
        or safe_get(target, ["asset", "name"])
        or "UNKNOWN"
    )

    return str(group_id), str(target_type), str(version), str(name)


# ----------------------------------------------------
# Main
# ----------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "List governed APIs that are NOT conformant to Anypoint API Governance "
            "(based on /stats/organization/targets stats)."
        )
    )
    parser.add_argument("--auth_token", help="API Governance authentication token")
    #parser.add_argument("--client_id", required=True, help="Connected App client_id")
    #parser.add_argument("--client_secret", required=True, help="Connected App client_secret")
    parser.add_argument(
        "--org_id",
        required=True,
        help="Anypoint organization (business group) ID for x-organization-id header",
    )
    parser.add_argument(
        "--owner_id",
        help=(
            "Anypoint owner (business group) ID for x-owner-id header. "
            "Defaults to org_id if omitted."
        ),
    )

    args = parser.parse_args()
    owner_id = args.owner_id or args.org_id

    print(
        "--- WARNING ---\n"
        " This is example code only and has not been\n"
        " fully tested. Under no circumstance should\n"
        " this code be run in a production environment.\n"
        "---------------\n"
    )

    print("Authenticating...")
    #token = get_access_token(args.client_id, args.client_secret)
    token = args.auth_token

    print(f"Calling API Governance /stats/organization/targets for org_id={args.org_id} owner_id={owner_id} ...")
    org_payload = fetch_organization_stats(token, args.org_id, owner_id)

    targets = extract_targets(org_payload)
    print(f"  Found {len(targets)} governed targets in /stats/organization/targets payload.")

    if not targets:
        print(
            "\nNo governed APIs returned by /stats/organization/targets.\n"
            "Check that:\n"
            "  - You have API Governance enabled and profiles configured\n"
            "  - Your Connected App has Governance Viewer or Admin permissions\n"
            "  - You are passing the correct org_id and owner_id headers\n"
        )
        sys.exit(0)

    nonconformant: List[dict] = []
    total_governed = 0

    for t in targets:
        asset_id, target_type, version, name = get_api_identity(t)
        if not (asset_id and target_type and version):
            # Can't identify the API reliably
            continue

        conf_status = get_conformance_status(t)
        if conf_status == "UNKNOWN":
            # Optionally, you could keep these and investigate
            continue

        if not is_published_or_implemented(t):
            # Best-effort lifecycle filter, see function docs
            continue

        total_governed += 1

        if conf_status != "CONFORMANT":
            nonconformant.append(
                {
                    "Id": asset_id,
                    "targetType": target_type,
                    "version": version,
                    "name": name,
                    "conformanceStatus": conf_status,
                }
            )

    print("\nNon-conformant governed APIs (best-effort published/implemented filter):")
    print("-----------------------------------------------------------------------")
    if not nonconformant:
        print("  None found. All governed APIs appear conformant.")
    else:
        # Sort by name then status for readability
        for entry in sorted(nonconformant, key=lambda x: (x["name"].lower(), x["version"])):
            print(
                f"{entry['name']} "
                f"(Id={entry['asset_id']}, targetType={entry['target_type']}, version={entry['version']}) "
                f"=> status={entry['conformanceStatus']}"
            )

    print("\nSummary:")
    print("--------")
    print(f"  Governed API targets considered : {total_governed}")
    print(f"  Non-conformant API targets      : {len(nonconformant)}")

    if total_governed > 0:
        pct = (len(nonconformant) / total_governed) * 100.0
        print(f"  Non-conformance percentage      : {pct:.2f}%")
    else:
        print("  Non-conformance percentage      : N/A (no governed APIs found)")

    print("\nNote:")
    print(
        "  This script uses best-effort field detection for conformance and lifecycle state.\n"
        "  Inspect one raw /stats/organization/targets response in your tenant and adjust:\n"
        "    - extract_targets()\n"
        "    - get_conformance_status()\n"
        "    - get_lifecycle_state() / is_published_or_implemented()\n"
        "  to match your actual payload shape."
    )


if __name__ == "__main__":
    main()