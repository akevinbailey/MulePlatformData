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

Report API policy access violations (Client ID/Secret, OAuth, OpenID Connect)
for the past 30 days, for MuleSoft managed APIs in a given org+environment.

What it does (high-level):
1) Lists API instances from API Manager for the target org/environment.
2) For each API instance, retrieves applied policy instances from API Manager.
3) Uses Anypoint Monitoring Metrics API (AMQL) to query policy violations grouped by:
      - api.instance.id
      - policy.violation.id
   within the last 30 days.
4) Filters violations to those whose violated policy instance matches one of:
      - Client ID Enforcement
      - OAuth (any OAuth policy)
      - OpenID Connect (any OIDC policy)
5) Outputs:
      - All matching APIs with violated policy instance and total violations
      - Total violations per API
      - Total violations per policy (across all APIs)

Notes / assumptions (important):
- Policy violations in Anypoint Monitoring are grouped by a "policy violation ID".
  In practice, this commonly corresponds to the API Manager *policy instance id*.
  This script joins the Metrics "policy violation id" dimension to API Manager policy
  instance "id". If your tenant uses a different identifier, adjust the join.
- The Metrics API requires the "observability" endpoints and AMQL queries.
- Some tenants require "Authorization: Bearer <token>" and others accept "Authentication: <token>".
  This script sends both headers to be resilient.

Refs:
- Metrics API base: https://anypoint.mulesoft.com/observability/api/v1/...
- API Manager APIs: https://anypoint.mulesoft.com/apimanager/api/v1/...
"""

import sys
import argparse
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple


# ----------------------------------------------------
# HARD-CODED CONFIGURATION
# ----------------------------------------------------
ANYPOINT_BASE_URL = "https://anypoint.mulesoft.com"

# Pagination
APIM_PAGE_SIZE = 100

# Metrics API endpoints
OBS_BASE = f"{ANYPOINT_BASE_URL}/observability/api/v1"

# We only care about violations caused by these policy families
AUTH_POLICY_KEYWORDS = [
    "client id",          # Client ID Enforcement (and similar)
    "oauth",              # OAuth 2.0 policies
    "open id", "openid",  # OpenID Connect policies
]


# ----------------------------------------------------
# Helper Functions
# ----------------------------------------------------
def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def normalize(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def is_auth_policy_name(policy_name: str) -> bool:
    p = normalize(policy_name)
    return any(k in p for k in AUTH_POLICY_KEYWORDS)


def http_headers(token: str) -> Dict[str, str]:
    # Be tolerant: some docs show "Authentication", most platform APIs use "Authorization: Bearer"
    return {
        "Authorization": f"Bearer {token}",
        "Authentication": token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def safe_get(d: dict, path: List[str]) -> Optional[object]:
    cur: object = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


# ----------------------------------------------------
# Authentication (Access Management)
# ----------------------------------------------------
def get_access_token(client_id: str, client_secret: str) -> str:
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
# API Manager
# ----------------------------------------------------
def fetch_env_api_instances(token: str, org_id: str, env_id: str) -> List[dict]:
    """
    Fetch all API instances in the given org/environment.

    Endpoint pattern:
      GET /apimanager/api/v1/organizations/{orgId}/environments/{envId}/apis
    """
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
        url = f"{ANYPOINT_BASE_URL}/apimanager/api/v1/organizations/{org_id}/environments/{env_id}/apis"
        resp = requests.get(url, headers=headers, params=params, timeout=60)

        if resp.status_code != 200:
            die(f"ERROR fetching API instances: {resp.status_code}\n{resp.text}")

        data = resp.json()
        # In many tenants this is returned under "assets" (as your working code handled)
        if isinstance(data, list):
            items = data
        else:
            items = data.get("assets") or data.get("items") or []

        if not items:
            break

        results.extend(items)

        if len(items) < APIM_PAGE_SIZE:
            break

        offset += APIM_PAGE_SIZE

    return results


def get_api_instance_name(api_obj: dict) -> str:
    # Be conservative: different API Manager versions vary
    return (
        api_obj.get("name")
        or api_obj.get("assetId")
        or api_obj.get("assetName")
        or api_obj.get("instanceLabel")
        or api_obj.get("id")
        or "UNKNOWN"
    )


def fetch_api_policies(token: str, org_id: str, env_id: str, api_id: str) -> List[dict]:
    """
    Fetch policy instances applied to a specific API instance.

    Endpoint (documented in multiple sources):
      GET /apimanager/api/v1/organizations/{orgId}/environments/{envId}/apis/{apiId}/policies

    Some tenants support:
      ?fullInfo=true
    This function tries with fullInfo=true first, then falls back.
    """
    headers = {"Authorization": f"Bearer {token}"}
    base = f"{ANYPOINT_BASE_URL}/apimanager/api/v1/organizations/{org_id}/environments/{env_id}/apis/{api_id}/policies"

    # Try fullInfo=true first (if unsupported, we retry without it)
    for params in ({"fullInfo": "true"}, None):
        resp = requests.get(base, headers=headers, params=params, timeout=60)
        if resp.status_code == 200:
            j = resp.json()
            if isinstance(j, list):
                return j
            return j.get("policies") or j.get("items") or j.get("assets") or []
        if resp.status_code in (400, 404):
            continue
        die(f"ERROR fetching policies for API {api_id}: {resp.status_code}\n{resp.text}")

    return []


# ----------------------------------------------------
# Metrics API (Anypoint Monitoring)
# ----------------------------------------------------
def list_metric_types(token: str) -> List[str]:
    url = f"{OBS_BASE}/metric_types"
    resp = requests.get(url, headers=http_headers(token), timeout=60)
    if resp.status_code != 200:
        die(f"ERROR listing metric types: {resp.status_code}\n{resp.text}")
    j = resp.json()
    if isinstance(j, list):
        return [str(x) for x in j]
    return [str(x) for x in (j.get("metricTypes") or j.get("data") or j.get("items") or [])]


def describe_metric(token: str, metric_name: str) -> dict:
    url = f"{OBS_BASE}/metric_types/{metric_name}:describe"
    resp = requests.get(url, headers=http_headers(token), timeout=60)
    if resp.status_code != 200:
        die(f"ERROR describing metric {metric_name}: {resp.status_code}\n{resp.text}")
    return resp.json()


def pick_metric_and_fields(token: str) -> Tuple[str, str, str]:
    """
    Find a metric + dimensions that can support policy-violation reporting.

    Returns:
      (metric_name, api_instance_dim, policy_violation_dim)

    Strategy:
    - Prefer metric "mulesoft.api" if it contains a dimension with "api.instance" and one with both "policy" and "violation".
    - Otherwise scan metrics that start with "mulesoft.api" and pick the first that fits.
    """
    preferred = ["mulesoft.api", "mulesoft.api.summary", "mulesoft.api.metrics", "mulesoft.api.request"]
    candidates = preferred + [m for m in list_metric_types(token) if str(m).startswith("mulesoft.api")]

    checked = set()
    for metric in candidates:
        if metric in checked:
            continue
        checked.add(metric)

        desc = describe_metric(token, metric)
        dims = desc.get("dimensions") or desc.get("attributes") or []
        dim_names = [d.get("name") for d in dims if isinstance(d, dict) and d.get("name")]

        api_dim = None
        viol_dim = None

        for dn in dim_names:
            nd = normalize(dn)
            if api_dim is None and ("api.instance" in nd or nd == "api.instance.id"):
                api_dim = dn
            if viol_dim is None and ("violation" in nd and "policy" in nd):
                viol_dim = dn

        # Common fallbacks
        if api_dim is None:
            for dn in dim_names:
                if normalize(dn) in ("api.instance.id", "api.id"):
                    api_dim = dn
                    break

        if api_dim and viol_dim:
            return metric, api_dim, viol_dim

    die(
        "ERROR: Could not find a Metrics API metric that exposes both an API instance id dimension "
        "and a policy violation id dimension. Run the 'describe' calls manually to inspect fields."
    )
    raise RuntimeError("unreachable")


def metrics_search(token: str, amql_query: str, limit: int = 500, offset: int = 0) -> List[dict]:
    url = f"{OBS_BASE}/metrics:search"
    resp = requests.post(
        url,
        headers=http_headers(token),
        params={"limit": str(limit), "offset": str(offset)},
        json={"query": amql_query},
        timeout=120,
    )
    if resp.status_code != 200:
        die(f"ERROR metrics search: {resp.status_code}\nQuery: {amql_query}\n{resp.text}")
    j = resp.json()
    data = j.get("data")
    if isinstance(data, list):
        return data
    # Some shapes return "items"
    items = j.get("items")
    return items if isinstance(items, list) else []


# ----------------------------------------------------
# Processing
# ----------------------------------------------------
def build_policy_index(policies: List[dict]) -> Dict[str, dict]:
    """
    Returns:
      policy_instance_id -> {
          "id": "...",
          "name": "...",
          "type": "...",
          "templateId": "...",
          "enabled": bool,
          "raw": <original policy dict>
      }
    """
    out: Dict[str, dict] = {}
    for p in policies or []:
        pid = str(p.get("id") or "")
        if not pid:
            continue

        # Field names vary; try common ones
        name = (
            p.get("name")
            or safe_get(p, ["policyTemplate", "name"])
            or safe_get(p, ["template", "name"])
            or p.get("policyName")
            or "UNKNOWN_POLICY"
        )
        template_id = (
            str(p.get("templateId") or "")
            or str(safe_get(p, ["policyTemplate", "id"]) or "")
            or str(safe_get(p, ["template", "id"]) or "")
        )
        enabled = bool(p.get("enabled")) if p.get("enabled") is not None else True

        out[pid] = {
            "id": pid,
            "name": str(name),
            "templateId": template_id,
            "enabled": enabled,
            "raw": p,
        }
    return out


# noinspection SqlNoDataSourceInspection
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Report auth-related policy access violations (Client ID/OAuth/OIDC) for the last 30 days."
    )
    parser.add_argument("--client_id", required=True, help="Connected App client_id")
    parser.add_argument("--client_secret", required=True, help="Connected App client_secret")
    parser.add_argument("--org_id", required=True, help="Anypoint Organization ID (business group)")
    parser.add_argument("--env_id", required=True, help="Anypoint Environment ID")
    parser.add_argument("--days", type=int, default=30, help="Lookback window in days (default 30)")

    args = parser.parse_args()

    print(
        "--- WARNING ---\n"
        " This is example code only and has not been\n"
        " fully tested. Under no circumstance should\n"
        " this code be run in a production environment.\n"
        "---------------\n"
    )

    print("Authenticating...")
    token = get_access_token(args.client_id, args.client_secret)

    print(f"Fetching API Manager instances for org={args.org_id} env={args.env_id} ...")
    apis = fetch_env_api_instances(token, args.org_id, args.env_id)
    print(f"  Found {len(apis)} API instances.")

    # Build API lookup by id (API Manager uses environment-scoped API id; Metrics typically uses api.instance.id)
    api_by_id: Dict[str, dict] = {}
    for a in apis:
        aid = str(a.get("id") or "")
        if aid:
            api_by_id[aid] = a

    print("Fetching policy instances for each API (this can take a while)...")
    # policy_index_by_api: api_id -> (policy_instance_id -> policy info)
    policy_index_by_api: Dict[str, Dict[str, dict]] = {}
    for i, a in enumerate(apis, start=1):
        aid = str(a.get("id") or "")
        if not aid:
            continue
        pols = fetch_api_policies(token, args.org_id, args.env_id, aid)
        policy_index_by_api[aid] = build_policy_index(pols)
        if i % 25 == 0:
            print(f"  ...policies fetched for {i}/{len(apis)} APIs")

    print("Discovering Metrics API fields for policy violations...")
    metric_name, api_dim, viol_dim = pick_metric_and_fields(token)
    print(f"  Using metric: {metric_name}")
    print(f"  API instance dimension: {api_dim}")
    print(f"  Policy violation dimension: {viol_dim}")

    end_dt = now_utc()
    start_dt = end_dt - timedelta(days=args.days)
    start_ms = to_epoch_ms(start_dt)
    end_ms = to_epoch_ms(end_dt)

    # Query counts grouped by API instance id + policy violation id
    # Required filters: sub_org.id and env.id (per Metrics API docs)
    #
    # We also try to exclude empty violation ids in query; if your tenant stores nulls differently,
    # the post-filter step below will still handle it.
    amql = (
        f'SELECT COUNT(requests) AS "violations", "{api_dim}", "{viol_dim}" '
        f'FROM "{metric_name}" '
        f'WHERE "sub_org.id" = \'{args.org_id}\' AND "env.id" = \'{args.env_id}\' '
        f'AND timestamp BETWEEN {start_ms} AND {end_ms} '
        f'GROUP BY "{api_dim}", "{viol_dim}" '
        f'LIMIT 2000'
    )

    print(f"Querying Metrics API for the last {args.days} days of policy violations...")
    rows = metrics_search(token, amql, limit=2000, offset=0)
    print(f"  Metrics rows returned: {len(rows)}")

    # Join + filter to auth-related policies
    per_api_totals: Dict[str, int] = {}
    per_policy_totals: Dict[str, int] = {}
    findings: List[dict] = []

    for r in rows:
        # tolerate different key naming returned by API
        violations = r.get("violations") or r.get('COUNT(requests)') or 0
        try:
            v_count = int(violations)
        except ValueError:
            continue

        api_instance_id = str(r.get(api_dim) or r.get("api.instance.id") or r.get("api.id") or "")
        violation_id = str(r.get(viol_dim) or "")

        if v_count <= 0 or not api_instance_id or not violation_id:
            continue

        api_obj = api_by_id.get(api_instance_id)
        if not api_obj:
            # Not one of the APIs returned by API Manager for this env (or id mismatch)
            continue

        # Join violation id -> API Manager policy instance id
        pol_idx = policy_index_by_api.get(api_instance_id, {})
        pol = pol_idx.get(violation_id)
        if not pol:
            # If your tenant uses a different id, you can log these and investigate.
            continue

        pol_name = pol.get("name", "UNKNOWN_POLICY")
        if not is_auth_policy_name(pol_name):
            continue

        api_name = get_api_instance_name(api_obj)

        findings.append(
            {
                "api_id": api_instance_id,
                "api_name": api_name,
                "policy_instance_id": violation_id,
                "policy_name": pol_name,
                "violations": v_count,
            }
        )

        per_api_totals[api_instance_id] = per_api_totals.get(api_instance_id, 0) + v_count
        # Policy totals aggregated across APIs by policy *name* (you can switch to instance id if desired)
        per_policy_totals[pol_name] = per_policy_totals.get(pol_name, 0) + v_count

    # Output
    if not findings:
        print(
            "\nNo auth-related policy access violations found (Client ID/OAuth/OIDC) in the selected window.\n"
            "If you expected results, check:\n"
            "  - API auto-discovery / API analytics is enabled for the managed APIs\n"
            "  - You are querying the correct org/env\n"
            "  - Metrics API dimensions match your tenant (inspect metric :describe)\n"
            "  - Your violated-policy id dimension matches API Manager policy instance ids\n"
        )
        sys.exit(0)

    print("\nViolations by API and violated policy instance (last window):")
    print("----------------------------------------------------------------")
    for f in sorted(findings, key=lambda x: (-x["violations"], x["api_name"], x["policy_name"])):
        print(
            f'{f["api_name"]} | {f["violations"]} violations | '
            f'Policy: {f["policy_name"]} | policyInstanceId={f["policy_instance_id"]} | apiId={f["api_id"]}'
        )

    print("\nTotal violations per API:")
    print("-------------------------")
    for api_id, total in sorted(per_api_totals.items(), key=lambda x: -x[1]):
        api_name = get_api_instance_name(api_by_id.get(api_id, {}))
        print(f"{api_name} | {total} violations | apiId={api_id}")

    print("\nTotal violations per policy (across all APIs):")
    print("---------------------------------------------")
    for pname, total in sorted(per_policy_totals.items(), key=lambda x: -x[1]):
        print(f"{pname} | {total} violations")

    print("\nDone.")


if __name__ == "__main__":
    main()
