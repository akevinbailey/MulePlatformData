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

List Anypoint Exchange assets whose *published* documentation is too short.

Goal:
- Check each Anypoint Exchange asset
- Retrieve its published portal documentation pages
- Sum the total markdown content length across all pages
- Report assets whose documentation length is < 80 characters

Notes:
- Assets are listed with: GET /exchange/api/v2/assets?organizationId=...&offset=...&limit=...
- Published portal pages are listed with:
  GET /exchange/api/v2/assets/{groupId}/{assetId}/{version}/portal/pages
- Page content is retrieved via:
  GET /exchange/api/v2/assets/{groupId}/{assetId}/{version}/portal/pages/{pageId}
  Prefer Accept: text/markdown, but fall back to JSON if needed.
"""

import argparse
import sys
from typing import List, Optional

import requests
from requests import JSONDecodeError

# ----------------------------------------------------
# HARD-CODED CONFIGURATION
# ----------------------------------------------------

ANYPOINT_BASE_URL = "https://anypoint.mulesoft.com"

# Optional: constrain which asset types you want to evaluate
# (You can also remove this filter entirely and check all asset types.)
EXCHANGE_ASSET_TYPES = ["rest-api", "http-api", "soap-api"]

# Pagination
EXCHANGE_PAGE_SIZE = 100

# Documentation minimum (characters)
MIN_DOC_CHARS = 80


# ----------------------------------------------------
# Helper Functions
# ----------------------------------------------------

def normalize_name(name: Optional[str]) -> Optional[str]:
    """Normalize names for display/comparison."""
    if not name:
        return None
    return name.strip()


def safe_dict_get(obj: Optional[dict], *keys, default=None):
    """Safely get nested dict values without throwing."""
    cur = obj
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


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
# Exchange: list assets
# ----------------------------------------------------

def fetch_exchange_assets(token: str, org_id: str) -> List[dict]:
    """
    Fetch Exchange assets (paged).

    Uses:
      GET /exchange/api/v2/assets?organizationId=...&offset=...&limit=...
    """
    headers = {"Authorization": f"Bearer {token}"}
    assets: List[dict] = []

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
        if isinstance(data, list):
            items = data
        else:
            items = data.get("assets") or data.get("items") or []

        if not items:
            break

        assets.extend(items)

        if len(items) < EXCHANGE_PAGE_SIZE:
            break

        offset += EXCHANGE_PAGE_SIZE

    return assets


# ----------------------------------------------------
# Exchange: portal documentation
# ----------------------------------------------------

def list_published_portal_pages(token: str, group_id: str, asset_id: str, version: str) -> List[dict]:
    """
    List published portal pages for an asset version.

    Uses:
      GET /exchange/api/v2/assets/{groupId}/{assetId}/{version}/portal/pages
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    url = (
        f"{ANYPOINT_BASE_URL}/exchange/api/v2/assets/"
        f"{group_id}/{asset_id}/{version}/portal/pages"
    )
    resp = requests.get(url, headers=headers)

    if resp.status_code in (404, 403):
        # 404: no portal published / no docs
        # 403: insufficient rights to view portal/pages for this asset
        return []

    if resp.status_code != 200:
        print(
            f"WARNING listing portal pages failed for {group_id}/{asset_id}/{version}: "
            f"{resp.status_code} {resp.text}",
            file=sys.stderr,
        )
        return []

    data = resp.json()
    if isinstance(data, list):
        return data
    return data.get("pages") or data.get("items") or []


def get_portal_page_markdown(token: str, group_id: str, asset_id: str, version: str, page_id: str) -> str:
    """
    Retrieve a portal page content.

    Preferred:
      GET .../portal/pages/{pageId} with Accept: text/markdown

    Fallback:
      If server returns JSON, try to extract likely content fields.
    """
    url = (
        f"{ANYPOINT_BASE_URL}/exchange/api/v2/assets/"
        f"{group_id}/{asset_id}/{version}/portal/pages/{page_id}"
    )

    # 1) Prefer Markdown
    headers_md = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/markdown",
    }
    resp = requests.get(url, headers=headers_md)
    if resp.status_code == 200:
        # Some tenants still respond with JSON even if Accept Markdown;
        # detect by content-type.
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                j = resp.json()
                # Common-ish places documentation content might appear
                return (
                    j.get("content")
                    or j.get("markdown")
                    or safe_dict_get(j, "page", "content", default="")
                    or safe_dict_get(j, "page", "markdown", default="")
                    or ""
                )
            except JSONDecodeError:
                return ""
        return resp.text or ""

    if resp.status_code in (404, 403):
        return ""

    # 2) Fallback: JSON Accept (some environments require it)
    headers_json = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    resp2 = requests.get(url, headers=headers_json)
    if resp2.status_code != 200:
        return ""

    try:
        j = resp2.json()
        return (
            j.get("content")
            or j.get("markdown")
            or safe_dict_get(j, "page", "content", default="")
            or safe_dict_get(j, "page", "markdown", default="")
            or ""
        )
    except JSONDecodeError:
        return ""


def compute_asset_doc_length(token: str, group_id: str, asset_id: str, version: str) -> int:
    """
    Sum the character length of all published portal pages for an asset version.
    """
    pages = list_published_portal_pages(token, group_id, asset_id, version)
    if not pages:
        return 0

    total = 0
    for p in pages:
        # Most commonly "id"; be defensive.
        page_id = p.get("id") or p.get("pageId") or p.get("pagePath")
        if not page_id:
            continue
        md = get_portal_page_markdown(token, group_id, asset_id, version, page_id)
        total += len(md or "")

    return total


# ----------------------------------------------------
# Main
# ----------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="List Exchange assets with published documentation shorter than 80 characters."
    )
    parser.add_argument("--client_id", required=True, help="Connected App client_id")
    parser.add_argument("--client_secret", required=True, help="Connected App client_secret")
    parser.add_argument("--org_id", required=True, help="Anypoint Organization ID")

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

    print("Fetching Exchange assets...")
    assets = fetch_exchange_assets(token, args.org_id)
    print(f"  Found {len(assets)} assets (filtered by types: {EXCHANGE_ASSET_TYPES}).")

    short_docs: List[dict] = []

    print(f"Checking published portal documentation (< {MIN_DOC_CHARS} chars)...")
    for a in assets:
        group_id = a.get("groupId") or a.get("group_id")
        asset_id = a.get("assetId") or a.get("asset_id")
        version = a.get("version") or a.get("assetVersion")
        display_name = normalize_name(a.get("name") or asset_id)

        if not (group_id and asset_id and version):
            continue

        doc_len = compute_asset_doc_length(token, group_id, asset_id, version)

        if doc_len < MIN_DOC_CHARS:
            short_docs.append({
                "name": display_name,
                "groupId": group_id,
                "assetId": asset_id,
                "version": version,
                "doc_len": doc_len,
            })

    if not short_docs:
        print(f"\nNo assets found with published documentation under {MIN_DOC_CHARS} characters.")
        sys.exit(0)

    short_docs.sort(key=lambda x: x["doc_len"])

    print(f"\nAssets with published documentation under {MIN_DOC_CHARS} characters:")
    print("-----------------------------------------------------------------------")
    for s in short_docs:
        print(
            f"{s['name']} "
            f"(groupId={s['groupId']}, assetId={s['assetId']}, version={s['version']}) "
            f"-> {s['doc_len']} chars"
        )


if __name__ == "__main__":
    main()
