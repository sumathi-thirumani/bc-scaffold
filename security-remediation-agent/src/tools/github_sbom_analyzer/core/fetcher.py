import json
import os

import httpx

from spdx_tools.spdx.parser.json.json_parser import remove_json_control_chars_hook
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.model.document import Document

GITHUB_API = "https://api.github.com"


async def fetch_github_sbom(owner: str, repo: str) -> Document:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/dependency-graph/sbom"

    async with httpx.AsyncClient(headers=_headers(), timeout=httpx.Timeout(30.0)) as client:
        resp = await client.get(url)
    _check(resp)

    sbom_json = resp.json().get("sbom")
    if not sbom_json:
        raise ValueError("Missing SBOM payload")

    sbom_json = json.loads(
        json.dumps(sbom_json),
        object_pairs_hook=remove_json_control_chars_hook,
    )

    return JsonLikeDictParser().parse(sbom_json)


def _headers():
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _check(resp: httpx.Response) -> None:
    if resp.status_code == 401:
        raise RuntimeError("Unauthorized (missing token)")
    if resp.status_code == 403:
        raise RuntimeError(resp.json().get("message", "Forbidden"))
    if resp.status_code == 404:
        raise RuntimeError("Repo not found or SBOM disabled")
    resp.raise_for_status()
    