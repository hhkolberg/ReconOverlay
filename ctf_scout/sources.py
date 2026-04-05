from __future__ import annotations

import json
import os
import subprocess
from typing import Dict, List

import requests

from .models import CVEEntry, ExploitRef
from .utils import HTTPCache, command_exists, score_to_severity

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com"
VULNERS_API = "https://vulners.com/api/v3/search/lucene/"
EPSS_API = "https://api.first.org/data/v1/epss"
MAX_CVE = 6
MAX_GH_REPOS = 5
HTTP_TIMEOUT = 10

HTTP = requests.Session()
HTTP.headers.update({"User-Agent": "CTF-Scout/4.0"})
CACHE = HTTPCache()


def unique_refs(refs: List[ExploitRef]) -> List[ExploitRef]:
    seen = set()
    out = []
    for ref in refs:
        key = (ref.source, ref.url, ref.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(ref)
    return out


def fetch_nvd(keyword: str) -> List[CVEEntry]:
    cached = CACHE.get("nvd", keyword)
    if cached is not None:
        return cached
    entries: List[CVEEntry] = []
    try:
        r = HTTP.get(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": MAX_CVE}, timeout=HTTP_TIMEOUT)
        if r.status_code != 200:
            return []
        for item in r.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")[:180]
            pub = cve.get("published", "")[:10]
            score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ms = cve.get("metrics", {}).get(key, [])
                if ms:
                    score = ms[0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            if cid:
                entries.append(CVEEntry(cid, desc, score, score_to_severity(score), keyword, pub))
    except Exception:
        return []
    entries.sort(key=lambda e: e.cvss_score, reverse=True)
    CACHE.set("nvd", keyword, entries)
    return entries


def fetch_epss(cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
    if not cve_ids:
        return {}
    key = ",".join(sorted(cve_ids))
    cached = CACHE.get("epss", key)
    if cached is not None:
        return cached
    try:
        r = HTTP.get(EPSS_API, params={"cve": ",".join(cve_ids)}, timeout=HTTP_TIMEOUT)
        if r.status_code != 200:
            return {}
        result = {}
        for item in r.json().get("data", []):
            try:
                result[item["cve"]] = {
                    "epss": float(item.get("epss", 0.0)),
                    "percentile": float(item.get("percentile", 0.0)),
                }
            except Exception:
                continue
        CACHE.set("epss", key, result)
        return result
    except Exception:
        return {}


def _gh_headers(token: str) -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def search_github_repos(cve_id: str, token: str) -> List[ExploitRef]:
    cached = CACHE.get("ghrepo", cve_id)
    if cached is not None:
        return cached
    refs: List[ExploitRef] = []
    try:
        r = HTTP.get(
            f"{GITHUB_API}/search/repositories",
            params={"q": f'"{cve_id}" exploit OR poc', "sort": "stars", "order": "desc", "per_page": MAX_GH_REPOS},
            headers=_gh_headers(token),
            timeout=8,
        )
        if r.status_code == 200:
            for repo in r.json().get("items", []):
                refs.append(ExploitRef("github", repo.get("full_name", ""), repo.get("html_url", ""), repo.get("stargazers_count", 0), (repo.get("description") or "")[:100], True))
    except Exception:
        pass
    refs = unique_refs(refs)
    CACHE.set("ghrepo", cve_id, refs)
    return refs


def search_github_advisory_by_cve(cve_id: str, token: str) -> List[ExploitRef]:
    cached = CACHE.get("ghadv", cve_id)
    if cached is not None:
        return cached
    refs: List[ExploitRef] = []
    try:
        r = HTTP.get(f"{GITHUB_API}/advisories", params={"cve_id": cve_id, "per_page": 3}, headers=_gh_headers(token), timeout=8)
        if r.status_code == 200:
            for adv in r.json():
                refs.append(ExploitRef("github-advisory", f"{adv.get('ghsa_id', '')} — {(adv.get('summary') or '')[:70]}", adv.get("html_url", ""), 0, (adv.get("description") or "")[:100], True))
    except Exception:
        pass
    refs = unique_refs(refs)
    CACHE.set("ghadv", cve_id, refs)
    return refs


def search_vulners(query: str, api_key: str, exact: bool) -> List[ExploitRef]:
    if not api_key:
        return []
    ck = f"{query}|{int(exact)}"
    cached = CACHE.get("vulners", ck)
    if cached is not None:
        return cached
    refs: List[ExploitRef] = []
    try:
        r = HTTP.post(VULNERS_API, json={"query": query, "apiKey": api_key, "size": 5}, timeout=10)
        if r.status_code == 200:
            for item in r.json().get("data", {}).get("search", []):
                src = item.get("_source", {})
                refs.append(ExploitRef(f"vulners/{src.get('type', '?')}", (src.get("title") or "")[:100], f"https://vulners.com/{src.get('type', '')}/{src.get('id', '')}", 0, (src.get("description") or "")[:100], exact))
    except Exception:
        pass
    refs = unique_refs(refs)
    CACHE.set("vulners", ck, refs)
    return refs


def search_exploitdb(keyword: str, exact: bool) -> List[ExploitRef]:
    if not command_exists("searchsploit"):
        return []
    ck = f"{keyword}|{int(exact)}"
    cached = CACHE.get("searchsploit", ck)
    if cached is not None:
        return cached
    refs: List[ExploitRef] = []
    try:
        out = subprocess.check_output(["searchsploit", "--json", keyword], text=True, timeout=8, stderr=subprocess.DEVNULL)
        for item in json.loads(out).get("RESULTS_EXPLOIT", [])[:5]:
            path = item.get("Path", "")
            full = os.path.join("/usr/share/exploitdb", path) if path else ""
            refs.append(ExploitRef("searchsploit", (item.get("Title") or "")[:100], full if os.path.exists(full) else path, 0, f"EDB:{item.get('EDB-ID', '?')} · {item.get('Type', '?')}", exact))
    except Exception:
        pass
    refs = unique_refs(refs)
    CACHE.set("searchsploit", ck, refs)
    return refs
