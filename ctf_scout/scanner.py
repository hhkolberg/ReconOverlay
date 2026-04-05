from __future__ import annotations

import threading
import time
from typing import Dict, List

from .catalog import SoftwareCatalog
from .learning import LearnedPatterns
from .models import ActivityItem, CVEEntry
from .ocr_engine import extract_from_learned_regions, extract_keywords, ocr
from .sources import (
    fetch_epss,
    fetch_nvd,
    search_exploitdb,
    search_github_advisory_by_cve,
    search_github_repos,
    search_vulners,
    unique_refs,
)
from .utils import clamp_float, clamp_int
from .windowing import capture_window


class Scanner:
    def __init__(self, q, config: dict, learned: LearnedPatterns, catalog: SoftwareCatalog):
        self.q = q
        self.config = config
        self.learned = learned
        self.catalog = catalog
        self.windows: List[dict] = []
        self.running = False
        self._seen: Dict[str, float] = {}
        self._seen_lock = threading.Lock()
        self._active = set()
        self._active_lock = threading.Lock()

    def start(self, windows: List[dict]):
        if self.running:
            return
        self.windows = windows
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False

    def clear_seen(self):
        with self._seen_lock:
            self._seen.clear()

    def queue_manual_keyword(self, keyword: str):
        keyword = keyword.strip()
        if not keyword:
            return
        with self._active_lock:
            if keyword in self._active:
                return
            self._active.add(keyword)
        self._activity(keyword, "SEARCHING", "manual search")
        threading.Thread(target=self._process_keyword, args=(keyword,), daemon=True).start()

    def _activity(self, keyword: str, state: str, detail: str = ""):
        self.q.put(("activity", ActivityItem(keyword=keyword, state=state, detail=detail, timestamp=time.time())))

    def _fresh_keyword(self, kw: str) -> bool:
        ttl = clamp_int(self.config.get("keyword_ttl", 1800), 1800, 60, 86400)
        now = time.time()
        with self._seen_lock:
            last = self._seen.get(kw)
            if last and now - last < ttl:
                return False
            self._seen[kw] = now
            return True

    def _loop(self):
        while self.running:
            psm = clamp_int(self.config.get("ocr_psm", 6), 6, 3, 13)
            scale = clamp_float(self.config.get("ocr_scale", 1.8), 1.8, 1.0, 3.0)
            for win in list(self.windows):
                if not self.running:
                    break
                try:
                    self.q.put(("status", f"Scanning: {win['title'][:55]}"))
                    img = capture_window(win)
                    keywords = extract_from_learned_regions(img, win, self.learned, self.catalog)
                    if not keywords:
                        text = ocr(img, psm=psm, scale=scale)
                        keywords = extract_keywords(text, self.catalog)
                    for kw in keywords:
                        self._activity(kw, "DETECTED", win["title"][:60])
                        if not self._fresh_keyword(kw):
                            self._activity(kw, "SKIPPED", "seen recently")
                            continue
                        with self._active_lock:
                            if kw in self._active:
                                self._activity(kw, "SKIPPED", "already searching")
                                continue
                            self._active.add(kw)
                        self._activity(kw, "SEARCHING", "queued from OCR")
                        threading.Thread(target=self._process_keyword, args=(kw,), daemon=True).start()
                except Exception as e:
                    self.q.put(("error", f"scan error: {str(e)[:80]}"))

            interval = clamp_int(self.config.get("scan_interval", 12), 12, 1, 600)
            for _ in range(interval * 2):
                if not self.running:
                    break
                time.sleep(0.5)

    def _process_keyword(self, kw: str):
        token = str(self.config.get("github_token", "")).strip()
        vulners_key = str(self.config.get("vulners_key", "")).strip()
        try:
            cves = fetch_nvd(kw)
            if not cves:
                self._activity(kw, "DONE", "no CVEs found")
                self.q.put(("status", f"No CVEs found for: {kw}"))
                return

            epss_map = fetch_epss([c.cve_id for c in cves])
            general_refs = unique_refs(search_exploitdb(kw, False) + search_vulners(kw, vulners_key, False))

            for cve in cves:
                epss = epss_map.get(cve.cve_id, {})
                if epss:
                    cve.epss = epss.get("epss")
                    cve.epss_percentile = epss.get("percentile")
                exact = []
                exact.extend(search_github_repos(cve.cve_id, token))
                exact.extend(search_github_advisory_by_cve(cve.cve_id, token))
                exact.extend(search_exploitdb(cve.cve_id, True))
                exact.extend(search_vulners(cve.cve_id, vulners_key, True))
                cve.exact_refs = unique_refs(exact)
                cve.related_refs = general_refs[:]

            cves.sort(key=lambda c: c.risk_sort, reverse=True)
            self.q.put(("result_group", {"keyword": kw, "cves": cves}))
            self._activity(kw, "DONE", f"{len(cves)} CVEs")
        finally:
            with self._active_lock:
                self._active.discard(kw)
