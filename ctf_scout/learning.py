from __future__ import annotations

import time
from typing import Optional, Tuple

from .config import LEARN_FILE, load_json, save_json


class LearnedPatterns:
    def __init__(self, path: str = LEARN_FILE):
        self.path = path
        self.data = load_json(path, {"patterns": []})
        if not isinstance(self.data, dict):
            self.data = {"patterns": []}
        self.data.setdefault("patterns", [])

    def save(self):
        save_json(self.path, self.data)

    def add_or_update(self, title_pattern: str, name_region: dict, version_region: dict):
        title_pattern = title_pattern.strip()
        for item in self.data["patterns"]:
            if item.get("title_pattern", "").lower() == title_pattern.lower():
                item["name_region"] = name_region
                item["version_region"] = version_region
                item["updated"] = int(time.time())
                self.save()
                return
        self.data["patterns"].append({
            "title_pattern": title_pattern,
            "name_region": name_region,
            "version_region": version_region,
            "updated": int(time.time()),
        })
        self.save()

    def match(self, title: str) -> Optional[dict]:
        title_l = title.lower()
        best = None
        best_len = -1
        for item in self.data["patterns"]:
            pat = (item.get("title_pattern") or "").lower()
            if pat and pat in title_l and len(pat) > best_len:
                best = item
                best_len = len(pat)
        return best


def rel_region(abs_region: Tuple[int, int, int, int], win: dict) -> dict:
    x1, y1, x2, y2 = abs_region
    return {
        "x1": max(0.0, min(1.0, (x1 - win["x"]) / max(1, win["w"]))),
        "y1": max(0.0, min(1.0, (y1 - win["y"]) / max(1, win["h"]))),
        "x2": max(0.0, min(1.0, (x2 - win["x"]) / max(1, win["w"]))),
        "y2": max(0.0, min(1.0, (y2 - win["y"]) / max(1, win["h"]))),
    }


def abs_region_from_rel(rel: dict, win: dict) -> Tuple[int, int, int, int]:
    x1 = win["x"] + int(rel["x1"] * win["w"])
    y1 = win["y"] + int(rel["y1"] * win["h"])
    x2 = win["x"] + int(rel["x2"] * win["w"])
    y2 = win["y"] + int(rel["y2"] * win["h"])
    return x1, y1, x2, y2
