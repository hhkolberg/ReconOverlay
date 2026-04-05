from __future__ import annotations

import re
import shutil
import threading
import time
from typing import Dict, Tuple

CACHE_TTL = 3600

SEVERITY_COLOR = {
    "CRITICAL": "#ff5555",
    "HIGH": "#ff9b42",
    "MEDIUM": "#ffd866",
    "LOW": "#8bd17c",
    "NONE": "#6e7681",
}

BG = "#0d1117"
BG2 = "#161b22"
BG3 = "#1f2630"
FG = "#d0d7de"
ACCENT = "#58a6ff"
GREEN = "#3fb950"
RED = "#f85149"
PURPLE = "#bc8cff"
ORANGE = "#d29922"
MUTED = "#8b949e"


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def clamp_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        n = int(value)
    except Exception:
        return default
    return max(minimum, min(maximum, n))


def clamp_float(value, default: float, minimum: float, maximum: float) -> float:
    try:
        n = float(value)
    except Exception:
        return default
    return max(minimum, min(maximum, n))


def norm_key(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


class HTTPCache:
    def __init__(self, ttl: int = CACHE_TTL):
        self.ttl = ttl
        self._data: Dict[Tuple[str, str], Tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, ns: str, key: str):
        with self._lock:
            item = self._data.get((ns, key))
            if not item:
                return None
            ts, val = item
            if time.time() - ts > self.ttl:
                self._data.pop((ns, key), None)
                return None
            return val

    def set(self, ns: str, key: str, val):
        with self._lock:
            self._data[(ns, key)] = (time.time(), val)
