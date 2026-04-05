from __future__ import annotations

import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = os.path.expanduser("~/.ctfscout.json")
LEARN_FILE = os.path.expanduser("~/.ctfscout_learned.json")
CATALOG_FILE = str(BASE_DIR / "software_catalog.json")

DEFAULT_CONFIG = {
    "github_token": "",
    "vulners_key": "",
    "scan_interval": 12,
    "font_size": 11,
    "ocr_psm": 6,
    "ocr_scale": 1.8,
    "keyword_ttl": 1800,
}


def load_json(path: str, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default
    return default


def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(load_json(CONFIG_FILE, {}))
    return cfg


def save_config(cfg: dict):
    save_json(CONFIG_FILE, cfg)
