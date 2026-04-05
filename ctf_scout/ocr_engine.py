from __future__ import annotations

import re
from typing import List, Optional

from .catalog import SoftwareCatalog
from .learning import abs_region_from_rel, LearnedPatterns
from .windowing import crop_absolute

VER_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9_\-\.]{2,})[\s/_\-vV:]+(\d+(?:\.\d+){1,4}(?:[a-z]\d+|[-._]?[a-z0-9]+)?)\b",
    re.IGNORECASE,
)

VERSION_ONLY_RE = re.compile(r"\d+(?:\.\d+){1,4}(?:[a-z]\d+|[-._]?[a-z0-9]+)?", re.IGNORECASE)


def preprocess_for_ocr(img, scale: float):
    from PIL import ImageFilter, ImageOps
    if scale > 1.0:
        img = img.resize((int(img.width * scale), int(img.height * scale)))
    gray = ImageOps.grayscale(img)
    gray = gray.filter(ImageFilter.SHARPEN)
    return gray


def ocr(img, psm: int = 6, scale: float = 1.8) -> str:
    import pytesseract
    processed = preprocess_for_ocr(img, scale)
    return pytesseract.image_to_string(processed, config=f"--psm {psm} --oem 1")


def normalize_product_name(name: str, catalog: SoftwareCatalog) -> Optional[str]:
    return catalog.all_names().get(re.sub(r"[^a-z0-9]+", "", (name or "").lower()))


def extract_keywords(text: str, catalog: SoftwareCatalog) -> List[str]:
    found = set()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for m in VER_RE.finditer(text):
        name = normalize_product_name(m.group(1), catalog)
        version = m.group(2).strip()
        if name and version:
            found.add(f"{name} {version}")
    # fallback: known product in line + version in same line
    for line in lines:
        line_l = line.lower()
        for alias_key, canonical in catalog.all_names().items():
            raw_alias = canonical if alias_key == re.sub(r'[^a-z0-9]+', '', canonical) else None
            if raw_alias and raw_alias in line_l:
                ver = VERSION_ONLY_RE.search(line)
                if ver:
                    found.add(f"{canonical} {ver.group(0)}")
    return sorted(found)


def extract_from_learned_regions(img, win: dict, learned: LearnedPatterns, catalog: SoftwareCatalog) -> List[str]:
    match = learned.match(win["title"])
    if not match:
        return []
    try:
        name_abs = abs_region_from_rel(match["name_region"], win)
        ver_abs = abs_region_from_rel(match["version_region"], win)
        name_text = re.sub(r"\s+", " ", ocr(crop_absolute(img, win, name_abs), psm=7, scale=2.2)).strip()
        ver_text = re.sub(r"\s+", " ", ocr(crop_absolute(img, win, ver_abs), psm=7, scale=2.2)).strip()
        raw_name = name_text.split()[0] if name_text.split() else name_text
        name = normalize_product_name(raw_name, catalog)
        ver_match = VERSION_ONLY_RE.search(ver_text)
        if name and ver_match:
            return [f"{name} {ver_match.group(0)}"]
    except Exception:
        pass
    return []
