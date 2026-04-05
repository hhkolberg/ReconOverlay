from __future__ import annotations

import subprocess
from typing import Dict, List, Optional, Tuple

from .utils import command_exists


def _parse_wmctrl() -> List[dict]:
    if not command_exists("wmctrl"):
        return []
    try:
        out = subprocess.check_output(["wmctrl", "-l", "-G"], text=True, timeout=4)
    except Exception:
        return []
    wins = []
    for line in out.splitlines():
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        try:
            wid = parts[0]
            x, y = int(parts[2]), int(parts[3])
            w, h = int(parts[4]), int(parts[5])
            title = parts[8].strip()
        except Exception:
            continue
        if not title or title in {"Desktop", "N/A"} or w < 80 or h < 60:
            continue
        wins.append({"id": wid, "title": title[:160], "x": x, "y": y, "w": w, "h": h})
    return wins


def _xwininfo_geometry(win_id: str) -> Optional[Tuple[int, int, int, int]]:
    if not command_exists("xwininfo"):
        return None
    try:
        out = subprocess.check_output(["xwininfo", "-id", win_id], text=True, timeout=4)
    except Exception:
        return None
    rx = ry = rw = rh = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Absolute upper-left X:"):
            rx = int(line.split(":", 1)[1].strip())
        elif line.startswith("Absolute upper-left Y:"):
            ry = int(line.split(":", 1)[1].strip())
        elif line.startswith("Width:"):
            rw = int(line.split(":", 1)[1].strip())
        elif line.startswith("Height:"):
            rh = int(line.split(":", 1)[1].strip())
    if None in (rx, ry, rw, rh):
        return None
    return rx, ry, rw, rh


def _parse_xdotool() -> List[dict]:
    if not command_exists("xdotool"):
        return []
    try:
        out = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--name", "."], text=True, timeout=5)
    except Exception:
        return []
    wins = []
    for raw_id in out.splitlines():
        raw_id = raw_id.strip()
        if not raw_id:
            continue
        try:
            name = subprocess.check_output(["xdotool", "getwindowname", raw_id], text=True, timeout=3).strip()
        except Exception:
            continue
        if not name:
            continue
        geom = _xwininfo_geometry(hex(int(raw_id)))
        if not geom:
            continue
        x, y, w, h = geom
        if w < 80 or h < 60:
            continue
        wins.append({"id": hex(int(raw_id)), "title": name[:160], "x": x, "y": y, "w": w, "h": h})
    return wins


def list_windows() -> List[dict]:
    merged: Dict[str, dict] = {}
    for win in _parse_wmctrl() + _parse_xdotool():
        merged[win["id"].lower()] = win
    out = list(merged.values())
    out.sort(key=lambda w: (w["title"].lower(), -(w["w"] * w["h"])))
    return out


def capture_window(win: dict):
    import mss
    from PIL import Image
    with mss.mss() as sct:
        raw = sct.grab({"left": win["x"], "top": win["y"], "width": win["w"], "height": win["h"]})
        return Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")


def crop_absolute(img, win: dict, region: Tuple[int, int, int, int]):
    x1, y1, x2, y2 = region
    left = max(0, x1 - win["x"])
    top = max(0, y1 - win["y"])
    right = min(win["w"], x2 - win["x"])
    bottom = min(win["h"], y2 - win["y"])
    if right <= left or bottom <= top:
        return img
    return img.crop((left, top, right, bottom))
