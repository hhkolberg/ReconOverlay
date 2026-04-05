from __future__ import annotations

import queue
import tkinter as tk
from tkinter import ttk
from typing import Dict, List

from .catalog import SoftwareCatalog
from .config import CATALOG_FILE, load_config, save_config
from .learning import LearnedPatterns, rel_region
from .models import ActivityItem, CVEEntry
from .scanner import Scanner
from .utils import ACCENT, BG, BG2, BG3, FG, GREEN, MUTED, ORANGE, PURPLE, RED, SEVERITY_COLOR, clamp_float, clamp_int, command_exists
from .windowing import list_windows


class RegionSelector:
    def __init__(self, parent, on_done):
        self.on_done = on_done
        self.top = tk.Toplevel(parent)
        self.top.attributes("-fullscreen", True)
        self.top.attributes("-topmost", True)
        self.top.attributes("-alpha", 0.25)
        self.top.configure(bg="black")
        self.top.overrideredirect(True)
        self.canvas = tk.Canvas(self.top, cursor="cross", bg="black", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.start_x = self.start_y = 0
        self.rect = None
        self.canvas.bind("<ButtonPress-1>", self._down)
        self.canvas.bind("<B1-Motion>", self._drag)
        self.canvas.bind("<ButtonRelease-1>", self._up)
        self.top.bind("<Escape>", lambda _e: self._cancel())

    def _down(self, event):
        self.start_x, self.start_y = event.x_root, event.y_root
        if self.rect:
            self.canvas.delete(self.rect)
        self.rect = self.canvas.create_rectangle(event.x, event.y, event.x, event.y, outline="red", width=3)

    def _drag(self, event):
        if self.rect:
            self.canvas.coords(self.rect, self.start_x, self.start_y, event.x_root, event.y_root)

    def _up(self, event):
        x1, y1 = self.start_x, self.start_y
        x2, y2 = event.x_root, event.y_root
        self.top.destroy()
        self.on_done((min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2)))

    def _cancel(self):
        self.top.destroy()
        self.on_done(None)


class SettingsWindow:
    def __init__(self, parent, config: dict, on_save):
        self.win = tk.Toplevel(parent)
        self.win.title("Settings")
        self.win.geometry("640x430")
        self.win.configure(bg=BG)
        self.win.attributes("-topmost", True)
        self.config = dict(config)
        self.on_save = on_save
        self.vars: Dict[str, tk.StringVar] = {}
        self._build()

    def _build(self):
        fields = [
            ("github_token", "GitHub Token"),
            ("vulners_key", "Vulners API Key"),
            ("scan_interval", "Scan interval"),
            ("font_size", "Font size"),
            ("ocr_psm", "OCR PSM"),
            ("ocr_scale", "OCR scale"),
            ("keyword_ttl", "Keyword TTL"),
        ]
        for key, label in fields:
            row = tk.Frame(self.win, bg=BG)
            row.pack(fill="x", padx=16, pady=8)
            tk.Label(row, text=label, font=("TkFixedFont", 11, "bold"), bg=BG, fg=FG, width=18, anchor="w").pack(side="left")
            var = tk.StringVar(value=str(self.config.get(key, "")))
            self.vars[key] = var
            tk.Entry(row, textvariable=var, font=("TkFixedFont", 11), bg=BG3, fg=FG, insertbackground=FG, width=34, show="*" if "token" in key or "key" in key else "").pack(side="left", padx=8)
        tk.Button(self.win, text="Save", command=self._save, font=("TkFixedFont", 11, "bold"), bg=GREEN, fg=BG, bd=0, padx=14, pady=8).pack(pady=14)

    def _save(self):
        self.config["github_token"] = self.vars["github_token"].get().strip()
        self.config["vulners_key"] = self.vars["vulners_key"].get().strip()
        self.config["scan_interval"] = clamp_int(self.vars["scan_interval"].get(), 12, 1, 600)
        self.config["font_size"] = clamp_int(self.vars["font_size"].get(), 11, 9, 22)
        self.config["ocr_psm"] = clamp_int(self.vars["ocr_psm"].get(), 6, 3, 13)
        self.config["ocr_scale"] = clamp_float(self.vars["ocr_scale"].get(), 1.8, 1.0, 3.0)
        self.config["keyword_ttl"] = clamp_int(self.vars["keyword_ttl"].get(), 1800, 60, 86400)
        save_config(self.config)
        self.on_save(self.config)
        self.win.destroy()


class AddSoftwareDialog:
    def __init__(self, parent, on_save):
        self.on_save = on_save
        self.win = tk.Toplevel(parent)
        self.win.title("Add Software")
        self.win.geometry("620x360")
        self.win.configure(bg=BG)
        self.win.attributes("-topmost", True)
        self.vars = {
            "name": tk.StringVar(),
            "version": tk.StringVar(),
            "aliases": tk.StringVar(),
            "category": tk.StringVar(value="manual"),
        }
        self._build()

    def _build(self):
        fields = [
            ("name", "Software name"),
            ("version", "Version (optional)"),
            ("aliases", "Aliases comma-separated"),
            ("category", "Category"),
        ]
        for key, label in fields:
            row = tk.Frame(self.win, bg=BG)
            row.pack(fill="x", padx=16, pady=8)
            tk.Label(row, text=label, font=("TkFixedFont", 11, "bold"), bg=BG, fg=FG, width=22, anchor="w").pack(side="left")
            tk.Entry(row, textvariable=self.vars[key], font=("TkFixedFont", 11), bg=BG3, fg=FG, insertbackground=FG, width=38).pack(side="left", padx=8)
        tk.Label(self.win, text="Vulnerability note (optional)", font=("TkFixedFont", 11, "bold"), bg=BG, fg=FG, anchor="w").pack(fill="x", padx=16, pady=(10, 2))
        self.vuln_text = tk.Text(self.win, height=4, bg=BG3, fg=FG, font=("TkFixedFont", 11), bd=0, insertbackground=FG)
        self.vuln_text.pack(fill="x", padx=16)
        tk.Label(self.win, text="General notes (optional)", font=("TkFixedFont", 11, "bold"), bg=BG, fg=FG, anchor="w").pack(fill="x", padx=16, pady=(10, 2))
        self.notes_text = tk.Text(self.win, height=4, bg=BG3, fg=FG, font=("TkFixedFont", 11), bd=0, insertbackground=FG)
        self.notes_text.pack(fill="x", padx=16)
        btns = tk.Frame(self.win, bg=BG)
        btns.pack(fill="x", padx=16, pady=14)
        tk.Button(btns, text="Save + Search", command=self._save, font=("TkFixedFont", 11, "bold"), bg=GREEN, fg=BG, bd=0, padx=14, pady=8).pack(side="left")
        tk.Button(btns, text="Cancel", command=self.win.destroy, font=("TkFixedFont", 11), bg=BG3, fg=FG, bd=0, padx=14, pady=8).pack(side="left", padx=8)

    def _save(self):
        name = self.vars["name"].get().strip()
        if not name:
            return
        payload = {
            "name": name,
            "version": self.vars["version"].get().strip(),
            "aliases": [a.strip() for a in self.vars["aliases"].get().split(",") if a.strip()],
            "category": self.vars["category"].get().strip() or "manual",
            "vulnerability_note": self.vuln_text.get("1.0", "end").strip(),
            "notes": self.notes_text.get("1.0", "end").strip(),
        }
        self.on_save(payload)
        self.win.destroy()


class CTFScoutApp:
    def __init__(self):
        self.config = load_config()
        self.catalog = SoftwareCatalog(CATALOG_FILE)
        self.learned = LearnedPatterns()
        self.root = tk.Tk()
        self.q: queue.Queue = queue.Queue()
        self.scanner = Scanner(self.q, self.config, self.learned, self.catalog)
        self.windows: List[dict] = []
        self.pending_name_region = None
        self.pending_version_region = None
        self.activity_state: Dict[str, ActivityItem] = {}
        self.result_state: Dict[str, List[CVEEntry]] = {}
        self.status_var = tk.StringVar(value="● IDLE")
        self.catalog_label_var = tk.StringVar(value=f"catalog: {self.catalog.product_count()} products")
        self.learn_var = tk.StringVar(value=f"No learned selection yet | External DB: {CATALOG_FILE}")
        self._build()
        self._refresh_windows()
        self._poll()

    def _font(self, delta=0, bold=False):
        size = clamp_int(self.config.get("font_size", 11), 11, 9, 22) + delta
        return ("TkFixedFont", max(9, size), "bold" if bold else "normal")

    def _btn(self, parent, text, cmd, bg=BG3, fg=FG, bold=False):
        return tk.Button(parent, text=text, command=cmd, font=self._font(0, bold), bg=bg, fg=fg, bd=0, padx=10, pady=7, cursor="hand2")

    def _frame(self, parent, title):
        f = tk.LabelFrame(parent, text=f"  {title}  ", font=self._font(), labelanchor="nw", bg=BG2, fg="#7d8590")
        f.pack(fill="both", expand=False if title in {"Monitor Windows", "Learning", "Live Activity"} else True, padx=8, pady=6)
        return f

    def _build(self):
        r = self.root
        r.title("CTF-Scout v4 Modular")
        r.geometry("980x1100+50+30")
        r.configure(bg=BG)
        r.attributes("-topmost", True)
        r.attributes("-alpha", 0.97)

        ttk.Style().theme_use("default")
        style = ttk.Style()
        style.configure("Treeview", background=BG3, fieldbackground=BG3, foreground=FG)
        style.configure("Treeview.Heading", background=BG2, foreground=FG)

        hdr = tk.Frame(r, bg="#10243f", pady=8)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⚡ CTF-Scout v4 Modular", font=self._font(4, True), bg="#10243f", fg=ACCENT).pack(side="left", padx=14)
        tk.Label(hdr, textvariable=self.status_var, font=self._font(1), bg="#10243f", fg="#b7c6d6").pack(side="right", padx=10)
        tk.Button(hdr, text="⚙ Settings", command=lambda: SettingsWindow(r, self.config, self._on_cfg), font=self._font(1), bg="#10243f", fg=FG, bd=0).pack(side="right", padx=12)

        tools = tk.Frame(r, bg=BG, pady=6)
        tools.pack(fill="x", padx=10)
        discovery = ", ".join([x for x in ["wmctrl" if command_exists("wmctrl") else None, "xdotool" if command_exists("xdotool") else None, "xwininfo" if command_exists("xwininfo") else None] if x]) or "none"
        tk.Label(tools, text=f"window discovery: {discovery}", font=self._font(), bg=BG, fg=MUTED).pack(side="left")
        tk.Label(tools, textvariable=self.catalog_label_var, font=self._font(), bg=BG, fg=ACCENT).pack(side="right")

        wf = self._frame(r, "Monitor Windows")
        wrap = tk.Frame(wf, bg=BG2)
        wrap.pack(fill="x", padx=6, pady=6)
        self.win_lb = tk.Listbox(wrap, selectmode="multiple", height=7, bg=BG3, fg=FG, font=self._font(1), selectbackground="#1f6feb", selectforeground="white", bd=0, activestyle="none")
        sb = tk.Scrollbar(wrap, orient="vertical", command=self.win_lb.yview)
        self.win_lb.config(yscrollcommand=sb.set)
        self.win_lb.pack(side="left", fill="x", expand=True)
        sb.pack(side="right", fill="y")
        btns = tk.Frame(wf, bg=BG2)
        btns.pack(fill="x", padx=6, pady=(0, 8))
        self._btn(btns, "↻ Refresh", self._refresh_windows).pack(side="left", padx=4)
        self._btn(btns, "✕ Clear", self._clear).pack(side="left", padx=4)
        self._btn(btns, "+ Add Software", self._open_add_software, bg="#27415a").pack(side="left", padx=4)
        self.scan_btn = self._btn(btns, "▶ Start Scanning", self._toggle, bg=RED, fg="white", bold=True)
        self.scan_btn.pack(side="right", padx=4)

        af = self._frame(r, "Live Activity")
        self.activity_lb = tk.Listbox(af, height=8, bg=BG3, fg=FG, font=self._font(), bd=0)
        self.activity_lb.pack(fill="both", expand=True, padx=6, pady=6)

        lf = self._frame(r, "Learning")
        lbtns = tk.Frame(lf, bg=BG2)
        lbtns.pack(fill="x", padx=6, pady=8)
        self._btn(lbtns, "Learn Name Region", self._learn_name, bg="#27415a").pack(side="left", padx=4)
        self._btn(lbtns, "Learn Version Region", self._learn_version, bg="#27415a").pack(side="left", padx=4)
        self._btn(lbtns, "Save Learned Pattern", self._save_learned_pattern, bg=GREEN, fg=BG, bold=True).pack(side="left", padx=4)
        tk.Label(lf, textvariable=self.learn_var, font=self._font(), bg=BG2, fg=MUTED, justify="left", anchor="w", wraplength=900).pack(fill="x", padx=8, pady=(0, 8))

        rf = self._frame(r, "CVE + Exploit Results")
        self.result_tree = ttk.Treeview(rf, columns=("risk", "epss", "cvss", "published"), show="tree headings")
        self.result_tree.heading("#0", text="Detected / CVE / Exploit")
        self.result_tree.heading("risk", text="Risk")
        self.result_tree.heading("epss", text="EPSS")
        self.result_tree.heading("cvss", text="CVSS")
        self.result_tree.heading("published", text="Published")
        self.result_tree.column("#0", width=610)
        self.result_tree.column("risk", width=80, anchor="center")
        self.result_tree.column("epss", width=90, anchor="center")
        self.result_tree.column("cvss", width=70, anchor="center")
        self.result_tree.column("published", width=100, anchor="center")
        rsb = ttk.Scrollbar(rf, orient="vertical", command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=rsb.set)
        self.result_tree.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        rsb.pack(side="right", fill="y")

    def _refresh_windows(self):
        self.windows = list_windows()
        self.win_lb.delete(0, "end")
        for w in self.windows:
            self.win_lb.insert("end", f"{w['title']}  [{w['w']}x{w['h']}]")
        self.status_var.set(f"● {len(self.windows)} windows found")

    def _selected_window(self):
        sel = self.win_lb.curselection()
        if not sel:
            self.status_var.set("⚠ Select one window first")
            return None
        return self.windows[sel[0]]

    def _open_add_software(self):
        AddSoftwareDialog(self.root, self._save_software_entry)

    def _save_software_entry(self, payload: dict):
        try:
            canonical = self.catalog.add_product(
                name=payload.get("name", ""),
                version=payload.get("version", ""),
                vulnerability_note=payload.get("vulnerability_note", ""),
                aliases=payload.get("aliases", []),
                notes=payload.get("notes", ""),
                category=payload.get("category", "manual"),
            )
        except ValueError as e:
            self.status_var.set(f"⚠ {e}")
            return
        version = (payload.get("version") or "").strip()
        keyword = f"{canonical} {version}".strip()
        self.catalog_label_var.set(f"catalog: {self.catalog.product_count()} products")
        self.learn_var.set(f"Saved to external DB: {CATALOG_FILE} | Last added: {keyword}")
        self.status_var.set(f"● Added software: {keyword} | searching now")
        self.scanner.queue_manual_keyword(keyword)

    def _learn_name(self):
        win = self._selected_window()
        if not win:
            return
        self.status_var.set("● Drag over the product name region")
        RegionSelector(self.root, self._name_selected)

    def _learn_version(self):
        win = self._selected_window()
        if not win:
            return
        self.status_var.set("● Drag over the version region")
        RegionSelector(self.root, self._version_selected)

    def _name_selected(self, region):
        if not region:
            self.status_var.set("● Name selection cancelled")
            return
        self.pending_name_region = region
        self.learn_var.set(f"Name region captured: {region} | Version region: {self.pending_version_region}")
        self.status_var.set("● Name region captured")

    def _version_selected(self, region):
        if not region:
            self.status_var.set("● Version selection cancelled")
            return
        self.pending_version_region = region
        self.learn_var.set(f"Name region: {self.pending_name_region} | Version region captured: {region}")
        self.status_var.set("● Version region captured")

    def _save_learned_pattern(self):
        win = self._selected_window()
        if not win:
            return
        if not self.pending_name_region or not self.pending_version_region:
            self.status_var.set("⚠ Capture both name and version regions first")
            return
        title_pattern = win["title"].split(" - ")[0].strip()[:80]
        nr = rel_region(self.pending_name_region, win)
        vr = rel_region(self.pending_version_region, win)
        self.learned.add_or_update(title_pattern, nr, vr)
        self.status_var.set(f"● Learned pattern saved for: {title_pattern}")
        self.learn_var.set(f"Saved learned pattern for '{title_pattern}'")

    def _toggle(self):
        if self.scanner.running:
            self.scanner.stop()
            self.scan_btn.config(text="▶ Start Scanning", bg=RED)
            self.status_var.set("● IDLE")
            return
        sel = self.win_lb.curselection()
        if not sel:
            self.status_var.set("⚠ Select at least one window first")
            return
        self.scanner.config = self.config
        self.scanner.start([self.windows[i] for i in sel])
        self.scan_btn.config(text="■ Stop", bg="#424a53")
        self.status_var.set("● SCANNING")

    def _clear(self):
        self.scanner.clear_seen()
        self.activity_state.clear()
        self.result_state.clear()
        self.activity_lb.delete(0, "end")
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)

    def _on_cfg(self, cfg: dict):
        self.config = cfg
        self.scanner.config = cfg

    def _update_activity(self, item: ActivityItem):
        self.activity_state[item.keyword] = item
        ordered = sorted(self.activity_state.values(), key=lambda x: x.timestamp, reverse=True)
        self.activity_lb.delete(0, "end")
        for act in ordered[:50]:
            self.activity_lb.insert("end", f"[{act.state}] {act.keyword}  {('- ' + act.detail) if act.detail else ''}")

    def _render_results(self):
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        for keyword, cves in sorted(self.result_state.items(), key=lambda kv: max((c.risk_sort for c in kv[1]), default=(0, 0, 0, "")), reverse=True):
            top_epss = max((c.epss or 0.0 for c in cves), default=0.0)
            top_cvss = max((c.cvss_score for c in cves), default=0.0)
            root = self.result_tree.insert("", "end", text=f"{keyword}  [{len(cves)} CVEs]", values=("TOP", f"{top_epss:.3f}", f"{top_cvss:.1f}", ""), open=False)
            for cve in sorted(cves, key=lambda c: c.risk_sort, reverse=True):
                risk = "HIGH" if cve.has_exact_exploits or (cve.epss or 0.0) >= 0.5 else "MED"
                cve_node = self.result_tree.insert(root, "end", text=f"{cve.cve_id} — {cve.description[:110]}", values=(risk, f"{(cve.epss or 0.0):.3f}", f"{cve.cvss_score:.1f}", cve.published), open=False)
                self.result_tree.insert(cve_node, "end", text=f"Keyword: {cve.keyword}")
                if cve.epss is not None:
                    self.result_tree.insert(cve_node, "end", text=f"EPSS: {cve.epss:.3f} | Percentile: {(cve.epss_percentile or 0.0):.3f}")
                for ref in cve.exact_refs:
                    self.result_tree.insert(cve_node, "end", text=f"[EXACT:{ref.source}] {ref.title} -> {ref.url}")
                for ref in cve.related_refs[:3]:
                    self.result_tree.insert(cve_node, "end", text=f"[RELATED:{ref.source}] {ref.title} -> {ref.url}")

    def _poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "status":
                    self.status_var.set(f"● {data}")
                elif kind == "error":
                    self.status_var.set(f"⚠ {data}")
                elif kind == "activity":
                    self._update_activity(data)
                elif kind == "result_group":
                    self.result_state[data["keyword"]] = data["cves"]
                    self._render_results()
        except queue.Empty:
            pass
        self.root.after(350, self._poll)

    def run(self):
        self.root.mainloop()
