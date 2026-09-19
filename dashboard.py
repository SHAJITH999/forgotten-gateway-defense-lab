from __future__ import annotations

import threading
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, ttk

from history import HistoryStore
from models import ScanHistory, ScanResult, Service
from parser import NmapParseError, parse_nmap_xml
from scanner import ScanError, nmap_command, run_nmap, validate_target
from ui.level2_dashboard import Level2Dashboard


class Dashboard(tk.Tk):
    BG = "#0b1220"
    PANEL = "#111b2e"
    PANEL_ALT = "#16243b"
    TEXT = "#e6edf7"
    MUTED = "#8da2bf"
    ACCENT = "#31d0aa"
    BLUE = "#5da9ff"
    RED = "#ff6b7a"

    def __init__(self, history_path: str):
        super().__init__()
        self.title("Network Exposure Assessment")
        self.geometry("1180x760")
        self.minsize(920, 620)
        self.configure(bg=self.BG)
        self.history_store = HistoryStore(history_path)
        self.history_entries = self.history_store.load()
        self.current_result: ScanResult | None = None
        self.worker: threading.Thread | None = None
        self._build_style()
        self._build_ui()
        self._refresh_history()
        self._update_command()

    def _build_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TFrame", background=self.BG)
        style.configure("Panel.TFrame", background=self.PANEL)
        style.configure("Card.TFrame", background=self.PANEL_ALT)
        style.configure("Title.TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 25, "bold"))
        style.configure("Subtitle.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI", 11))
        style.configure("Label.TLabel", background=self.PANEL, foreground=self.MUTED, font=("Segoe UI", 9, "bold"))
        style.configure("Body.TLabel", background=self.PANEL, foreground=self.TEXT, font=("Segoe UI", 10))
        style.configure("CardLabel.TLabel", background=self.PANEL_ALT, foreground=self.MUTED, font=("Segoe UI", 9, "bold"))
        style.configure("CardValue.TLabel", background=self.PANEL_ALT, foreground=self.TEXT, font=("Segoe UI", 22, "bold"))
        style.configure("Accent.TButton", background=self.ACCENT, foreground="#06131a", font=("Segoe UI", 10, "bold"), padding=(16, 9))
        style.map("Accent.TButton", background=[("active", "#55e3c0"), ("disabled", "#355e59")])
        style.configure("Secondary.TButton", background=self.PANEL_ALT, foreground=self.TEXT, padding=(10, 7))
        style.map("Secondary.TButton", background=[("active", "#203554")])
        style.configure("Treeview", background="#0f192b", fieldbackground="#0f192b", foreground=self.TEXT, rowheight=30, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=self.PANEL_ALT, foreground=self.MUTED, relief="flat", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#164c5d")], foreground=[("selected", "#ffffff")])
        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.PANEL, foreground=self.MUTED, padding=(12, 7))
        style.map("TNotebook.Tab", background=[("selected", self.PANEL_ALT)], foreground=[("selected", self.ACCENT)])
        style.configure("Horizontal.TProgressbar", troughcolor=self.PANEL_ALT, background=self.ACCENT, bordercolor=self.PANEL_ALT, lightcolor=self.ACCENT, darkcolor=self.ACCENT)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, style="App.TFrame", padding=24)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer, style="App.TFrame")
        header.pack(fill="x", pady=(0, 18))
        header_text = ttk.Frame(header, style="App.TFrame")
        header_text.pack(side="left")
        ttk.Label(header_text, text="Network Exposure Assessment", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header_text, text="Discover network services exposed by an authorized target.", style="Subtitle.TLabel").pack(anchor="w", pady=(4, 0))
        ttk.Button(header, text="LEVEL 2: ATTACK RECONSTRUCTION", style="Secondary.TButton", command=self.open_level2).pack(side="right", pady=(5, 0))

        control = ttk.Frame(outer, style="Panel.TFrame", padding=16)
        control.pack(fill="x", pady=(0, 14))
        ttk.Label(control, text="TARGET IP ADDRESS", style="Label.TLabel").grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar()
        self.target_var.trace_add("write", lambda *_: self._update_command())
        self.target_entry = ttk.Entry(control, textvariable=self.target_var, font=("Segoe UI", 11), width=30)
        self.target_entry.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.scan_button = ttk.Button(control, text="START NMAP SCAN", style="Accent.TButton", command=self.start_scan)
        self.scan_button.grid(row=1, column=1, padx=(12, 0), pady=(6, 0))
        ttk.Button(control, text="NEW SCAN", style="Secondary.TButton", command=self.new_scan).grid(row=1, column=2, padx=(8, 0), pady=(6, 0))
        control.columnconfigure(0, weight=1)

        status_bar = ttk.Frame(outer, style="App.TFrame")
        status_bar.pack(fill="x", pady=(0, 14))
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_bar, textvariable=self.status_var, style="Body.TLabel")
        self.status_label.pack(side="left")
        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", length=190)
        self.progress.pack(side="right")
        self.progress.stop(); self.progress.pack_forget()

        cards = ttk.Frame(outer, style="App.TFrame")
        cards.pack(fill="x", pady=(0, 14))
        self.card_values: dict[str, tk.StringVar] = {}
        for index, (key, label) in enumerate((("open", "OPEN PORTS"), ("tcp", "TCP SERVICES"), ("udp", "UDP SERVICES"), ("total", "TOTAL SERVICES"))):
            card = ttk.Frame(cards, style="Card.TFrame", padding=14)
            card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 6, 0))
            ttk.Label(card, text=label, style="CardLabel.TLabel").pack(anchor="w")
            value = tk.StringVar(value="—")
            self.card_values[key] = value
            ttk.Label(card, textvariable=value, style="CardValue.TLabel").pack(anchor="w", pady=(5, 0))
            cards.columnconfigure(index, weight=1)

        content = ttk.PanedWindow(outer, orient="horizontal")
        content.pack(fill="both", expand=True)
        left = ttk.Frame(content, style="Panel.TFrame", padding=12)
        right = ttk.Frame(content, style="Panel.TFrame", padding=12)
        content.add(left, weight=4); content.add(right, weight=1)
        ttk.Label(left, text="OBSERVED OPEN SERVICES", style="Label.TLabel").pack(anchor="w", pady=(0, 9))
        columns = ("port", "protocol", "state", "service", "product", "version")
        self.service_tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        widths = {"port": 70, "protocol": 80, "state": 75, "service": 110, "product": 170, "version": 150}
        for column in columns:
            self.service_tree.heading(column, text=column.upper())
            self.service_tree.column(column, width=widths[column], anchor="w")
        self.service_tree.pack(fill="both", expand=True)
        self.service_tree.bind("<<TreeviewSelect>>", self._show_details)
        self.empty_label = ttk.Label(left, text="No open services discovered.", style="Subtitle.TLabel")
        self.empty_label.place(relx=0.5, rely=0.53, anchor="center")

        ttk.Label(right, text="SERVICE DETAILS", style="Label.TLabel").pack(anchor="w", pady=(0, 9))
        self.detail_vars = {key: tk.StringVar(value="—") for key in ("target", "port", "protocol", "state", "service", "product", "version", "extra")}
        for key, label in (("target", "Target IP"), ("port", "Port"), ("protocol", "Protocol"), ("state", "State"), ("service", "Service"), ("product", "Product"), ("version", "Version"), ("extra", "Extra Information")):
            row = ttk.Frame(right, style="Panel.TFrame"); row.pack(fill="x", pady=3)
            ttk.Label(row, text=label, style="Label.TLabel").pack(anchor="w")
            ttk.Label(row, textvariable=self.detail_vars[key], style="Body.TLabel", wraplength=210).pack(anchor="w", pady=(2, 0))
        ttk.Label(right, text="SCAN HISTORY", style="Label.TLabel").pack(anchor="w", pady=(18, 7))
        self.history_list = tk.Listbox(right, bg="#0f192b", fg=self.TEXT, selectbackground="#164c5d", selectforeground="#ffffff", relief="flat", highlightthickness=0, font=("Segoe UI", 9), height=7)
        self.history_list.pack(fill="both", expand=True)
        self.history_list.bind("<<ListboxSelect>>", self._load_history)

        command_frame = ttk.Frame(outer, style="Panel.TFrame", padding=10)
        command_frame.pack(fill="x", pady=(14, 0))
        ttk.Label(command_frame, text="NMAP COMMAND", style="Label.TLabel").pack(anchor="w")
        self.command_var = tk.StringVar()
        ttk.Label(command_frame, textvariable=self.command_var, style="Body.TLabel").pack(anchor="w", pady=(4, 0))
        self.raw_frame = ttk.Frame(outer, style="Panel.TFrame")
        self.raw_frame.pack(fill="x", pady=(10, 0))
        self.raw_visible = False
        ttk.Button(self.raw_frame, text="SHOW RAW NMAP XML", style="Secondary.TButton", command=self.toggle_raw).pack(side="left")
        ttk.Button(self.raw_frame, text="COPY RAW OUTPUT", style="Secondary.TButton", command=self.copy_raw).pack(side="left", padx=8)
        self.raw_text = tk.Text(outer, height=8, bg="#08101d", fg="#9ee7c9", insertbackground=self.TEXT, relief="flat", font=("DejaVu Sans Mono", 8))

    def _update_command(self) -> None:
        target = self.target_var.get().strip() if hasattr(self, "target_var") else "<TARGET_IP>"
        self.command_var.set("sudo -n nmap -sS -sU -sV -p T:22,80,443,3000,445,49152,U:53 -oX - " + (target or "<TARGET_IP>"))

    def start_scan(self) -> None:
        if self.worker and self.worker.is_alive(): return
        try: target = validate_target(self.target_var.get())
        except ScanError as exc:
            messagebox.showerror("Invalid target", str(exc)); return
        self.target_var.set(target); self.scan_button.state(["disabled"]); self.target_entry.state(["disabled"])
        self.status_var.set(f"Scanning {target}... Running Nmap service discovery...")
        self.progress.pack(side="right"); self.progress.start(12)
        self.worker = threading.Thread(target=self._scan_worker, args=(target,), daemon=True); self.worker.start()

    def _scan_worker(self, target: str) -> None:
        try:
            raw = run_nmap(target); result = parse_nmap_xml(raw, target)
            self.after(0, self._scan_success, result)
        except (ScanError, NmapParseError) as exc:
            self.after(0, self._scan_failure, target, str(exc))
        except Exception:
            self.after(0, self._scan_failure, target, "The scan could not be completed due to an unexpected application error.")

    def _finish_scan_ui(self) -> None:
        self.progress.stop(); self.progress.pack_forget(); self.scan_button.state(["!disabled"]); self.target_entry.state(["!disabled"])

    def _scan_success(self, result: ScanResult) -> None:
        self._finish_scan_ui(); self.current_result = result; self._display_result(result); self.status_var.set("Scan completed")
        entry = ScanHistory(result.target_ip, datetime.now().astimezone().isoformat(timespec="seconds"), "Scan completed", result.open_ports, result)
        self.history_entries = self.history_store.add(entry); self._refresh_history()

    def _scan_failure(self, target: str, error: str) -> None:
        self._finish_scan_ui(); self.status_var.set("Scan failed"); messagebox.showerror("Scan failed", error)
        entry = ScanHistory(target, datetime.now().astimezone().isoformat(timespec="seconds"), "Scan failed", 0, None)
        self.history_entries = self.history_store.add(entry); self._refresh_history()

    def _display_result(self, result: ScanResult) -> None:
        for item in self.service_tree.get_children(): self.service_tree.delete(item)
        for index, service in enumerate(result.services):
            self.service_tree.insert("", "end", iid=str(index), values=(service.port, service.protocol, service.state, service.service or "—", service.product or "—", service.version or "—"))
        self.empty_label.place_forget() if result.services else self.empty_label.place(relx=0.5, rely=0.53, anchor="center")
        self.card_values["open"].set(str(result.open_ports)); self.card_values["tcp"].set(str(result.tcp_services)); self.card_values["udp"].set(str(result.udp_services)); self.card_values["total"].set(str(result.open_ports))
        self.raw_text.delete("1.0", "end"); self.raw_text.insert("1.0", result.raw_xml)
        self._clear_details()

    def _show_details(self, _event=None) -> None:
        if not self.current_result: return
        selection = self.service_tree.selection()
        if not selection: return
        service = self.current_result.services[int(selection[0])]
        values = {"target": self.current_result.target_ip, "port": str(service.port), "protocol": service.protocol, "state": service.state, "service": service.service or "—", "product": service.product or "—", "version": service.version or "—", "extra": service.extra or "—"}
        for key, value in values.items(): self.detail_vars[key].set(value)

    def _clear_details(self) -> None:
        for key in self.detail_vars: self.detail_vars[key].set("—")

    def _refresh_history(self) -> None:
        self.history_list.delete(0, "end")
        for entry in self.history_entries:
            self.history_list.insert("end", f"{entry.timestamp.replace('T', ' ')}  |  {entry.target_ip}  |  {entry.status}  |  {entry.open_ports} open")

    def _load_history(self, _event=None) -> None:
        selection = self.history_list.curselection()
        if not selection: return
        entry = self.history_entries[selection[0]]
        if entry.result:
            self.target_var.set(entry.target_ip); self.current_result = entry.result; self._display_result(entry.result); self.status_var.set("Loaded from scan history")

    def toggle_raw(self) -> None:
        self.raw_visible = not self.raw_visible
        if self.raw_visible: self.raw_text.pack(fill="x", pady=(8, 0))
        else: self.raw_text.pack_forget()

    def copy_raw(self) -> None:
        raw = self.raw_text.get("1.0", "end-1c")
        if not raw: return
        self.clipboard_clear(); self.clipboard_append(raw); self.update(); self.status_var.set("Raw XML copied to clipboard")

    def new_scan(self) -> None:
        if self.worker and self.worker.is_alive(): return
        self.target_var.set(""); self.current_result = None; self._clear_details()
        for item in self.service_tree.get_children(): self.service_tree.delete(item)
        self.empty_label.place(relx=0.5, rely=0.53, anchor="center")
        for value in self.card_values.values(): value.set("—")
        self.raw_text.delete("1.0", "end"); self.status_var.set("Ready"); self.target_entry.focus_set()

    def open_level2(self) -> None:
        Level2Dashboard(self, self.current_result)
