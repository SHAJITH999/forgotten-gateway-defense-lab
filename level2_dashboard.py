from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from level2_detection import TECHNIQUES, detect, map_mitre
from level2_models import Detection, MitreMapping, SecurityEvent, TimelineEntry
from level2_pipeline import build_timeline
from telemetry_receiver import TelemetryReceiver


class Level2Dashboard(tk.Toplevel):
    BG = "#0b1220"; PANEL = "#111b2e"; PANEL_ALT = "#16243b"; TEXT = "#e6edf7"; MUTED = "#8da2bf"; ACCENT = "#31d0aa"

    def __init__(self, parent: tk.Misc, level1_result=None):
        super().__init__(parent)
        self.parent = parent; self.level1_result = level1_result
        self.title("Attack Reconstruction — Level 2")
        self.geometry("1320x860"); self.minsize(1040, 700); self.configure(bg=self.BG)
        self.events: list[SecurityEvent] = []; self.detections: list[Detection] = []; self.mappings: list[MitreMapping] = []; self.timeline: list[TimelineEntry] = []
        self.receiver: TelemetryReceiver | None = None
        self._build_style(); self._build_ui(); self.protocol("WM_DELETE_WINDOW", self.close); self._refresh()

    def _build_style(self):
        style = ttk.Style(self); style.theme_use("clam")
        style.configure("App.TFrame", background=self.BG); style.configure("Panel.TFrame", background=self.PANEL); style.configure("Card.TFrame", background=self.PANEL_ALT)
        style.configure("Title.TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 23, "bold")); style.configure("Subtitle.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI", 10))
        style.configure("Label.TLabel", background=self.PANEL, foreground=self.MUTED, font=("Segoe UI", 9, "bold")); style.configure("Body.TLabel", background=self.PANEL, foreground=self.TEXT, font=("Segoe UI", 9))
        style.configure("CardLabel.TLabel", background=self.PANEL_ALT, foreground=self.MUTED, font=("Segoe UI", 8, "bold")); style.configure("CardValue.TLabel", background=self.PANEL_ALT, foreground=self.TEXT, font=("Segoe UI", 18, "bold"))
        style.configure("Accent.TButton", background=self.ACCENT, foreground="#06131a", font=("Segoe UI", 9, "bold"), padding=(12, 7)); style.map("Accent.TButton", background=[("active", "#55e3c0"), ("disabled", "#355e59")])
        style.configure("Secondary.TButton", background=self.PANEL_ALT, foreground=self.TEXT, padding=(9, 6)); style.map("Secondary.TButton", background=[("active", "#203554")])
        style.configure("Treeview", background="#0f192b", fieldbackground="#0f192b", foreground=self.TEXT, rowheight=27, borderwidth=0, font=("Segoe UI", 8)); style.configure("Treeview.Heading", background=self.PANEL_ALT, foreground=self.MUTED, relief="flat", font=("Segoe UI", 8, "bold")); style.map("Treeview", background=[("selected", "#164c5d")], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        outer = ttk.Frame(self, style="App.TFrame", padding=20); outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer, style="App.TFrame"); header.pack(fill="x", pady=(0, 12))
        htext = ttk.Frame(header, style="App.TFrame"); htext.pack(side="left"); ttk.Label(htext, text="Attack Reconstruction", style="Title.TLabel").pack(anchor="w"); ttk.Label(htext, text="LEVEL 2 — REAL MAC NGINX TELEMETRY", style="Subtitle.TLabel").pack(anchor="w", pady=(4, 0))
        context = "No Level 1 scan context loaded"
        if self.level1_result is not None:
            services = ", ".join(f"{item.port}/{item.protocol} {item.service or 'service'}" for item in self.level1_result.services) or "no open services"
            context = f"Level 1 context: {self.level1_result.target_ip} — {services} (exposure context only; not an attack finding)"
        ttk.Label(outer, text=context, style="Subtitle.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Button(header, text="STOP RECEIVER", style="Secondary.TButton", command=self.stop_receiver).pack(side="right", pady=(5, 0))

        config = ttk.Frame(outer, style="Panel.TFrame", padding=12); config.pack(fill="x", pady=(0, 10)); ttk.Label(config, text="WINDOWS RECEIVER CONFIGURATION", style="Label.TLabel").grid(row=0, column=0, columnspan=5, sticky="w")
        ttk.Label(config, text="Bind address", style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(7, 0)); self.bind_var = tk.StringVar(value="0.0.0.0"); ttk.Entry(config, textvariable=self.bind_var, width=15).grid(row=1, column=1, sticky="w", padx=8, pady=(7, 0))
        ttk.Label(config, text="Port", style="Body.TLabel").grid(row=1, column=2, sticky="w", pady=(7, 0)); self.port_var = tk.StringVar(value="8765"); ttk.Entry(config, textvariable=self.port_var, width=8).grid(row=1, column=3, sticky="w", padx=8, pady=(7, 0))
        ttk.Label(config, text="Shared token", style="Body.TLabel").grid(row=1, column=4, sticky="w", pady=(7, 0)); self.token_var = tk.StringVar(); ttk.Entry(config, textvariable=self.token_var, show="•", width=28).grid(row=1, column=5, sticky="ew", padx=8, pady=(7, 0)); ttk.Button(config, text="START RECEIVER", style="Accent.TButton", command=self.start_receiver).grid(row=1, column=6, padx=(8, 0), pady=(7, 0)); config.columnconfigure(5, weight=1)
        ttk.Label(config, text="The Mac agent sends authenticated events here; Windows never reads Mac filesystem paths.", style="Subtitle.TLabel").grid(row=2, column=0, columnspan=7, sticky="w", pady=(8, 0))

        status = ttk.Frame(outer, style="Panel.TFrame", padding=10); status.pack(fill="x", pady=(0, 10)); self.status_vars = {key: tk.StringVar(value=value) for key, value in (("connection", "DISCONNECTED"), ("last", "—"), ("count", "0"), ("health", "Idle"))}
        for index, (key, label) in enumerate((("connection", "CONNECTION"), ("last", "LAST EVENT RECEIVED"), ("count", "EVENTS RECEIVED"), ("health", "COLLECTOR HEALTH"))):
            cell = ttk.Frame(status, style="Panel.TFrame"); cell.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 18, 0)); status.columnconfigure(index, weight=1); ttk.Label(cell, text=label, style="Label.TLabel").pack(anchor="w"); ttk.Label(cell, textvariable=self.status_vars[key], style="Body.TLabel").pack(anchor="w", pady=(3, 0))

        cards = ttk.Frame(outer, style="App.TFrame"); cards.pack(fill="x", pady=(0, 10)); self.card_vars = {key: tk.StringVar(value="0") for key in ("events", "detections", "high", "mitre")}
        for index, (key, title) in enumerate((("events", "TOTAL EVENTS"), ("detections", "DETECTIONS"), ("high", "HIGH / CRITICAL"), ("mitre", "OBSERVED MITRE TECHNIQUES"))):
            card = ttk.Frame(cards, style="Card.TFrame", padding=11); card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 6, 0)); cards.columnconfigure(index, weight=1); ttk.Label(card, text=title, style="CardLabel.TLabel").pack(anchor="w"); ttk.Label(card, textvariable=self.card_vars[key], style="CardValue.TLabel").pack(anchor="w", pady=(3, 0))

        notebook = ttk.Notebook(outer); notebook.pack(fill="both", expand=True)
        self.timeline_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10); self.events_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10); self.alerts_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10); self.mitre_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10)
        notebook.add(self.timeline_tab, text="  REAL OBSERVED TIMELINE  "); notebook.add(self.events_tab, text="  LIVE EVENT STREAM  "); notebook.add(self.alerts_tab, text="  SECURITY ALERTS  "); notebook.add(self.mitre_tab, text="  MITRE ATT&CK  ")
        self.timeline_tree = self._tree(self.timeline_tab, ("time", "event", "source", "severity", "description", "technique", "evidence"), (170, 140, 110, 80, 470, 260, 150)); self.timeline_tree.bind("<<TreeviewSelect>>", self._timeline_detail)
        top = ttk.Frame(self.events_tab, style="Panel.TFrame"); top.pack(fill="x", pady=(0, 7)); ttk.Label(top, text="Filter", style="Body.TLabel").pack(side="left"); self.filter_var = tk.StringVar(); self.filter_var.trace_add("write", lambda *_: self._refresh_events()); ttk.Entry(top, textvariable=self.filter_var, width=40).pack(side="left", padx=8)
        self.events_tree = self._tree(self.events_tab, ("time", "source_ip", "method", "path", "status", "source", "event_id"), (170, 120, 75, 270, 65, 100, 150)); self.events_tree.bind("<<TreeviewSelect>>", self._event_detail)
        self.alerts_tree = self._tree(self.alerts_tab, ("time", "severity", "reason", "source_ip", "rule", "confidence", "technique"), (170, 75, 440, 120, 190, 85, 180)); self.alerts_tree.bind("<<TreeviewSelect>>", self._alert_detail)
        self.mitre_tree = self._tree(self.mitre_tab, ("id", "name", "status", "confidence", "timestamp", "why", "evidence"), (100, 230, 145, 85, 170, 430, 150)); self.mitre_tree.bind("<<TreeviewSelect>>", self._mitre_detail)
        panel = ttk.Frame(outer, style="Panel.TFrame", padding=10); panel.pack(fill="x", pady=(10, 0)); ttk.Label(panel, text="EVIDENCE / EVENT DETAILS", style="Label.TLabel").pack(anchor="w"); self.details = tk.Text(panel, height=6, bg="#08101d", fg="#c6d6e9", insertbackground=self.TEXT, relief="flat", font=("DejaVu Sans Mono", 8), wrap="word"); self.details.pack(fill="x", pady=(5, 0))

    def _tree(self, parent, columns, widths):
        frame = ttk.Frame(parent, style="Panel.TFrame"); frame.pack(fill="both", expand=True); tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for column, width in zip(columns, widths): tree.heading(column, text=column.upper()); tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview); tree.configure(yscrollcommand=scroll.set); tree.pack(side="left", fill="both", expand=True); scroll.pack(side="right", fill="y"); return tree

    def start_receiver(self):
        try:
            port = int(self.port_var.get()); token = self.token_var.get()
            if not token: raise ValueError("Enter the shared authentication token.")
            if self.receiver: self.receiver.stop()
            self.receiver = TelemetryReceiver(self.bind_var.get().strip() or "0.0.0.0", port, token, self._received_from_thread, self._status_from_thread); self.receiver.start(); self._set_health("Receiver listening")
        except (ValueError, OSError) as exc: messagebox.showerror("Receiver error", str(exc), parent=self)

    def stop_receiver(self):
        if self.receiver: self.receiver.stop(); self.receiver = None
        self.status_vars["connection"].set("DISCONNECTED"); self.status_vars["health"].set("Receiver stopped")

    def _received_from_thread(self, event: SecurityEvent): self.after(0, self._accept_event, event)
    def _status_from_thread(self, status: dict): self.after(0, self._update_status, status)
    def _accept_event(self, event):
        if any(item.event_id == event.event_id for item in self.events): return
        self.events.append(event); self.events.sort(key=lambda item: item.timestamp); self._refresh()
    def _update_status(self, status):
        self.status_vars["connection"].set("CONNECTED" if status["connected"] else "DISCONNECTED"); self.status_vars["last"].set(status["last_event_received"] or "—"); self.status_vars["count"].set(str(status["events_received"])); self.status_vars["health"].set(status["last_error"] or ("Receiving telemetry" if status["connected"] else "Waiting for Mac agent"))
    def _set_health(self, value): self.status_vars["health"].set(value)

    def _refresh(self):
        self.detections = detect(self.events); self.mappings = map_mitre(self.events, self.detections); self.timeline = build_timeline(self.events, self.detections, self.mappings)
        self.card_vars["events"].set(str(len(self.events))); self.card_vars["detections"].set(str(len(self.detections))); self.card_vars["high"].set(str(sum(1 for item in self.detections if item.severity in ("high", "critical")))); self.card_vars["mitre"].set(str(len({item.technique_id for item in self.mappings if item.status == "observed"})))
        self._fill_timeline(); self._refresh_events(); self._fill_alerts(); self._fill_mitre()

    def _clear(self, tree):
        for item in tree.get_children(): tree.delete(item)
    def _fill_timeline(self):
        self._clear(self.timeline_tree)
        for index, item in enumerate(self.timeline): self.timeline_tree.insert("", "end", iid=f"tl-{index}", values=(item.timestamp, item.event, item.source, item.severity, item.description, item.mitre_technique or "—", ", ".join(item.evidence_event_ids) or "—"))
    def _refresh_events(self):
        self._clear(self.events_tree); query = self.filter_var.get().lower()
        for index, item in enumerate(self.events):
            values = (item.timestamp, item.source_ip, item.method, item.path, item.status or "—", item.source, item.event_id)
            if not query or query in " ".join(map(str, values)).lower(): self.events_tree.insert("", "end", iid=f"ev-{index}", values=values)
    def _fill_alerts(self):
        self._clear(self.alerts_tree)
        for index, item in enumerate(self.detections): self.alerts_tree.insert("", "end", iid=f"al-{index}", values=(item.timestamp, item.severity.upper(), item.reason, item.source_ip, item.rule, item.confidence, item.mitre_technique or "—"))
    def _fill_mitre(self):
        self._clear(self.mitre_tree)
        for index, item in enumerate(self.mappings): self.mitre_tree.insert("", "end", iid=f"mi-{index}", values=(item.technique_id, item.technique_name, item.status, item.confidence, item.timestamp or "—", item.why, ", ".join(item.supporting_event_ids) or "—"))
    def _set_details(self, text): self.details.delete("1.0", "end"); self.details.insert("1.0", text)
    def _event_by_iid(self, iid): return self.events[int(iid.split("-")[1])]
    def _timeline_detail(self, _event=None):
        selection = self.timeline_tree.selection()
        if selection:
            item = self.timeline[int(selection[0].split("-")[1])]; self._set_details(f"REAL OBSERVED TIMELINE ENTRY\nTimestamp: {item.timestamp}\nSource: {item.source}\nSeverity: {item.severity}\nDescription: {item.description}\nMITRE: {item.mitre_technique or '—'}\nEvidence IDs: {', '.join(item.evidence_event_ids) or '—'}")
    def _event_detail(self, _event=None):
        selection = self.events_tree.selection()
        if selection:
            item = self._event_by_iid(selection[0]); self._set_details("RAW RECEIVED NGINX EVIDENCE\n" + item.raw_event + "\n\nPARSED FIELDS\n" + "\n".join(f"{key}: {value}" for key, value in item.to_dict().items()))
    def _alert_detail(self, _event=None):
        selection = self.alerts_tree.selection()
        if selection:
            item = self.detections[int(selection[0].split("-")[1])]; self._set_details("DETECTION\n" + "\n".join(f"{key}: {value}" for key, value in item.to_dict().items()))
    def _mitre_detail(self, _event=None):
        selection = self.mitre_tree.selection()
        if selection:
            item = self.mappings[int(selection[0].split("-")[1])]; self._set_details("MITRE ATT&CK MAPPING\n" + "\n".join(f"{key}: {value}" for key, value in item.to_dict().items()))
    def close(self):
        self.stop_receiver(); self.destroy()
