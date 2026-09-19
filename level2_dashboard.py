from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from level2_correlation import calculate_risk, correlate
from level2_detection import TECHNIQUES, detect, map_mitre
from level2_models import (
    Correlation,
    Detection,
    MitreMapping,
    RiskAssessment,
    SecurityEvent,
    TimelineEntry,
)
from level2_pipeline import build_timeline
from level2_scenarios import SCENARIOS, parse_scenario_lines
from nginx_parser import parse_access_line, parse_error_line
from telemetry_receiver import TelemetryReceiver


class Level2Dashboard(tk.Toplevel):
    BG = "#0b1220"
    PANEL = "#111b2e"
    PANEL_ALT = "#16243b"
    TEXT = "#e6edf7"
    MUTED = "#8da2bf"
    ACCENT = "#31d0aa"
    ALERT_HIGH = "#ff5c77"
    ALERT_MED = "#f59e0b"

    def __init__(self, parent: tk.Misc, level1_result=None):
        super().__init__(parent)
        self.parent = parent
        self.level1_result = level1_result
        self.title("Attack Reconstruction & Security Detection — Level 2")
        self.geometry("1360x880")
        self.minsize(1080, 720)
        self.configure(bg=self.BG)

        self.events: list[SecurityEvent] = []
        self.detections: list[Detection] = []
        self.correlations: list[Correlation] = []
        self.mappings: list[MitreMapping] = []
        self.timeline: list[TimelineEntry] = []
        self.risk: RiskAssessment = RiskAssessment(0, "Low")
        self.receiver: TelemetryReceiver | None = None

        self._build_style()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self._refresh()

    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TFrame", background=self.BG)
        style.configure("Panel.TFrame", background=self.PANEL)
        style.configure("Card.TFrame", background=self.PANEL_ALT)
        style.configure("Title.TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI", 9))
        style.configure("Label.TLabel", background=self.PANEL, foreground=self.MUTED, font=("Segoe UI", 8, "bold"))
        style.configure("Body.TLabel", background=self.PANEL, foreground=self.TEXT, font=("Segoe UI", 9))
        style.configure("CardLabel.TLabel", background=self.PANEL_ALT, foreground=self.MUTED, font=("Segoe UI", 8, "bold"))
        style.configure("CardValue.TLabel", background=self.PANEL_ALT, foreground=self.TEXT, font=("Segoe UI", 16, "bold"))
        style.configure("Accent.TButton", background=self.ACCENT, foreground="#06131a", font=("Segoe UI", 8, "bold"), padding=(10, 6))
        style.map("Accent.TButton", background=[("active", "#55e3c0"), ("disabled", "#355e59")])
        style.configure("Secondary.TButton", background=self.PANEL_ALT, foreground=self.TEXT, font=("Segoe UI", 8), padding=(8, 5))
        style.map("Secondary.TButton", background=[("active", "#203554")])
        style.configure("Treeview", background="#0f192b", fieldbackground="#0f192b", foreground=self.TEXT, rowheight=26, borderwidth=0, font=("Segoe UI", 8))
        style.configure("Treeview.Heading", background=self.PANEL_ALT, foreground=self.MUTED, relief="flat", font=("Segoe UI", 8, "bold"))
        style.map("Treeview", background=[("selected", "#164c5d")], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        outer = ttk.Frame(self, style="App.TFrame", padding=16)
        outer.pack(fill="both", expand=True)

        # Header
        header = ttk.Frame(outer, style="App.TFrame")
        header.pack(fill="x", pady=(0, 10))
        htext = ttk.Frame(header, style="App.TFrame")
        htext.pack(side="left")
        ttk.Label(htext, text="Attack Reconstruction & Security Detection", style="Title.TLabel").pack(anchor="w")
        ttk.Label(htext, text="LEVEL 2 — REAL TELEMETRY, CORRELATION, MITRE ATT&CK & TIMELINE", style="Subtitle.TLabel").pack(anchor="w", pady=(3, 0))

        # Level 1 Context Banner
        context = "No Level 1 scan context loaded"
        if self.level1_result is not None:
            services = ", ".join(f"{item.port}/{item.protocol} {item.service or 'service'}" for item in self.level1_result.services) or "no open services"
            context = f"Level 1 Scan Context: Target {self.level1_result.target_ip} — Open Services: [{services}] (Exposure context used for correlation & risk scoring)"
        ttk.Label(outer, text=context, style="Subtitle.TLabel").pack(anchor="w", pady=(0, 8))

        # Top Control Bar (Receiver + Scenario loader)
        ctrl_bar = ttk.Frame(outer, style="Panel.TFrame", padding=10)
        ctrl_bar.pack(fill="x", pady=(0, 10))

        # Receiver controls
        ttk.Label(ctrl_bar, text="REMOTE MAC RECEIVER", style="Label.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(ctrl_bar, text="Host", style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.bind_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(ctrl_bar, textvariable=self.bind_var, width=12).grid(row=1, column=1, sticky="w", padx=6, pady=(4, 0))
        ttk.Label(ctrl_bar, text="Port", style="Body.TLabel").grid(row=1, column=2, sticky="w", pady=(4, 0))
        self.port_var = tk.StringVar(value="8765")
        ttk.Entry(ctrl_bar, textvariable=self.port_var, width=6).grid(row=1, column=3, sticky="w", padx=6, pady=(4, 0))
        ttk.Label(ctrl_bar, text="Token", style="Body.TLabel").grid(row=1, column=4, sticky="w", pady=(4, 0))
        self.token_var = tk.StringVar()
        ttk.Entry(ctrl_bar, textvariable=self.token_var, show="•", width=18).grid(row=1, column=5, sticky="ew", padx=6, pady=(4, 0))
        ttk.Button(ctrl_bar, text="START RECEIVER", style="Accent.TButton", command=self.start_receiver).grid(row=1, column=6, padx=4, pady=(4, 0))
        ttk.Button(ctrl_bar, text="STOP", style="Secondary.TButton", command=self.stop_receiver).grid(row=1, column=7, padx=4, pady=(4, 0))

        # Separator & Scenario controls
        ttk.Separator(ctrl_bar, orient="vertical").grid(row=0, column=8, rowspan=2, sticky="ns", padx=12)

        ttk.Label(ctrl_bar, text="SAFE LOCAL SCENARIOS & LOGS", style="Label.TLabel").grid(row=0, column=9, sticky="w")
        self.scenario_var = tk.StringVar(value="multi_stage")
        sc_menu = ttk.Combobox(
            ctrl_bar,
            textvariable=self.scenario_var,
            values=["multi_stage", "auth_anomaly", "account_discovery", "admin_probing", "normal"],
            state="readonly",
            width=18,
        )
        sc_menu.grid(row=1, column=9, sticky="w", padx=6, pady=(4, 0))
        ttk.Button(ctrl_bar, text="RUN SCENARIO", style="Accent.TButton", command=self._run_selected_scenario).grid(row=1, column=10, padx=4, pady=(4, 0))
        ttk.Button(ctrl_bar, text="LOAD LOG FILE...", style="Secondary.TButton", command=self._load_log_file).grid(row=1, column=11, padx=4, pady=(4, 0))
        ttk.Button(ctrl_bar, text="CLEAR", style="Secondary.TButton", command=self.clear_events).grid(row=1, column=12, padx=4, pady=(4, 0))

        ctrl_bar.columnconfigure(5, weight=1)

        # Receiver status indicators
        status = ttk.Frame(outer, style="Panel.TFrame", padding=8)
        status.pack(fill="x", pady=(0, 10))
        self.status_vars = {key: tk.StringVar(value=value) for key, value in (("connection", "DISCONNECTED"), ("last", "—"), ("count", "0"), ("health", "Idle"))}
        for index, (key, label) in enumerate((("connection", "CONNECTION"), ("last", "LAST EVENT RECEIVED"), ("count", "EVENTS RECEIVED"), ("health", "COLLECTOR HEALTH"))):
            cell = ttk.Frame(status, style="Panel.TFrame")
            cell.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 16, 0))
            status.columnconfigure(index, weight=1)
            ttk.Label(cell, text=label, style="Label.TLabel").pack(anchor="w")
            ttk.Label(cell, textvariable=self.status_vars[key], style="Body.TLabel").pack(anchor="w", pady=(2, 0))

        # KPI Summary Cards (Added Risk Score and Correlations)
        cards = ttk.Frame(outer, style="App.TFrame")
        cards.pack(fill="x", pady=(0, 10))
        self.card_vars = {key: tk.StringVar(value="0") for key in ("events", "detections", "correlations", "risk", "high", "mitre")}
        card_meta = [
            ("events", "TOTAL EVENTS"),
            ("detections", "DETECTIONS"),
            ("correlations", "ATTACK CHAINS"),
            ("risk", "RISK SCORE"),
            ("high", "HIGH / CRITICAL"),
            ("mitre", "MITRE TECHNIQUES"),
        ]
        for index, (key, title) in enumerate(card_meta):
            card = ttk.Frame(cards, style="Card.TFrame", padding=9)
            card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 6, 0))
            cards.columnconfigure(index, weight=1)
            ttk.Label(card, text=title, style="CardLabel.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=self.card_vars[key], style="CardValue.TLabel").pack(anchor="w", pady=(2, 0))

        # Notebook tabs
        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        self.timeline_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=8)
        self.correlations_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=8)
        self.alerts_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=8)
        self.mitre_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=8)
        self.events_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=8)

        notebook.add(self.timeline_tab, text="  ATTACK TIMELINE  ")
        notebook.add(self.correlations_tab, text="  CORRELATED CHAINS  ")
        notebook.add(self.alerts_tab, text="  SECURITY DETECTIONS  ")
        notebook.add(self.mitre_tab, text="  MITRE ATT&CK  ")
        notebook.add(self.events_tab, text="  EVIDENCE STREAM  ")

        # Tab: Timeline
        self.timeline_tree = self._tree(
            self.timeline_tab,
            ("time", "source", "severity", "description", "technique", "evidence"),
            (160, 120, 80, 520, 180, 150),
        )
        self.timeline_tree.bind("<<TreeviewSelect>>", self._timeline_detail)

        # Tab: Correlations
        self.corr_tree = self._tree(
            self.correlations_tab,
            ("id", "ip", "severity", "confidence", "stages", "summary", "start", "end"),
            (110, 120, 80, 80, 240, 420, 140, 140),
        )
        self.corr_tree.bind("<<TreeviewSelect>>", self._corr_detail)

        # Tab: Security Alerts
        self.alerts_tree = self._tree(
            self.alerts_tab,
            ("time", "severity", "reason", "source_ip", "rule", "confidence", "technique"),
            (160, 75, 460, 120, 180, 85, 160),
        )
        self.alerts_tree.bind("<<TreeviewSelect>>", self._alert_detail)

        # Tab: MITRE ATT&CK
        self.mitre_tree = self._tree(
            self.mitre_tab,
            ("id", "name", "status", "confidence", "timestamp", "why", "evidence"),
            (90, 220, 140, 85, 160, 440, 140),
        )
        self.mitre_tree.bind("<<TreeviewSelect>>", self._mitre_detail)

        # Tab: Evidence Stream
        top = ttk.Frame(self.events_tab, style="Panel.TFrame")
        top.pack(fill="x", pady=(0, 6))
        ttk.Label(top, text="Filter", style="Body.TLabel").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._refresh_events())
        ttk.Entry(top, textvariable=self.filter_var, width=35).pack(side="left", padx=8)

        self.events_tree = self._tree(
            self.events_tab,
            ("time", "source_ip", "method", "path", "status", "source", "event_id"),
            (160, 120, 75, 270, 65, 100, 150),
        )
        self.events_tree.bind("<<TreeviewSelect>>", self._event_detail)

        # Bottom Evidence/Details Panel
        panel = ttk.Frame(outer, style="Panel.TFrame", padding=8)
        panel.pack(fill="x", pady=(8, 0))
        ttk.Label(panel, text="EVIDENCE / INVESTIGATION DETAILS", style="Label.TLabel").pack(anchor="w")
        self.details = tk.Text(
            panel,
            height=5,
            bg="#08101d",
            fg="#c6d6e9",
            insertbackground=self.TEXT,
            relief="flat",
            font=("DejaVu Sans Mono", 8),
            wrap="word",
        )
        self.details.pack(fill="x", pady=(4, 0))

    def _tree(self, parent, columns, widths):
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for column, width in zip(columns, widths):
            tree.heading(column, text=column.upper())
            tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return tree

    def start_receiver(self):
        try:
            port = int(self.port_var.get())
            token = self.token_var.get()
            if not token:
                raise ValueError("Enter the shared authentication token.")
            if self.receiver:
                self.receiver.stop()
            self.receiver = TelemetryReceiver(
                self.bind_var.get().strip() or "0.0.0.0",
                port,
                token,
                self._received_from_thread,
                self._status_from_thread,
            )
            self.receiver.start()
            self._set_health("Receiver listening")
        except (ValueError, OSError) as exc:
            messagebox.showerror("Receiver error", str(exc), parent=self)

    def stop_receiver(self):
        if self.receiver:
            self.receiver.stop()
            self.receiver = None
        self.status_vars["connection"].set("DISCONNECTED")
        self.status_vars["health"].set("Receiver stopped")

    def _received_from_thread(self, event: SecurityEvent):
        self.after(0, self._accept_event, event)

    def _status_from_thread(self, status: dict):
        self.after(0, self._update_status, status)

    def _accept_event(self, event: SecurityEvent):
        if any(item.event_id == event.event_id for item in self.events):
            return
        self.events.append(event)
        self.events.sort(key=lambda item: item.timestamp)
        self._refresh()

    def _update_status(self, status: dict):
        self.status_vars["connection"].set("CONNECTED" if status["connected"] else "DISCONNECTED")
        self.status_vars["last"].set(status["last_event_received"] or "—")
        self.status_vars["count"].set(str(status["events_received"]))
        self.status_vars["health"].set(status["last_error"] or ("Receiving telemetry" if status["connected"] else "Waiting for Mac agent"))

    def _set_health(self, value: str):
        self.status_vars["health"].set(value)

    def _run_selected_scenario(self):
        sc_name = self.scenario_var.get()
        if sc_name in SCENARIOS:
            raw_lines = SCENARIOS[sc_name]()
            parsed_events = parse_scenario_lines(raw_lines)
            for ev in parsed_events:
                if not any(item.event_id == ev.event_id for item in self.events):
                    self.events.append(ev)
            self.events.sort(key=lambda item: item.timestamp)
            self._refresh()
            self.status_vars["health"].set(f"Loaded scenario: {sc_name}")

    def _load_log_file(self):
        filename = filedialog.askopenfilename(
            parent=self,
            title="Select Nginx Access/Error Log File",
            filetypes=[("Log files", "*.log;*.txt"), ("All files", "*.*")],
        )
        if not filename:
            return
        try:
            added = 0
            with open(filename, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    ev = parse_access_line(line) or parse_error_line(line)
                    if ev and not any(item.event_id == ev.event_id for item in self.events):
                        self.events.append(ev)
                        added += 1
            self.events.sort(key=lambda item: item.timestamp)
            self._refresh()
            self.status_vars["health"].set(f"Loaded {added} events from log file")
        except Exception as exc:
            messagebox.showerror("File Error", f"Unable to read log file: {exc}", parent=self)

    def clear_events(self):
        self.events.clear()
        self.detections.clear()
        self.correlations.clear()
        self.mappings.clear()
        self.timeline.clear()
        self.risk = RiskAssessment(0, "Low")
        self._refresh()
        self.status_vars["health"].set("Events cleared")

    def show_demo(self):
        """Reference demo scenario for legacy tests."""
        demo_entries = [
            TimelineEntry("2026-09-17T08:10:00+05:30", "Reconnaissance", "nmap", "low", "External services are identified and mapped", "T1071.001", ["ref-1"], demo=True),
            TimelineEntry("2026-09-17T08:24:00+05:30", "Initial Access", "nginx", "high", "An obsolete internet-facing appliance is probed / initial access attempt", "T1190", ["ref-2"], demo=True),
            TimelineEntry("2026-09-17T09:05:00+05:30", "Discovery", "nginx", "medium", "Access is validated and account/data discovery occurs", "T1087", ["ref-3"], demo=True),
            TimelineEntry("2026-09-17T10:40:00+05:30", "Collection", "nginx", "medium", "Collection and limited movement occurs", "T1041", ["ref-4"], demo=True),
            TimelineEntry("2026-09-17T13:15:00+05:30", "Detection", "detection-engine", "high", "A defender detects anomalous activity (repeated authentication failures)", "T1071.001", ["ref-5"], demo=True),
            TimelineEntry("2026-09-17T15:00:00+05:30", "Containment", "incident-response", "info", "Access revoked, affected systems/accounts contained, evidence preserved", "", ["ref-6"], demo=True),
        ]
        self.timeline = demo_entries
        self._fill_timeline()


    def _refresh(self):
        self.detections = detect(self.events)
        self.correlations = correlate(self.events, self.detections)
        self.mappings = map_mitre(self.events, self.detections)
        self.timeline = build_timeline(self.events, self.detections, self.mappings, self.correlations)
        self.risk = calculate_risk(self.detections, self.correlations, level1_context=self.level1_result)

        # Update KPI Cards
        self.card_vars["events"].set(str(len(self.events)))
        self.card_vars["detections"].set(str(len(self.detections)))
        self.card_vars["correlations"].set(str(len(self.correlations)))
        self.card_vars["risk"].set(f"{self.risk.score} ({self.risk.severity})")
        self.card_vars["high"].set(str(sum(1 for item in self.detections if item.severity in ("high", "critical"))))
        self.card_vars["mitre"].set(str(len({item.technique_id for item in self.mappings if item.status == "observed"})))

        self._fill_timeline()
        self._fill_correlations()
        self._refresh_events()
        self._fill_alerts()
        self._fill_mitre()

    def _clear(self, tree):
        for item in tree.get_children():
            tree.delete(item)

    def _fill_timeline(self):
        self._clear(self.timeline_tree)
        for index, item in enumerate(self.timeline):
            self.timeline_tree.insert(
                "",
                "end",
                iid=f"tl-{index}",
                values=(
                    item.timestamp,
                    item.source,
                    item.severity.upper(),
                    item.description,
                    item.mitre_technique or "—",
                    ", ".join(item.evidence_event_ids) or "—",
                ),
            )

    def _fill_correlations(self):
        self._clear(self.corr_tree)
        for index, item in enumerate(self.correlations):
            self.corr_tree.insert(
                "",
                "end",
                iid=f"cr-{index}",
                values=(
                    item.correlation_id,
                    item.source_ip,
                    item.severity.upper(),
                    item.confidence,
                    " -> ".join(item.stages_observed) or "Single Stage",
                    item.summary,
                    item.start_time,
                    item.end_time,
                ),
            )

    def _refresh_events(self):
        self._clear(self.events_tree)
        query = self.filter_var.get().lower()
        for index, item in enumerate(self.events):
            values = (item.timestamp, item.source_ip, item.method, item.path, item.status or "—", item.source, item.event_id)
            if not query or query in " ".join(map(str, values)).lower():
                self.events_tree.insert("", "end", iid=f"ev-{index}", values=values)

    def _fill_alerts(self):
        self._clear(self.alerts_tree)
        for index, item in enumerate(self.detections):
            self.alerts_tree.insert(
                "",
                "end",
                iid=f"al-{index}",
                values=(
                    item.timestamp,
                    item.severity.upper(),
                    item.reason,
                    item.source_ip,
                    item.rule,
                    item.confidence,
                    item.mitre_technique or "—",
                ),
            )

    def _fill_mitre(self):
        self._clear(self.mitre_tree)
        for index, item in enumerate(self.mappings):
            self.mitre_tree.insert(
                "",
                "end",
                iid=f"mi-{index}",
                values=(
                    item.technique_id,
                    item.technique_name,
                    item.status,
                    item.confidence,
                    item.timestamp or "—",
                    item.why,
                    ", ".join(item.supporting_event_ids) or "—",
                ),
            )

    def _set_details(self, text: str):
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)

    def _event_by_iid(self, iid: str) -> SecurityEvent:
        return self.events[int(iid.split("-")[1])]

    def _timeline_detail(self, _event=None):
        selection = self.timeline_tree.selection()
        if selection:
            item = self.timeline[int(selection[0].split("-")[1])]
            self._set_details(
                f"TIMELINE ENTRY\nTimestamp: {item.timestamp}\nSource: {item.source}\nSeverity: {item.severity}\nDescription: {item.description}\nMITRE: {item.mitre_technique or '—'}\nEvidence Event IDs: {', '.join(item.evidence_event_ids) or '—'}"
            )

    def _corr_detail(self, _event=None):
        selection = self.corr_tree.selection()
        if selection:
            item = self.correlations[int(selection[0].split("-")[1])]
            self._set_details(
                f"CORRELATED ATTACK CHAIN\nID: {item.correlation_id}\nSource IP: {item.source_ip}\nSeverity: {item.severity.upper()} (Confidence: {item.confidence})\nStages Observed: {' -> '.join(item.stages_observed)}\nSummary: {item.summary}\nTime Window: {item.start_time} to {item.end_time}\nRelated Detection IDs: {item.related_detection_ids}\nSupporting Event IDs: {item.related_event_ids}"
            )

    def _event_detail(self, _event=None):
        selection = self.events_tree.selection()
        if selection:
            item = self._event_by_iid(selection[0])
            self._set_details(
                f"RAW NGINX EVIDENCE\n{item.raw_event}\n\nPARSED FIELDS\n"
                + "\n".join(f"{key}: {value}" for key, value in item.to_dict().items())
            )

    def _alert_detail(self, _event=None):
        selection = self.alerts_tree.selection()
        if selection:
            item = self.detections[int(selection[0].split("-")[1])]
            self._set_details(
                f"DETECTION ALERT\n"
                + "\n".join(f"{key}: {value}" for key, value in item.to_dict().items())
            )

    def _mitre_detail(self, _event=None):
        selection = self.mitre_tree.selection()
        if selection:
            item = self.mappings[int(selection[0].split("-")[1])]
            self._set_details(
                f"MITRE ATT&CK MAPPING\n"
                + "\n".join(f"{key}: {value}" for key, value in item.to_dict().items())
            )

    def close(self):
        self.stop_receiver()
        self.destroy()
