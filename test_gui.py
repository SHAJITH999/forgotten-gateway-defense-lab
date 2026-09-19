from pathlib import Path
import tkinter as tk
from ui.dashboard import Dashboard

app = Dashboard(str(Path("/tmp/network-exposure-assessment-test-history.json")))
app.update_idletasks()
assert app.status_var.get() == "Ready"
assert "<TARGET_IP>" in app.command_var.get()
app.destroy()
print("gui smoke test passed")
