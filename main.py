from pathlib import Path

from ui.dashboard import Dashboard


if __name__ == "__main__":
    project_dir = Path(__file__).resolve().parent
    app = Dashboard(str(project_dir / "scan_history.json"))
    app.mainloop()
