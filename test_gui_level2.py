from ui.dashboard import Dashboard
from ui.level2_dashboard import Level2Dashboard

app = Dashboard('/tmp/level2-history-test.json')
app.update_idletasks()
assert app.status_var.get() == 'Ready'
window = Level2Dashboard(app)
window.update_idletasks()
window.show_demo()
assert len(window.timeline) == 6
assert all(item.demo for item in window.timeline)
window.destroy()
app.destroy()
print('dual dashboard GUI smoke test passed')
