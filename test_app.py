import tempfile
from pathlib import Path

from history import HistoryStore
from models import ScanHistory
from parser import parse_nmap_xml
from scanner import ScanError, nmap_command, validate_target

XML = '''<?xml version="1.0"?><nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
<port protocol="udp" portid="53"><state state="open"/><service name="domain" product="dnsmasq" extrainfo="cached"/></port>
</ports></host></nmaprun>'''

assert validate_target("192.168.1.100") == "192.168.1.100"
assert validate_target("2001:db8::1") == "2001:db8::1"
for bad in ("", "not-an-ip", "192.168.1.1; rm -rf /"):
    try:
        validate_target(bad)
    except ScanError:
        pass
    else:
        raise AssertionError(f"accepted invalid target: {bad}")
assert nmap_command("192.168.1.100")[-1] == "192.168.1.100"
result = parse_nmap_xml(XML, "192.168.1.100")
assert result.open_ports == 2
assert result.tcp_services == 1 and result.udp_services == 1
assert result.services[0].service == "ssh"
assert result.services[1].extra == "cached"
with tempfile.TemporaryDirectory() as directory:
    store = HistoryStore(Path(directory) / "history.json")
    entries = store.add(ScanHistory("192.168.1.100", "now", "Scan completed", 2, result))
    loaded = store.load()
    assert len(entries) == len(loaded) == 1
    assert loaded[0].result.services[1].service == "domain"
print("all tests passed")
