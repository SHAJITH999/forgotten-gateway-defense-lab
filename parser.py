from __future__ import annotations

import xml.etree.ElementTree as ET

from models import ScanResult, Service


class NmapParseError(ValueError):
    """Raised when Nmap XML is malformed or incomplete."""


def parse_nmap_xml(xml_text: str, target_ip: str) -> ScanResult:
    if not xml_text or not xml_text.strip():
        raise NmapParseError("Nmap returned an invalid or incomplete XML result.")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapParseError("Nmap returned an invalid or incomplete XML result.") from exc

    services: list[Service] = []
    for port in root.findall(".//host/ports/port"):
        state_node = port.find("state")
        state = state_node.get("state", "") if state_node is not None else ""
        if state != "open":
            continue
        try:
            port_number = int(port.get("portid", "0"))
        except ValueError:
            continue
        protocol = port.get("protocol", "").upper()
        service_node = port.find("service")
        service = service_node.get("name", "") if service_node is not None else ""
        product = service_node.get("product", "") if service_node is not None else ""
        version = service_node.get("version", "") if service_node is not None else ""
        extra = ""
        if service_node is not None:
            extra = service_node.get("extrainfo", "")
            if not extra:
                extra = service_node.get("tunnel", "")
        services.append(Service(port_number, protocol, state, service, product, version, extra))

    services.sort(key=lambda item: (item.port, item.protocol))
    return ScanResult(target_ip=target_ip, raw_xml=xml_text, services=services)
