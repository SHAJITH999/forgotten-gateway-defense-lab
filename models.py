from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Service":
        return cls(
            port=int(data.get("port", 0)),
            protocol=str(data.get("protocol", "")),
            state=str(data.get("state", "")),
            service=str(data.get("service", "")),
            product=str(data.get("product", "")),
            version=str(data.get("version", "")),
            extra=str(data.get("extra", "")),
        )


@dataclass
class ScanResult:
    target_ip: str
    raw_xml: str
    services: list[Service] = field(default_factory=list)

    @property
    def open_ports(self) -> int:
        return len(self.services)

    @property
    def tcp_services(self) -> int:
        return sum(1 for item in self.services if item.protocol.lower() == "tcp")

    @property
    def udp_services(self) -> int:
        return sum(1 for item in self.services if item.protocol.lower() == "udp")

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "raw_xml": self.raw_xml,
            "services": [service.to_dict() for service in self.services],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            target_ip=str(data.get("target_ip", "")),
            raw_xml=str(data.get("raw_xml", "")),
            services=[Service.from_dict(item) for item in data.get("services", [])],
        )


@dataclass
class ScanHistory:
    target_ip: str
    timestamp: str
    status: str
    open_ports: int
    result: ScanResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "timestamp": self.timestamp,
            "status": self.status,
            "open_ports": self.open_ports,
            "result": self.result.to_dict() if self.result else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanHistory":
        result_data = data.get("result")
        return cls(
            target_ip=str(data.get("target_ip", "")),
            timestamp=str(data.get("timestamp", "")),
            status=str(data.get("status", "")),
            open_ports=int(data.get("open_ports", 0)),
            result=ScanResult.from_dict(result_data) if result_data else None,
        )
