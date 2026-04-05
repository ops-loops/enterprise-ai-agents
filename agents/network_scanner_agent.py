"""Network Scanner Agent – discovers hosts and open ports on a network."""

from typing import Any

from skills.nmap_skill import NmapSkill
from skills.port_analysis_skill import PortAnalysisSkill
from .base_agent import BaseAgent


class NetworkScannerAgent(BaseAgent):
    """Agent that discovers hosts and open ports in a target network.

    Uses :class:`~skills.nmap_skill.NmapSkill` for host discovery and port
    scanning, then feeds discovered ports into
    :class:`~skills.port_analysis_skill.PortAnalysisSkill` for risk
    classification.

    Example::

        agent = NetworkScannerAgent()
        result = agent.run(target="192.168.1.0/24", flags=["-sV", "-T4"])
    """

    def __init__(self) -> None:
        super().__init__(
            name="network_scanner",
            description="Discover hosts and open ports in a target network and classify associated risks.",
        )
        self.register_skill(NmapSkill())
        self.register_skill(PortAnalysisSkill())

    def run(self, target: str, flags: list[str] | None = None, timeout: int = 300) -> dict[str, Any]:
        """Scan *target* and return host/port discovery results with risk analysis.

        Args:
            target:  Hostname, IP address or CIDR range to scan.
            flags:   Optional nmap flags. Defaults to ``["-sV", "-T4"]``.
            timeout: Maximum scan time in seconds.

        Returns:
            A result dictionary containing:
            - ``"agent"``: ``"network_scanner"``
            - ``"status"``: ``"success"`` or ``"error"``
            - ``"target"``: the scanned target
            - ``"scan_output"``: raw nmap output
            - ``"port_analysis"``: risk analysis of discovered ports (if any)
        """
        self.logger.info("NetworkScannerAgent starting scan of '%s'", target)

        nmap_result = self.get_skill("nmap").execute(target=target, flags=flags, timeout=timeout)

        if nmap_result["status"] == "error":
            return {
                "agent": self.name,
                "status": "error",
                "target": target,
                "scan_output": nmap_result["result"],
                "port_analysis": None,
            }

        scan_output: str = nmap_result["result"]
        open_ports = self._parse_open_ports(scan_output)
        self.logger.info("Discovered %d open port(s) on '%s'", len(open_ports), target)

        port_analysis = None
        if open_ports:
            port_analysis = self.get_skill("port_analysis").execute(ports=open_ports)

        return {
            "agent": self.name,
            "status": "success",
            "target": target,
            "scan_output": scan_output,
            "port_analysis": port_analysis,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_open_ports(nmap_output: str) -> list[int]:
        """Extract open port numbers from nmap text output.

        Handles lines of the form ``80/tcp  open  http``.
        """
        ports: list[int] = []
        for line in nmap_output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "open" and "/" in parts[0]:
                port_str = parts[0].split("/")[0]
                try:
                    ports.append(int(port_str))
                except ValueError:
                    continue
        return sorted(set(ports))
