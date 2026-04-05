"""Port analysis skill – classifies open ports and identifies common services."""

from typing import Any

from .base_skill import BaseSkill

# Well-known port → (service name, risk level, notes)
_PORT_DB: dict[int, tuple[str, str, str]] = {
    21:   ("FTP",          "HIGH",   "Unencrypted file transfer; prefer SFTP/SCP"),
    22:   ("SSH",          "MEDIUM", "Secure shell; ensure key-based auth and no root login"),
    23:   ("Telnet",       "CRITICAL","Unencrypted remote access; must be disabled"),
    25:   ("SMTP",         "MEDIUM", "Mail relay; verify auth requirements to prevent open relay"),
    53:   ("DNS",          "MEDIUM", "Ensure recursion is limited to trusted clients"),
    80:   ("HTTP",         "MEDIUM", "Unencrypted web traffic; consider enforcing HTTPS"),
    110:  ("POP3",         "HIGH",   "Unencrypted mail retrieval; prefer POP3S"),
    135:  ("MS-RPC",       "HIGH",   "Windows RPC; often exploited, block from internet"),
    139:  ("NetBIOS",      "HIGH",   "Legacy Windows file sharing; should not be internet-facing"),
    143:  ("IMAP",         "HIGH",   "Unencrypted mail; prefer IMAPS"),
    443:  ("HTTPS",        "LOW",    "Encrypted web traffic"),
    445:  ("SMB",          "CRITICAL","Windows file sharing; frequently attacked, block from internet"),
    1433: ("MSSQL",        "HIGH",   "Microsoft SQL Server; should not be internet-facing"),
    1521: ("Oracle DB",    "HIGH",   "Oracle database; should not be internet-facing"),
    3306: ("MySQL",        "HIGH",   "MySQL database; should not be internet-facing"),
    3389: ("RDP",          "CRITICAL","Windows Remote Desktop; frequently attacked, restrict access"),
    5432: ("PostgreSQL",   "HIGH",   "PostgreSQL database; should not be internet-facing"),
    5900: ("VNC",          "CRITICAL","Virtual Network Computing; often unencrypted, restrict access"),
    6379: ("Redis",        "CRITICAL","Redis database; often unauthenticated by default"),
    8080: ("HTTP-Alt",     "MEDIUM", "Alternate HTTP port; verify TLS and access controls"),
    8443: ("HTTPS-Alt",    "LOW",    "Alternate HTTPS port"),
    9200: ("Elasticsearch","CRITICAL","Often unauthenticated; must not be internet-facing"),
    27017:("MongoDB",      "CRITICAL","Often unauthenticated by default; must not be internet-facing"),
}

_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class PortAnalysisSkill(BaseSkill):
    """Skill that analyses a list of open ports and identifies associated risks.

    Does not perform any network I/O – it classifies port data obtained from
    another skill (e.g. :class:`~skills.nmap_skill.NmapSkill`).

    Example::

        skill = PortAnalysisSkill()
        result = skill.execute(ports=[22, 80, 443, 3389, 27017])
    """

    def __init__(self) -> None:
        super().__init__(
            name="port_analysis",
            description="Classify open ports and identify associated security risks.",
        )

    def execute(self, ports: list[int]) -> dict[str, Any]:
        """Analyse a list of open port numbers.

        Args:
            ports: A list of open TCP/UDP port numbers (integers).

        Returns:
            ``{"skill": "port_analysis", "status": "success", "result": <analysis>}``

            *result* is a dict with:
            - ``"findings"``: list of per-port dicts (port, service, risk, notes)
            - ``"summary"``: counts by risk level
            - ``"critical_ports"``: list of CRITICAL ports found
        """
        if not isinstance(ports, list):
            raise TypeError(f"ports must be a list, got {type(ports)}")

        findings: list[dict[str, Any]] = []
        summary: dict[str, int] = {level: 0 for level in _RISK_ORDER}

        for port in ports:
            if not isinstance(port, int) or port < 0 or port > 65535:
                raise ValueError(f"Invalid port number: {port!r}")

            if port in _PORT_DB:
                service, risk, notes = _PORT_DB[port]
            else:
                service, risk, notes = "Unknown", "INFO", "No known risk classification"

            findings.append({
                "port": port,
                "service": service,
                "risk": risk,
                "notes": notes,
            })
            summary[risk] = summary.get(risk, 0) + 1

        findings.sort(key=lambda f: (_RISK_ORDER.get(f["risk"], 99), f["port"]))

        critical_ports = [f["port"] for f in findings if f["risk"] == "CRITICAL"]

        return {
            "skill": self.name,
            "status": "success",
            "result": {
                "findings": findings,
                "summary": {k: v for k, v in summary.items() if v > 0},
                "critical_ports": critical_ports,
            },
        }
