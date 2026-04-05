"""Threat Intelligence Agent – enriches IoCs via Shodan and CVE lookups."""

from typing import Any

from skills.cve_lookup_skill import CVELookupSkill
from skills.shodan_skill import ShodanSkill
from .base_agent import BaseAgent


class ThreatIntelAgent(BaseAgent):
    """Agent that enriches Indicators of Compromise (IoCs) with threat intelligence.

    Supports two primary workflows:

    * **IP enrichment** – performs a Shodan host lookup for an IP address to
      reveal open ports, banners, and geolocation data.
    * **CVE enrichment** – fetches CVE metadata from the NIST NVD for a given
      CVE identifier.

    Example::

        agent = ThreatIntelAgent(shodan_api_key="YOUR_SHODAN_KEY")
        result = agent.run(action="enrich_ip", ioc="8.8.8.8")
        result = agent.run(action="enrich_cve", ioc="CVE-2021-44228")
    """

    def __init__(self, shodan_api_key: str | None = None, nvd_api_key: str | None = None) -> None:
        super().__init__(
            name="threat_intel",
            description="Enrich IoCs (IP addresses, CVEs) with threat intelligence from Shodan and NIST NVD.",
        )
        self.register_skill(CVELookupSkill(api_key=nvd_api_key))
        self._shodan_configured = bool(shodan_api_key)
        if shodan_api_key:
            self.register_skill(ShodanSkill(api_key=shodan_api_key))

    def run(self, action: str, ioc: str) -> dict[str, Any]:
        """Enrich an IoC with threat intelligence.

        Args:
            action: One of:
                    - ``"enrich_ip"``  – Shodan host lookup for an IP address
                    - ``"enrich_cve"`` – NVD CVE details lookup
            ioc:    The indicator value (IP address or CVE-ID).

        Returns:
            A result dictionary containing:
            - ``"agent"``: ``"threat_intel"``
            - ``"status"``: ``"success"`` or ``"error"``
            - ``"action"``: the requested action
            - ``"ioc"``:    the indicator value
            - ``"result"``: enrichment data
        """
        self.logger.info("ThreatIntelAgent action='%s' ioc='%s'", action, ioc)

        if action == "enrich_ip":
            return self._enrich_ip(ioc)

        if action == "enrich_cve":
            return self._enrich_cve(ioc)

        return {
            "agent": self.name,
            "status": "error",
            "action": action,
            "ioc": ioc,
            "result": f"Unknown action: {action!r}. Supported: 'enrich_ip', 'enrich_cve'",
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _enrich_ip(self, ip: str) -> dict[str, Any]:
        if not self._shodan_configured:
            return {
                "agent": self.name,
                "status": "error",
                "action": "enrich_ip",
                "ioc": ip,
                "result": "Shodan API key not configured; cannot enrich IP addresses",
            }
        shodan_result = self.get_skill("shodan").execute(action="host", target=ip)
        return {
            "agent": self.name,
            "status": shodan_result["status"],
            "action": "enrich_ip",
            "ioc": ip,
            "result": shodan_result["result"],
        }

    def _enrich_cve(self, cve_id: str) -> dict[str, Any]:
        cve_result = self.get_skill("cve_lookup").execute(cve_id=cve_id)
        return {
            "agent": self.name,
            "status": cve_result["status"],
            "action": "enrich_cve",
            "ioc": cve_id,
            "result": cve_result["result"],
        }
