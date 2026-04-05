"""CVE lookup skill – queries the NIST NVD REST API for CVE details."""

import urllib.error
import urllib.parse
import urllib.request
import json
import re
from typing import Any

from .base_skill import BaseSkill

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVELookupSkill(BaseSkill):
    """Skill that looks up CVE details from the NIST National Vulnerability Database.

    Uses the NVD REST API v2 (no API key required for basic lookups, though
    providing one via *api_key* raises the rate limit).

    Example::

        skill = CVELookupSkill()
        result = skill.execute(cve_id="CVE-2021-44228")
    """

    def __init__(self, api_key: str | None = None, timeout: int = 15) -> None:
        super().__init__(
            name="cve_lookup",
            description="Look up CVE details from the NIST National Vulnerability Database.",
        )
        self._api_key = api_key
        self._timeout = timeout

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------

    def execute(self, cve_id: str) -> dict[str, Any]:
        """Fetch details for a single CVE identifier.

        Args:
            cve_id: A CVE identifier such as ``"CVE-2021-44228"``.

        Returns:
            ``{"skill": "cve_lookup", "status": "success"/"error", "result": <cve_data>}``

            On success *result* is a dictionary with keys:
            - ``"id"``
            - ``"description"``
            - ``"cvss_score"`` (float or None)
            - ``"severity"`` (str or None)
            - ``"published"``
            - ``"last_modified"``
        """
        cve_id = cve_id.strip().upper()
        if not _CVE_RE.match(cve_id):
            raise ValueError(f"Invalid CVE identifier: {cve_id!r}")

        params = {"cveId": cve_id}
        url = f"{_NVD_API_BASE}?{urllib.parse.urlencode(params)}"

        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        self.logger.info("Querying NVD for %s", cve_id)

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return {"skill": self.name, "status": "error", "result": f"HTTP {exc.code}: {exc.reason}"}
        except urllib.error.URLError as exc:
            return {"skill": self.name, "status": "error", "result": str(exc.reason)}
        except TimeoutError:
            return {"skill": self.name, "status": "error", "result": "Request timed out"}

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"skill": self.name, "status": "error", "result": f"CVE {cve_id} not found in NVD"}

        cve = vulnerabilities[0].get("cve", {})
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            None,
        )

        cvss_score: float | None = None
        severity: str | None = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
                break

        return {
            "skill": self.name,
            "status": "success",
            "result": {
                "id": cve.get("id", cve_id),
                "description": description,
                "cvss_score": cvss_score,
                "severity": severity,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
            },
        }
