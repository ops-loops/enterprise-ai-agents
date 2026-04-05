"""Shodan skill – queries the Shodan Internet Intelligence API."""

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .base_skill import BaseSkill

_SHODAN_API_BASE = "https://api.shodan.io"


class ShodanSkill(BaseSkill):
    """Skill that queries the Shodan API for host and search intelligence.

    Requires a valid Shodan API key.  The free-tier key supports host lookups
    and basic search; a paid membership unlocks the full search API.

    Example::

        skill = ShodanSkill(api_key="YOUR_SHODAN_KEY")
        result = skill.execute(action="host", target="8.8.8.8")
        result = skill.execute(action="search", query="apache port:443")
    """

    def __init__(self, api_key: str, timeout: int = 15) -> None:
        super().__init__(
            name="shodan",
            description="Query the Shodan API for host and internet-wide search intelligence.",
        )
        if not api_key:
            raise ValueError("A Shodan API key is required")
        self._api_key = api_key
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        all_params = {"key": self._api_key}
        if params:
            all_params.update(params)
        url = f"{_SHODAN_API_BASE}{path}?{urllib.parse.urlencode(all_params)}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Shodan API error {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error: {exc.reason}") from exc

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------

    def execute(self, action: str, target: str | None = None, query: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Perform a Shodan query.

        Args:
            action: One of ``"host"`` or ``"search"``.
            target: IP address for a host lookup (required when action is ``"host"``).
            query:  Shodan search query (required when action is ``"search"``).
            **kwargs: Additional parameters forwarded to the Shodan API
                      (e.g. ``page=1``, ``minify=True``).

        Returns:
            ``{"skill": "shodan", "status": "success"/"error", "result": <data>}``
        """
        try:
            if action == "host":
                if not target:
                    raise ValueError("'target' is required for action='host'")
                data = self._get(f"/shodan/host/{urllib.parse.quote(target, safe='.')}")
                return {"skill": self.name, "status": "success", "result": data}

            if action == "search":
                if not query:
                    raise ValueError("'query' is required for action='search'")
                params: dict[str, str] = {"query": query}
                if "page" in kwargs:
                    params["page"] = str(kwargs["page"])
                if "minify" in kwargs:
                    params["minify"] = str(kwargs["minify"]).lower()
                data = self._get("/shodan/host/search", params=params)
                return {"skill": self.name, "status": "success", "result": data}

            raise ValueError(f"Unknown action: {action!r}. Supported: 'host', 'search'")

        except (ValueError, RuntimeError) as exc:
            return {"skill": self.name, "status": "error", "result": str(exc)}
