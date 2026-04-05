"""Tests for cybersecurity skills."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock
import json

from skills.nmap_skill import NmapSkill
from skills.cve_lookup_skill import CVELookupSkill
from skills.shodan_skill import ShodanSkill
from skills.port_analysis_skill import PortAnalysisSkill


# ---------------------------------------------------------------------------
# NmapSkill
# ---------------------------------------------------------------------------

class TestNmapSkill:
    def setup_method(self):
        self.skill = NmapSkill()

    def test_name_and_description(self):
        assert self.skill.name == "nmap"
        assert "nmap" in self.skill.description.lower()

    def test_empty_target_raises(self):
        with pytest.raises(ValueError, match="target must not be empty"):
            self.skill.execute(target="")

    def test_invalid_target_characters(self):
        for bad_char in [";", "&", "|", "`", "$"]:
            with pytest.raises(ValueError, match="Invalid character"):
                self.skill.execute(target=f"192.168.1.1{bad_char}rm -rf /")

    def test_disallowed_flag_raises(self):
        with pytest.raises(ValueError, match="not allowed"):
            self.skill.execute(target="192.168.1.1", flags=["--script=malicious"])

    def test_nmap_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = self.skill.execute(target="192.168.1.1")
        assert result["status"] == "error"
        assert "not found" in result["result"]

    def test_nmap_timeout(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=1)):
            result = self.skill.execute(target="192.168.1.1", timeout=1)
        assert result["status"] == "error"
        assert "timed out" in result["result"]

    def test_nmap_success(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "80/tcp  open  http\n443/tcp open  https\n"
        mock_proc.stderr = ""
        with patch("subprocess.run", return_value=mock_proc):
            result = self.skill.execute(target="192.168.1.1")
        assert result["status"] == "success"
        assert "80/tcp" in result["result"]

    def test_nmap_nonzero_exit(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Permission denied"
        with patch("subprocess.run", return_value=mock_proc):
            result = self.skill.execute(target="192.168.1.1")
        assert result["status"] == "error"
        assert "Permission denied" in result["result"]

    def test_callable_interface(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "output"
        mock_proc.stderr = ""
        with patch("subprocess.run", return_value=mock_proc):
            result = self.skill(target="10.0.0.1")
        assert result["status"] == "success"


# ---------------------------------------------------------------------------
# CVELookupSkill
# ---------------------------------------------------------------------------

class TestCVELookupSkill:
    def setup_method(self):
        self.skill = CVELookupSkill()

    def test_name(self):
        assert self.skill.name == "cve_lookup"

    def test_invalid_cve_id(self):
        with pytest.raises(ValueError, match="Invalid CVE"):
            self.skill.execute(cve_id="NOT-A-CVE")

    def test_valid_cve_id_formats(self):
        # Test case-insensitivity normalisation (mocked response)
        nvd_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                    "published": "2021-12-10T00:00:00",
                    "lastModified": "2022-01-01T00:00:00",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"},
                        }]
                    },
                }
            }]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(nvd_response).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = self.skill.execute(cve_id="cve-2021-44228")

        assert result["status"] == "success"
        assert result["result"]["id"] == "CVE-2021-44228"
        assert result["result"]["cvss_score"] == 10.0
        assert result["result"]["severity"] == "CRITICAL"
        assert result["result"]["description"] == "Log4Shell"

    def test_cve_not_found(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"vulnerabilities": []}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = self.skill.execute(cve_id="CVE-9999-9999")

        assert result["status"] == "error"
        assert "not found" in result["result"]

    def test_http_error(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url="", code=403, msg="Forbidden", hdrs=None, fp=None  # type: ignore[arg-type]
        )):
            result = self.skill.execute(cve_id="CVE-2021-44228")
        assert result["status"] == "error"
        assert "403" in result["result"]


# ---------------------------------------------------------------------------
# ShodanSkill
# ---------------------------------------------------------------------------

class TestShodanSkill:
    def test_no_api_key_raises(self):
        with pytest.raises(ValueError, match="API key"):
            ShodanSkill(api_key="")

    def test_name(self):
        skill = ShodanSkill(api_key="dummy")
        assert skill.name == "shodan"

    def test_host_action(self):
        skill = ShodanSkill(api_key="dummy")
        mock_data = {"ip_str": "8.8.8.8", "ports": [53, 443]}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = skill.execute(action="host", target="8.8.8.8")

        assert result["status"] == "success"
        assert result["result"]["ip_str"] == "8.8.8.8"

    def test_search_action(self):
        skill = ShodanSkill(api_key="dummy")
        mock_data = {"total": 1, "matches": [{"ip_str": "1.2.3.4"}]}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = skill.execute(action="search", query="apache port:443")

        assert result["status"] == "success"
        assert result["result"]["total"] == 1

    def test_missing_target_for_host_action(self):
        skill = ShodanSkill(api_key="dummy")
        result = skill.execute(action="host")
        assert result["status"] == "error"

    def test_missing_query_for_search_action(self):
        skill = ShodanSkill(api_key="dummy")
        result = skill.execute(action="search")
        assert result["status"] == "error"

    def test_unknown_action(self):
        skill = ShodanSkill(api_key="dummy")
        result = skill.execute(action="unknown_action")
        assert result["status"] == "error"
        assert "Unknown action" in result["result"]


# ---------------------------------------------------------------------------
# PortAnalysisSkill
# ---------------------------------------------------------------------------

class TestPortAnalysisSkill:
    def setup_method(self):
        self.skill = PortAnalysisSkill()

    def test_name(self):
        assert self.skill.name == "port_analysis"

    def test_known_critical_ports(self):
        result = self.skill.execute(ports=[445, 3389, 6379])
        assert result["status"] == "success"
        analysis = result["result"]
        assert set(analysis["critical_ports"]) == {445, 3389, 6379}

    def test_known_low_risk_port(self):
        result = self.skill.execute(ports=[443])
        assert result["status"] == "success"
        findings = result["result"]["findings"]
        assert findings[0]["risk"] == "LOW"
        assert findings[0]["service"] == "HTTPS"

    def test_unknown_port(self):
        result = self.skill.execute(ports=[12345])
        assert result["status"] == "success"
        findings = result["result"]["findings"]
        assert findings[0]["service"] == "Unknown"
        assert findings[0]["risk"] == "INFO"

    def test_empty_ports(self):
        result = self.skill.execute(ports=[])
        assert result["status"] == "success"
        assert result["result"]["findings"] == []

    def test_invalid_port_type(self):
        with pytest.raises(TypeError):
            self.skill.execute(ports="not_a_list")  # type: ignore[arg-type]

    def test_invalid_port_number(self):
        with pytest.raises(ValueError, match="Invalid port"):
            self.skill.execute(ports=[99999])

    def test_results_sorted_by_risk(self):
        result = self.skill.execute(ports=[443, 445, 22])
        findings = result["result"]["findings"]
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        orders = [risk_order[f["risk"]] for f in findings]
        assert orders == sorted(orders)

    def test_summary_counts(self):
        result = self.skill.execute(ports=[22, 80, 445])
        summary = result["result"]["summary"]
        # 22=MEDIUM, 80=MEDIUM, 445=CRITICAL
        assert summary.get("CRITICAL", 0) == 1
        assert summary.get("MEDIUM", 0) == 2
