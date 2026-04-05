"""Tests for cybersecurity agents."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import MagicMock, patch
import json

from agents.network_scanner_agent import NetworkScannerAgent
from agents.vulnerability_scanner_agent import VulnerabilityScannerAgent
from agents.threat_intel_agent import ThreatIntelAgent


# ---------------------------------------------------------------------------
# NetworkScannerAgent
# ---------------------------------------------------------------------------

class TestNetworkScannerAgent:
    def setup_method(self):
        self.agent = NetworkScannerAgent()

    def test_name(self):
        assert self.agent.name == "network_scanner"

    def test_has_required_skills(self):
        assert "nmap" in self.agent.skills
        assert "port_analysis" in self.agent.skills

    def test_run_success(self):
        nmap_output = "80/tcp  open  http\n443/tcp open  https\n"
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = nmap_output
        mock_proc.stderr = ""

        with patch("subprocess.run", return_value=mock_proc):
            result = self.agent.run(target="192.168.1.1")

        assert result["status"] == "success"
        assert result["agent"] == "network_scanner"
        assert result["target"] == "192.168.1.1"
        assert "scan_output" in result
        assert result["port_analysis"] is not None
        assert "findings" in result["port_analysis"]["result"]

    def test_run_nmap_error_propagates(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = self.agent.run(target="10.0.0.1")

        assert result["status"] == "error"
        assert result["port_analysis"] is None

    def test_run_no_open_ports(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Host: 192.168.1.1\nNo open ports found\n"
        mock_proc.stderr = ""

        with patch("subprocess.run", return_value=mock_proc):
            result = self.agent.run(target="192.168.1.1")

        assert result["status"] == "success"
        assert result["port_analysis"] is None

    def test_parse_open_ports(self):
        output = (
            "PORT      STATE SERVICE\n"
            "22/tcp    open  ssh\n"
            "80/tcp    open  http\n"
            "443/tcp   open  https\n"
            "8080/tcp  closed http-proxy\n"
        )
        ports = NetworkScannerAgent._parse_open_ports(output)
        assert ports == [22, 80, 443]

    def test_parse_open_ports_deduplicates(self):
        output = "22/tcp open ssh\n22/tcp open ssh\n"
        ports = NetworkScannerAgent._parse_open_ports(output)
        assert ports == [22]


# ---------------------------------------------------------------------------
# VulnerabilityScannerAgent
# ---------------------------------------------------------------------------

class TestVulnerabilityScannerAgent:
    def setup_method(self):
        self.agent = VulnerabilityScannerAgent()

    def test_name(self):
        assert self.agent.name == "vulnerability_scanner"

    def test_has_required_skills(self):
        assert "port_analysis" in self.agent.skills
        assert "cve_lookup" in self.agent.skills

    def test_run_no_cves_for_safe_ports(self):
        result = self.agent.run(ports=[443])
        assert result["status"] == "success"
        assert result["cve_findings"] == []

    def test_run_with_critical_ports(self):
        # Ports 445 (SMB) and 3389 (RDP) have associated CVEs in the map
        # We mock the CVE lookup to avoid network calls
        cve_resp = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2017-0144",
                    "descriptions": [{"lang": "en", "value": "EternalBlue"}],
                    "published": "2017-03-14",
                    "lastModified": "2017-03-14",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                    },
                }
            }]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(cve_resp).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = self.agent.run(ports=[445])

        assert result["status"] == "success"
        assert 445 in result["critical_ports"]
        cve_ids = [f["cve_id"] for f in result["cve_findings"]]
        assert "CVE-2017-0144" in cve_ids

    def test_run_cve_lookup_failure_does_not_abort(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url="", code=503, msg="Service Unavailable", hdrs=None, fp=None  # type: ignore[arg-type]
        )):
            result = self.agent.run(ports=[445])

        assert result["status"] == "success"
        for finding in result["cve_findings"]:
            assert finding["cve_status"] == "error"


# ---------------------------------------------------------------------------
# ThreatIntelAgent
# ---------------------------------------------------------------------------

class TestThreatIntelAgent:
    def test_name(self):
        agent = ThreatIntelAgent()
        assert agent.name == "threat_intel"

    def test_shodan_not_configured_without_key(self):
        agent = ThreatIntelAgent()
        assert "shodan" not in agent.skills

    def test_shodan_configured_with_key(self):
        agent = ThreatIntelAgent(shodan_api_key="dummy")
        assert "shodan" in agent.skills

    def test_enrich_ip_without_key(self):
        agent = ThreatIntelAgent()
        result = agent.run(action="enrich_ip", ioc="8.8.8.8")
        assert result["status"] == "error"
        assert "Shodan" in result["result"]

    def test_enrich_ip_with_key(self):
        agent = ThreatIntelAgent(shodan_api_key="dummy")
        mock_data = {"ip_str": "8.8.8.8", "ports": [53]}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = agent.run(action="enrich_ip", ioc="8.8.8.8")

        assert result["status"] == "success"
        assert result["ioc"] == "8.8.8.8"
        assert result["result"]["ip_str"] == "8.8.8.8"

    def test_enrich_cve(self):
        agent = ThreatIntelAgent()
        nvd_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
                    "published": "2021-12-10",
                    "lastModified": "2022-01-01",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]
                    },
                }
            }]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(nvd_response).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = agent.run(action="enrich_cve", ioc="CVE-2021-44228")

        assert result["status"] == "success"
        assert result["action"] == "enrich_cve"
        assert result["result"]["severity"] == "CRITICAL"

    def test_unknown_action(self):
        agent = ThreatIntelAgent()
        result = agent.run(action="unknown", ioc="anything")
        assert result["status"] == "error"
        assert "Unknown action" in result["result"]
