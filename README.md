# enterprise-ai-agents

A Python framework of composable AI **agents** and **skills** for enterprise cybersecurity tools.

---

## Overview

```
enterprise-ai-agents/
├── agents/
│   ├── base_agent.py               # Abstract base class for all agents
│   ├── network_scanner_agent.py    # Host/port discovery + risk analysis
│   ├── vulnerability_scanner_agent.py  # CVE correlation for open ports
│   └── threat_intel_agent.py       # IP & CVE enrichment (Shodan + NVD)
├── skills/
│   ├── base_skill.py               # Abstract base class for all skills
│   ├── nmap_skill.py               # Nmap network scanner wrapper
│   ├── cve_lookup_skill.py         # NIST NVD CVE lookup (REST API v2)
│   ├── shodan_skill.py             # Shodan host + search queries
│   └── port_analysis_skill.py      # Port risk classification (no I/O)
└── tests/
    ├── test_base.py
    ├── test_skills.py
    └── test_agents.py
```

---

## Concepts

### Skills

Skills are atomic, reusable capabilities that wrap a single tool or API call.
Every skill extends `BaseSkill` and exposes a single `execute(**kwargs)` method
that returns a structured dictionary:

```python
{
    "skill": "<skill_name>",
    "status": "success" | "error",
    "result": <output>
}
```

Skills are callable directly or via an agent:

```python
from skills.nmap_skill import NmapSkill

skill = NmapSkill()
result = skill(target="192.168.1.1", flags=["-sV", "-T4"])
```

### Agents

Agents orchestrate one or more skills to accomplish a higher-level task.
Every agent extends `BaseAgent` and exposes a `run(**kwargs)` method.

```python
{
    "agent": "<agent_name>",
    "status": "success" | "error",
    ...   # agent-specific keys
}
```

---

## Agents

### NetworkScannerAgent

Discovers hosts and open ports in a target network, then classifies their
risk posture.

```python
from agents.network_scanner_agent import NetworkScannerAgent

agent = NetworkScannerAgent()
result = agent.run(target="192.168.1.0/24", flags=["-sV", "-T4"])
print(result["port_analysis"])
```

**Skills used:** `NmapSkill`, `PortAnalysisSkill`

---

### VulnerabilityScannerAgent

Takes a list of open ports, classifies risk levels, and correlates services
with known CVEs from the NIST National Vulnerability Database.

```python
from agents.vulnerability_scanner_agent import VulnerabilityScannerAgent

agent = VulnerabilityScannerAgent(nvd_api_key="optional")
result = agent.run(ports=[22, 80, 443, 445, 3389])
print(result["cve_findings"])
print(result["critical_ports"])
```

**Skills used:** `PortAnalysisSkill`, `CVELookupSkill`

---

### ThreatIntelAgent

Enriches Indicators of Compromise (IoCs) with threat intelligence:

* **IP enrichment** – Shodan host lookup revealing open ports, banners, and
  geolocation.
* **CVE enrichment** – NIST NVD metadata including CVSS score and severity.

```python
from agents.threat_intel_agent import ThreatIntelAgent

agent = ThreatIntelAgent(shodan_api_key="YOUR_KEY")

# Enrich an IP address
result = agent.run(action="enrich_ip", ioc="8.8.8.8")

# Enrich a CVE
result = agent.run(action="enrich_cve", ioc="CVE-2021-44228")
print(result["result"]["severity"])   # CRITICAL
```

**Skills used:** `CVELookupSkill`, `ShodanSkill` (when API key provided)

---

## Skills

| Skill | Description | External dependency |
|---|---|---|
| `NmapSkill` | Nmap network scan | `nmap` binary on PATH |
| `CVELookupSkill` | NIST NVD CVE details | HTTPS to `services.nvd.nist.gov` |
| `ShodanSkill` | Shodan host & search | Shodan API key + HTTPS |
| `PortAnalysisSkill` | Port risk classification | None (pure Python) |

---

## Adding a new skill

```python
from skills.base_skill import BaseSkill

class MySkill(BaseSkill):
    def __init__(self):
        super().__init__(name="my_skill", description="Does something useful")

    def execute(self, target: str, **kwargs):
        # ... call your tool / API ...
        return {"skill": self.name, "status": "success", "result": {...}}
```

Register it with any agent:

```python
agent.register_skill(MySkill())
```

---

## Requirements

* Python 3.10+
* `nmap` binary on `PATH` (only required by `NmapSkill`)
* Shodan API key (only required by `ShodanSkill`)

Install dev dependencies:

```bash
pip install -r requirements.txt
```

## Running tests

```bash
python -m pytest tests/ -v
```