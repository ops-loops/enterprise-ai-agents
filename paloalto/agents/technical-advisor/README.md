# Palo Alto Networks — Technical Advisor Agent

AI custom agent that acts as a **Senior Security Engineer and Technical Advisor** specializing in Palo Alto Networks. It provides expert-level guidance on architectural design, daily operations, deep-dive troubleshooting, automation scripting, and release notes analysis across the full Palo Alto Networks product portfolio.

---

## Setup

This agent is defined in [`agent.md`](agent.md) and discovered by Claude Code or copilot from `.claude/agents/paloalto-technical-advisor.md` `.github/agents/paloalto-technical-advisor.md`

To use it, run the `/agents` command in Claude Code and select **paloalto-technical-advisor**, or invoke it directly with:

```
@agent-paloalto-technical-advisor <your question>
```

### Agent Configuration

| Field | Value |
|---|---|
| **Name** | `paloalto-technical-advisor` |
| **Model** | `opus` |
| **Tools** | `Read`, `Glob`, `Grep`, `WebFetch`, `WebSearch` |

---

## Scope of Expertise

| Domain | Products |
|---|---|
| Network Security | NGFW (PA-Series, VM-Series, CN-Series), PAN-OS, GlobalProtect |
| Centralized Management | Panorama, Strata Cloud Manager, AIOps for NGFW |
| Security Operations | Cortex XDR, Cortex XSIAM |
| Cloud Security | Prisma Cloud, Cortex Cloud |
| AI Security | Prisma AIRS (AI Runtime Security) |
| Automation & Scripting | PAN-OS Python SDK (`pan-os-python`), XML API, REST API |
| Threat Intelligence | Unit 42, WildFire, AutoFocus |

---

## Example Prompts

### Release Notes & Known Issues

```
"Summarize the known issues in PAN-OS 11.2.10. Flag anything Critical or High severity."
```

```
"What was fixed in PAN-OS 10.2.9 vs 10.2.8? Are there any HA or networking regressions I should know about?"
```

```
"We're still running PAN-OS 9.1.14. What are the known issues and what's the recommended upgrade path?"
```

### Python SDK Scripting

```
"Write a Python script using pan-os-python to list all security rules on a firewall that have zero hit counts."
```

```
"Generate a script to connect to Panorama and push a new address object to all firewalls in the CORP-EDGE device group."
```

```
"Write a Python script to check HA state on a list of firewalls and alert if any peer is not in sync."
```

### Troubleshooting & Operations

```
"My GlobalProtect users can't connect after upgrading to 11.2.4. Walk me through the most common causes and CLI commands to diagnose."
```

```
"What's the safest way to upgrade an active/passive HA pair from PAN-OS 10.2.9 to 11.2.10 with zero downtime?"
```

```
"Run me through the NGFW health check runbook for a Panorama-managed PA-5200."
```

### CVE & Security Advisories

```
"Look up CVE-2024-3400 — what's the impact, affected versions, and recommended remediation?"
```

```
"Are there any open Critical or High severity CVEs affecting PAN-OS 11.2.x right now?"
```

```
"We're running PAN-OS 10.2.9 — list all CVEs that have been patched in newer 10.2.x releases."
```

### Architecture & Design

```
"We're deploying Cortex XDR alongside our NGFW. What integrations should we configure and what data flows between the two products?"
```

```
"Explain the difference between Prisma Cloud and Cortex Cloud and help me decide which modules we need for our AWS environment."
```

---

## Guardrails

This agent follows strict operational guardrails defined in `agent.md`:

- **Never executes** commands against live devices — only generates and displays them for human review
- **Labels all output** with an AI-generated content warning
- **Extra caution** on destructive operations (deleting rules, HA failover, factory reset)
- **Never includes** real credentials — always uses placeholders
- **Cites sources** (official docs, KB articles, field experience) when referencing a specific fix

---

## Documentation & Support Links

| Resource | URL |
|---|---|
| PAN-OS Documentation | https://docs.paloaltonetworks.com/pan-os |
| Panorama Documentation | https://docs.paloaltonetworks.com/panorama |
| Cortex XDR Documentation | https://docs.paloaltonetworks.com/cortex/cortex-xdr |
| PAN-OS Python SDK | https://pan-os-python.readthedocs.io |
| PAN-OS Release Notes | https://docs.paloaltonetworks.com/pan-os |
| Preferred Releases Guidance | https://docs.paloaltonetworks.com/pan-os/preferred-releases |


## Key Terminology Glossary

Quick reference for acronyms used throughout the Palo Alto Networks portfolio (removed from `agent.md` — modern LLMs already know these terms, but humans may want a lookup).

| Term | Definition |
|---|---|
| **App-ID** | PAN-OS engine that identifies applications by behavior, not port/protocol |
| **ATP** | Advanced Threat Prevention — inline ML-based threat blocking subscription |
| **BIOC** | Behavioral Indicator of Compromise — XDR custom behavioral detection rule |
| **BPA / BPA+** | Best Practice Assessment — scored evaluation of firewall configuration |
| **CDR** | Cloud Detection and Response — runtime threat detection in cloud workloads |
| **CIEM** | Cloud Infrastructure Entitlement Management — IAM risk management |
| **CNAPP** | Cloud Native Application Protection Platform |
| **CSPM** | Cloud Security Posture Management |
| **CWPP** | Cloud Workload Protection Platform |
| **DAG** | Dynamic Address Group — auto-updated via tags |
| **Device Group** | Panorama logical grouping of firewalls that share policy |
| **EDL** | External Dynamic List — IP/URL/domain list from an external source |
| **GlobalProtect** | PAN-OS VPN and ZTNA solution for remote users |
| **HA** | High Availability — active/passive or active/active firewall pair |
| **PAN-OS** | The operating system running on all Palo Alto Networks NGFWs |
| **Panorama** | Centralized management platform for PAN-OS devices |
| **Precision AI** | Palo Alto Networks' AI/ML engine across all products |
| **Prisma AIRS** | AI Runtime Security platform |
| **Template / Template Stack** | Panorama construct for pushing network/device config |
| **Unit 42** | Palo Alto Networks' threat intelligence and IR division |
| **WildFire** | Cloud-based sandbox for automated malware analysis |
| **XDR** | Extended Detection and Response |
| **XQL** | Cortex Query Language for hunting in Cortex XDR |
| **XSIAM** | Cortex AI-powered SOC platform (SIEM + SOAR + XDR unified) |
| **ZTNA** | Zero Trust Network Access |

---

## For Human Engineers

### `agent.md` Section Index

| # | Section | Purpose |
|---|---|---|
| — | Knowledge Sources | Priority order of sources the agent cites |
| — | Agent Guardrails | 6 non-negotiable rules (never execute, label output, scope, destructive ops, credentials, behavior) |
| — | Scope of Expertise | Domain → product mapping |
| 1 | NGFW | Next-Generation Firewall — App-ID, User-ID, subscriptions, CLI, gotchas |
| 2 | Panorama | Centralized management, deployment options, commit-vs-push, gotchas |
| 3 | Cortex XDR | XDR capabilities, XQL query examples, gotchas |
| 4 | Prisma Cloud / Cortex Cloud | CSPM, CWPP, CDR, CIEM, DSPM, AI-SPM |
| 5 | Prisma AIRS | AI Runtime Security modules and threats |
| 6 | Release Notes | Version index, URL templates, workflow, output format, severity triage |
| 7 | PAN-OS Python SDK | Core concepts, script generation rules, official doc references |
| 8 | Cross-Product Integration Map | How products fit together |
| 9 | Operational Runbook Checklists | NGFW, Panorama, XDR, Cortex Cloud, Prisma AIRS |
| 10 | Documentation & Support Links | Official docs, community, training, automation |
| 11 | Workflow Index | Quick pointers for common user request types |

### How to use it

When reading [`agent.md`](agent.md) directly (not invoking the agent), use it as a structured reference:

- **Routine operations** — Use the runbook checklists in Section 10 (NGFW Health Check, Panorama Operations, XDR Incident Response, etc.)
- **Automation scripting** — Section 7 covers the `pan-os-python` SDK concepts and links to official examples. Never paste generated scripts into production without review.
- **Release notes & upgrade planning** — Section 6 contains the full version URL index and upgrade workflow
- **Architecture & deployment scoping** — Start with the Cross-Product Integration Map (Section 8), then use each product's "What It Is" and "Key Capabilities" sections to scope requirements
- **Avoiding common pitfalls** — Every product section has a "Known Gotchas & Field Notes" subsection — read these before deploying or upgrading

---

## Maintenance

This agent definition (`agent.md`) should be updated whenever:

- A new PAN-OS major version is released (add to the release notes URL index in Section 6)
- A PAN-OS version reaches End of Life (mark in the version table)
- A product is rebranded or merged (e.g., Prisma Cloud → Cortex Cloud)
- New subscriptions or modules are added to the Palo Alto portfolio
- The `pan-os-python` SDK releases a major version
- The release notes URL structure changes on docs.paloaltonetworks.com
- Significant field-discovered issues or gotchas are identified

---

## AI Collaboration & Diligence Statement

> In creating this project, I collaborated with Claude / Gemini to assist with drafting, research, editing, and content generation. I affirm that all AI-generated and co-created content underwent thorough review and evaluation. The final output accurately reflects my understanding, expertise, and intended meaning. While AI assistance was instrumental in the process, I maintain full responsibility for the content, its accuracy, and its presentation. This disclosure is made in the spirit of transparency and to acknowledge the role of AI in the creation process.