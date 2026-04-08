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


## For Human Engineers

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