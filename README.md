# Phishing Email Investigation & Incident Response

A SOC analyst portfolio project demonstrating how to investigate a suspected spear-phishing email by reviewing email headers, identifying suspicious links and attachments, correlating SIEM/EDR events, mapping attacker behavior to MITRE ATT&CK, and documenting incident response actions.

> **Scenario note:** This repository presents a simulated incident for learning and portfolio purposes. Treat the email, domains, indicators, logs, and incident narrative as lab material—not as proof of a real-world compromise.

## Incident Overview

| Field | Details |
|---|---|
| Incident ID | `INC-2026-9041` |
| Scenario | Payroll-themed spear-phishing email |
| Severity in scenario | High / Critical |
| Main risk | Credential harvesting and execution of a suspicious attachment |
| Investigation approach | Email analysis + SIEM/EDR log correlation + incident reporting |
| Status in report | Closed / Remediated (simulated scenario) |

The scenario begins with an urgent payroll-policy email that appears to come from an internal HR address. The message uses a mismatched return-path, fails SPF/DKIM/DMARC checks, links to a suspicious login page, and includes a double-extension attachment named `Payroll_Policy_2026.pdf.exe`.

The accompanying event timeline describes the link being visited, the attachment being written and executed, a registry Run-key modification, an outbound connection, a SIEM alert, and host isolation.

## Investigation Workflow

1. **Inspect the email:** Review sender information, `Return-Path`, subject, timestamps, and authentication results.
2. **Identify suspicious indicators:** Extract URLs, domains, IP addresses, and attachment names; note double extensions and executable file types.
3. **Correlate telemetry:** Align email gateway, web proxy, endpoint detection and response (EDR), and SIEM events into a timeline.
4. **Assess impact and severity:** Connect the email interaction to endpoint execution, persistence, and possible command-and-control activity.
5. **Map techniques:** Relate the observed behavior in the scenario to MITRE ATT&CK techniques.
6. **Recommend response and prevention:** Document containment, credential reset, indicator blocking, email-authentication improvements, endpoint hardening, and user-reporting improvements.

## Repository Contents

| File | Purpose |
|---|---|
| [`incident_investigation_report.md`](incident_investigation_report.md) | Executive summary, technical findings, root-cause analysis, MITRE ATT&CK mapping, and corrective actions |
| [`raw_suspicious_email_sample.md`](raw_suspicious_email_sample.md) | Simulated suspicious email with headers, body, link, and attachment metadata |
| [`correlated_siem_edr_logs.md`](correlated_siem_edr_logs.md) | Timestamped email gateway, proxy, EDR, and SIEM events for timeline correlation |
| [`email_parser_script.py`](email_parser_script.py) | Python script to parse a raw `.eml` file and print selected headers, authentication results, URLs, and attachment details |

## Python Email Parser

### Requirements

- Python 3.8 or later (uses Python's standard library only)
- A raw email file saved in `.eml` format

No third-party packages are required by the current script.

### Run the script

From the repository directory:

```bash
python email_parser_script.py path/to/sample.eml
```

On Windows, for example:

```powershell
py .\email_parser_script.py .\sample.eml
```

The script prints:
- Subject, sender, recipient, return path, and date
- SPF, DKIM, and DMARC results when present in the `Authentication-Results` header
- URLs found in HTML email content
- Attachment names and MIME types
- A warning for filenames with multiple dots or executable-like extensions

**Input-format note:** `raw_suspicious_email_sample.md` is a human-readable Markdown representation of the example email, not a raw `.eml` file. The parser expects a properly formatted `.eml` input. Save or export an authorized sample as `.eml` before running the parser. Do not open attachments or visit suspicious links during analysis.

## Key Findings in the Simulated Case

- The displayed sender and actual return path do not align.
- SPF is reported as `SOFTFAIL`; DKIM and DMARC are reported as `FAIL`.
- The message uses urgency and payroll-related language to pressure the recipient.
- The link uses a lookalike login hostname.
- The attachment name uses a misleading `.pdf.exe` double extension.
- The timeline records endpoint persistence behavior and an outbound connection after execution.
- The SIEM alert correlates persistence creation with a connection to an external IP address.

These are findings within the provided scenario and should not be interpreted as independently verified threat intelligence.

## Incident Response Recommendations

- Isolate the affected endpoint and preserve relevant logs and evidence.
- Reset potentially exposed credentials and review authentication activity.
- Block or investigate confirmed malicious domains, URLs, IPs, and file hashes using approved security controls.
- Enforce aligned SPF, DKIM, and DMARC policies; consider a staged move toward quarantine/reject after validating legitimate mail flows.
- Show file extensions on Windows endpoints and restrict risky execution locations with application control.
- Apply web controls for newly registered or suspicious domains where appropriate.
- Provide a one-click phishing-reporting mechanism and targeted awareness training.
- Validate detections and response steps in an authorized lab before production use.

## MITRE ATT&CK References

The incident report maps the simulated behavior to these techniques:

| Technique | ID | Scenario context |
|---|---|---|
| Spearphishing Attachment | `T1566.001` | Malicious attachment delivered by email |
| Spearphishing Link | `T1566.002` | Credential-harvesting link |
| User Execution: Malicious File | `T1204.002` | User executes the attachment |
| Masquerading: Double File Extension | `T1036.007` | `.pdf.exe` filename |
| Registry Run Keys / Startup Folder | `T1547.001` | Registry-based persistence |
| Web Protocols | `T1071.001` | HTTP/S command-and-control behavior |

Technique mapping is based on the simulated evidence documented in this repository.

## Skills Demonstrated

- Phishing email triage and header analysis
- SPF, DKIM, and DMARC interpretation
- IOC identification and documentation
- SIEM/EDR log correlation and incident timeline building
- Endpoint persistence and network-connection investigation
- MITRE ATT&CK mapping
- Python scripting for email artifact inspection
- Incident reporting, containment, and remediation recommendations

## Limitations

- The incident evidence is a simulated portfolio scenario.
- The parser is a lightweight helper, not a full email-forensics platform; results depend on the input email's structure and headers.
- Authentication results are read from the email's `Authentication-Results` header; the script does not independently validate SPF, DKIM, or DMARC.
- The current script prints results to the terminal and does not produce a JSON report, despite importing the `json` module.
- A hash or indicator shown in sample material should be validated before operational use.

## Safe Use

Use this repository for education, defensive analysis, and authorized lab exercises only. Do not execute suspicious attachments, submit real confidential emails to public services, or visit potentially malicious URLs on a production device. Sanitize sensitive information before publishing evidence.

---

**Project type:** Cybersecurity / SOC Analyst Portfolio  
**Focus:** Phishing Investigation · Incident Response · SIEM/EDR Correlation · Python
