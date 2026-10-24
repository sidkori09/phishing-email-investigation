# Incident Response & Root Cause Analysis Report

**Incident Title:** Spear-Phishing Campaign Leading to Credential Access & Endpoint Malware Execution  
**Incident Tracking ID:** `INC-2026-9041`  
**Date of Incident:** October 24, 2026  
**Status:** Closed / Remediated  
**Severity:** HIGH / CRITICAL  

---

## 1. Executive Summary
On October 24, 2026, at 08:14:22 UTC, a targeted spear-phishing email titled *"URGENT: Required Annual Payroll Policy Acknowledgment"* was delivered to an enterprise user (`j.smith@corp-finsec.com`). 

The email contained both a credential-harvesting phishing link and a malicious attachment disguised as a PDF document (`Payroll_Policy_2026.pdf.exe`). The user clicked the malicious link and subsequently executed the double-extension file, initiating C2 callbacks to `185.220.101.5`. 

Endpoint Detection and Response (EDR) triggered an alert upon identifying registry modifications for persistence (`WinSysUpdate`), prompting SOC intervention. The host was isolated at 08:35:10 UTC, credentials were reset, and C2 IPs were blocked enterprise-wide.

---

## 2. Technical Investigation & Findings

### 2.1 Email Authentication Analysis
- **Displayed Sender**: `hr-payroll@corp-finsec.com`
- **Actual Envelope Sender (Return-Path)**: `no-reply@secure-hr-update-portal.com`
- **Originating Server IP**: `198.51.100.45`
- **SPF Verification**: `SOFTFAIL` (IP `198.51.100.45` not authorized for `corp-finsec.com`)
- **DKIM Verification**: `FAIL` (Signature invalid / altered in transit)
- **DMARC Verification**: `FAIL`

### 2.2 Indicators of Compromise (IOCs)
| Category | Indicator | Context / Description |
| :--- | :--- | :--- |
| **Domain** | `auth-update-portal.net` | Registered 2 days prior to attack |
| **URL** | `http://login.corp-finsec.com.auth-update-portal.net/login.php` | Phishing Landing Page (Subdomain Typosquatting) |
| **IP Address** | `198.51.100.45` | Malicious Mail Relay Server |
| **C2 IP/Port** | `185.220.101.5:443` | Endpoint C2 Server Connection |
| **File Name** | `Payroll_Policy_2026.pdf.exe` | Double extension execution payload |
| **File SHA256** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Trojan/Dropper Payload |

---

## 3. What Went Wrong (Root Cause Analysis)

A thorough post-incident analysis identified four key security control failures that permitted this attack to reach execution:

### ❌ 1. Weak DMARC Policy (`p=none`)
* **Failure:** The enterprise DMARC policy was configured in monitoring mode (`p=none`).
* **Impact:** Although SPF and DKIM checks both failed at the Secure Email Gateway (SEG), the gateway allowed the email into the user inbox rather than rejecting (`p=reject`) or quarantining (`p=quarantine`) it.

### ❌ 2. Default Windows OS Extension Settings
* **Failure:** Windows endpoints were deployed with default GPO settings where *"Hide extensions for known file types"* was enabled.
* **Impact:** The malicious file `Payroll_Policy_2026.pdf.exe` was rendered on screen as `Payroll_Policy_2026.pdf` with standard executable icon spoofing, tricking the employee into running an executable.

### ❌ 3. Web Proxy Missing Domain-Age Controls
* **Failure:** The web proxy did not enforce blocking or isolation rules for newly registered domains (NRDs).
* **Impact:** The proxy permitted outgoing HTTP traffic to `auth-update-portal.net` (registered 48 hours prior) without warning or challenge.

### ❌ 4. Absence of Direct Email Reporting Plugin
* **Failure:** Users lacked an integrated "Report Phishing" button in Outlook.
* **Impact:** The victim attempted to forward the email manually to IT support, causing a 15-minute delay during which payload execution occurred.

---

## 4. MITRE ATT&CK Mapping

```text
+-----------------------------------------------------------------------+
| MITRE ATT&CK Phase       | Technique ID | Technique Name              |
+--------------------------+--------------+-----------------------------+
| Initial Access           | T1566.001    | Spearphishing Attachment    |
| Initial Access           | T1566.002    | Spearphishing Link          |
| Execution                | T1204.002    | User Execution: Malicious   |
| Defense Evasion          | T1036.007    | Masquerading: Double Ext.   |
| Persistence              | T1547.001    | Registry Run Keys / Startup |
| Credential Access        | T1056.003    | Credential Harvesting       |
| Command & Control        | T1071.001    | Web Protocols (HTTP/S)      |
+-----------------------------------------------------------------------+
```

---

## 5. Corrective & Preventative Action Plan

1. **Email Security Enforcement**:
   - Upgrade DMARC policy from `p=none` to `p=quarantine`, then `p=reject` within 30 days.
   - Configure SEG to strictly drop messages failing DKIM and SPF alignment simultaneously.
2. **Endpoint Hardening (GPO)**:
   - Deploy Active Directory GPO setting **"Show file name extensions"** across all workstations.
   - Restrict execution of binary file types (`.exe`, `.bat`, `.ps1`) originating from `%APPDATA%` and `%TEMP%` directories using AppLocker / WDAC.
3. **Web & Network Controls**:
   - Implement web proxy policies to automatically block or sandbox traffic directed toward domains registered within the last 30 days.
4. **User Awareness**:
   - Deploy standard 1-click Phishing Alert Button in Outlook toolbar.
   - Conduct targeted phishing training regarding urgent payroll/HR updates.