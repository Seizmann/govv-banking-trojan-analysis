# Vultr Abuse Report — Malware C2 Server

**To:** abuse@constant.com  
**Subject:** Malware C2 Server Hosting on Vultr VPS — 65.20.66.209  
**Date:** 2026-06-24  

---

## Email Body

---

To: abuse@constant.com  
Subject: Active Android Banking Malware C2 Server — IP 65.20.66.209 — Immediate Takedown Request

---

Dear Vultr / The Constant Company Abuse Team,

I am writing to report an active Command & Control (C2) server for an Android banking trojan that is currently hosted on your infrastructure. The server has been confirmed live and is actively being used to steal financial credentials from mobile banking users in Bangladesh.

---

**REPORTED IP:** 65.20.66.209  
**REPORTED URL:** http://65.20.66.209/yaarsa/private/yaarsa_80541.php  
**REVERSE DNS:** 65.20.66.209.vultrusercontent.com  
**CONFIRMED LIVE:** Yes (HTTP 200 OK response at time of report)  

---

### Summary of Incident

A family member's Android device was compromised by a malware application distributed via Facebook Advertisements, disguised as "World Cup Live Free TV." Following installation, approximately BDT 20,000 (~USD 180) was stolen from their bKash mobile financial account through unauthorized transactions.

I conducted a full static and dynamic analysis of the malware sample.

---

### Technical Evidence

**1. Malware Sample**

| Field | Value |
|-------|-------|
| Filename | ufvx301ymvxzkw.apk |
| SHA256 | cee63a18cf8f25fad52a8184fbc3a617618cba3760d55528aa02975cc140d61d |
| Package | com.mmv.jnkh.rql7.tc8szt0d |
| Malware Family | Android/Btmob (Suricata IDS confirmed) |
| Detection | 5/64 AV engines on VirusTotal |

**2. C2 Connection (Dynamic Analysis — ANY.RUN Sandbox)**

The malware was detonated in a controlled sandbox environment (ANY.RUN). The following HTTP request was captured and flagged by Suricata IDS (SID: 84001342):

```
Request:
  Method:  HEAD
  URL:     /yaarsa/private/yarsap_80541.php
  Host:    65.20.66.209
  User-Agent: Dalvik/2.1.0 (Linux; U; Android 14; Galaxy_S10 Build/UP1A.231105.001.94835f2d)
  Connection: Keep-Alive

Response:
  Status:  200 OK
  Server:  Microsoft-IIS/10.0
  Date:    Wed, 24 Jun 2026 05:25:21 GMT
```

Suricata Alert: **"MALWARE [ANY.RUN] Android/Btmob activity observed in HTTP request"**  
MITRE ATT&CK: **T1071 — Application Layer Protocol**

**3. Static Analysis Confirmation**

Reverse engineering of the malware's DEX bytecode confirmed the C2 path through string decryption:

- C2 endpoint: `/yaarsa/private/yarsap_80541.php`
- Error log: `/yaarsa/private/log_error.php`
- Protocol: WebSocket over HTTP on port 80

**4. Malware Capabilities (Confirmed)**

This malware is a sophisticated 3-stage banking trojan with the following confirmed capabilities:
- VPN-based interception of all device network traffic
- Banking app overlay attacks (bKash, Nagad, Rocket)
- SMS OTP theft
- Keystroke logging via Accessibility Service
- Live screen capture and streaming
- Cryptocurrency mining
- Remote shell access
- Device factory reset capability
- Full Remote Access Trojan (RAT) functionality

**5. ANY.RUN Analysis Report**

Task URL: https://app.any.run/tasks/c50e0613-6703-4fad-92ff-4be747d4d0a9

---

### Requested Actions

1. **Immediate suspension** of VPS at IP 65.20.66.209
2. **Preservation of server logs** for law enforcement purposes
3. **Notification** if you identify the account holder

---

### Additional Reporting

This incident has also been reported to:
- Bangladesh Bank Cybersecurity Division
- BGD e-GOV CIRT (Bangladesh Computer Incident Response Team)
- bKash Security Team
- VirusTotal (sample submitted)
- vivoglobal.com abuse team (related infrastructure)

---

### Evidence Package

Full technical analysis available at:  
https://github.com/Seizmann/govv-banking-trojan-analysis

Includes:
- Complete static analysis with DEX bytecode evidence
- Dynamic analysis captures
- YARA detection rules
- Full IOC list

---

Thank you for your prompt attention to this matter. Every hour this server remains active puts additional mobile banking users at risk.

Please confirm receipt of this report and provide a ticket/case number if available.

Regards,  
Security Researcher  
GitHub: https://github.com/Seizmann/govv-banking-trojan-analysis  

---
