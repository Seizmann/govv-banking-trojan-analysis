# BGD e-GOV CIRT Abuse Report

**To:** incident@cirt.gov.bd  
**CC:** info@cirt.gov.bd  
**Subject:** Active Android Banking Malware Targeting Bangladeshi bKash Users — C2 IP: 65.20.66.209  
**Date:** 2026-06-24  

---

## Email Body

---

To: incident@cirt.gov.bd  
Subject: Active Android Banking Malware C2 — bKash Account Compromise — 65.20.66.209

---

Dear BGD e-GOV CIRT Team,

I am reporting an active Android banking trojan that is currently targeting Bangladeshi mobile financial service users, specifically bKash account holders. A confirmed financial loss of approximately BDT 20,000 has occurred in one documented case.

I have completed a full technical analysis of the malware and identified the active C2 (Command & Control) server.

---

### Incident Summary

**What happened:**  
A victim's family member in Bangladesh installed a malicious Android application from a Facebook Advertisement. The ad presented the app as "World Cup Live Free TV." After installation, BDT 20,000 was stolen from their bKash account through unauthorized transactions.

**Malware type:** Android Banking Trojan (family: Android/Btmob)  
**Distribution:** Facebook Advertisements  
**Primary target:** bKash mobile financial service users  
**Secondary targets:** Nagad, Rocket, other Bangladeshi MFS platforms  

---

### Confirmed C2 Server

| Field | Value |
|-------|-------|
| **IP Address** | `65.20.66.209` |
| **Port** | `80` |
| **URL** | `http://65.20.66.209/yaarsa/private/yarsap_80541.php` |
| **Server Software** | Microsoft-IIS/10.0 |
| **Hosting Provider** | Vultr VPS (The Constant Company, LLC) |
| **Status** | **ACTIVE** — 200 OK confirmed |
| **Confirmed By** | ANY.RUN sandbox + Suricata IDS (SID 84001342) |

---

### Malware Technical Details

**Sample:**
- SHA256: `cee63a18cf8f25fad52a8184fbc3a617618cba3760d55528aa02975cc140d61d`
- Package: `com.mmv.jnkh.rql7.tc8szt0d`  
- App name: "GOVV" (with invisible Unicode characters)
- Distributed as: APK sideload via Facebook Ad

**Attack Chain:**
1. Facebook Ad → APK download (bypassing Google Play)
2. 3-stage dropper: Stub APK → Injected DEX → Banking Trojan APK
3. VPN service activated → ALL device traffic intercepted
4. Accessibility Service abused → Banking overlay deployed
5. SMS OTP intercepted → bKash PIN captured → Unauthorized transactions

**Confirmed Capabilities:**
- VPN traffic interception (addRoute 0.0.0.0/0 — 100% of traffic)
- Banking app overlay (fake bKash/Nagad/Rocket UI)
- SMS OTP theft
- Keystroke logging
- Live screen capture and streaming
- Remote shell access (Telnet/terminal)
- Cryptocurrency mining on victim device
- Factory reset capability
- Phone cloning

---

### Evidence

**Dynamic Analysis (ANY.RUN):**
```
Task URL: https://app.any.run/tasks/b30ccc1a-83bd-4347-baaa-8b7d7a35452f

Captured HTTP Request:
  HEAD /yaarsa/private/yarsap_80541.php HTTP/1.1
  Host: 65.20.66.209
  User-Agent: Dalvik/2.1.0 (Linux; U; Android 14; Galaxy_S10 ...)
  → Response: 200 OK | Server: Microsoft-IIS/10.0
```

**Suricata IDS Alert:**
```
"MALWARE [ANY.RUN] Android/Btmob activity observed in HTTP request"
SID: 84001342; rev: 1
MITRE: T1071 (Application Layer Protocol)
```

**VirusTotal:**
- 5/64 AV engines detected
- File drops confirmed: payload.dex, b.apk, installing.html

---

### Full Technical Report

Complete analysis published at:  
**https://github.com/Seizmann/govv-banking-trojan-analysis**

Includes:
- Complete static analysis (DEX bytecode reversal)
- Encryption scheme reverse-engineered
- 30+ C2 commands decoded
- YARA detection rules
- Full IOC list
- Decrypted payload analysis

---

### Requested Actions

1. **Block** C2 IP `65.20.66.209` at Bangladesh internet gateway level
2. **Notify** bKash, Nagad, Rocket security teams with IOCs
3. **Alert** Facebook Bangladesh about the ad distribution vector
4. **Coordinate** with Vultr (abuse@constant.com) for server takedown
5. **Warn** Bangladeshi mobile banking users about this threat

---

### Other Reports Filed

- Vultr abuse team (abuse@constant.com) — hosting takedown request
- bKash security (16247 hotline)
- vivoglobal.com abuse team — related infrastructure
- VirusTotal — sample submitted

---

Bangladeshi CIRT's intervention is critical to protect mobile financial service users from ongoing financial losses. Please treat this as high priority.

I am available to provide additional technical evidence, raw sample files (via secure channel), or clarification on any aspect of the analysis.

Regards,  
Security Researcher  
GitHub: https://github.com/Seizmann/govv-banking-trojan-analysis  

---
