# bKash Security Team Report

**To:** security@bkash.com (অথবা 16247 hotline)  
**Subject:** Active Malware Targeting bKash Users — C2 Server Identified  
**Date:** 2026-06-24  

---

## Email Body

---

To: security@bkash.com  
Subject: Android Banking Trojan Targeting bKash — Active C2: 65.20.66.209 — Victim Report + IOCs

---

Dear bKash Security Team,

I am reporting an active Android banking trojan that is specifically targeting bKash users. I have conducted a complete technical analysis and identified the active C2 server. A victim has already suffered a financial loss of BDT 20,000.

---

### Victim Incident

- **Transaction type:** Unauthorized bKash transfer
- **Amount lost:** Approximately BDT 20,000
- **Attack method:** Banking overlay + VPN traffic interception + SMS OTP theft
- **Device:** Android (Vivo phone)
- **Attack vector:** Facebook Advertisement → APK sideload
- **Device status:** Factory reset performed after incident

---

### Malware Targeting bKash

The malware specifically targets bKash through:

1. **VPN Interception** — Routes 100% of device traffic through attacker-controlled tunnel. All bKash API communications are intercepted.

2. **Overlay Attack** — Displays fake bKash UI on top of the real app. When user enters PIN, it is captured and sent to attacker.

3. **SMS OTP Theft** — Intercepts bKash OTP SMS before it reaches the user's SMS inbox.

4. **Accessibility Keylogger** — Captures every keystroke including bKash PIN entry.

The attacker receives: **bKash PIN + OTP** → initiates unauthorized transfer.

---

### Active C2 Server (Block Immediately)

```
IP:     65.20.66.209
Port:   80
URL:    http://65.20.66.209/yaarsa/private/yarsap_80541.php
Server: Microsoft-IIS/10.0 (Windows)
Host:   Vultr VPS
Status: ACTIVE (200 OK confirmed 2026-06-24)
```

**Recommendation:** Block all bKash API/app connections from this IP at your network level.

---

### Detection IOCs for Your Security Team

**Malware hashes:**
```
APK SHA256: cee63a18cf8f25fad52a8184fbc3a617618cba3760d55528aa02975cc140d61d
Package:    com.mmv.jnkh.rql7.tc8szt0d  (outer)
Package:    com.d9fe4v4.pmpgv.eai.uszaw  (payload)
```

**Behavioral signals (for fraud detection):**
- Transaction initiated from device with active VPN (route 0.0.0.0/0)
- OTP requested and immediately used (< 5 seconds) without user seeing it
- New device used within seconds of OTP delivery
- Transaction from IP associated with known C2: 65.20.66.209
- Accessibility Service from unknown app enabled on device

**Certificate:**
```
SHA1: 61ed377e85d386a8dfee6b864bd85b0bfaa5af81 (AOSP debug cert — malware indicator)
```

---

### Full Technical Report

https://github.com/Seizmann/govv-banking-trojan-analysis

---

### Requested Actions

1. **Fraud team:** Review transactions from affected account and assist with recovery
2. **Security team:** Add C2 IP `65.20.66.209` to blocklist
3. **Risk team:** Flag accounts with suspicious OTP patterns matching this attack
4. **User awareness:** Consider alerting bKash users about Facebook Ad APK scams

---

I am available to provide the raw APK sample, additional IOCs, or any other technical assistance needed to protect bKash users from this ongoing threat.

Regards,  
Security Researcher  
Reference: https://github.com/Seizmann/govv-banking-trojan-analysis

---
