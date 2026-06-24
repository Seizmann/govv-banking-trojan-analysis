# GOVV Android Banking Trojan — Full Static Analysis

> **⚠️ Disclaimer:** This repository is published for **educational and defensive security purposes only.** All samples are represented by cryptographic hashes. No executable malware is included. Information here is intended to help defenders, researchers, and financial institutions protect users.

---

## 🚨 TL;DR

A sophisticated **3-stage Android banking trojan** distributed via **Facebook Ads** in Bangladesh, targeting **bKash** mobile financial accounts. The malware combines VPN-based traffic interception, Accessibility Service abuse, SMS OTP theft, and a full Remote Access Trojan (RAT) capability set. A single infection resulted in the unauthorized transfer of approximately **BDT 20,000** from a victim's bKash account.

| Property | Value |
|----------|-------|
| **Malware Family** | GOVV / ShellA |
| **Type** | Dropper → Banking Trojan → RAT |
| **Distribution** | Facebook Ads ("World Cup Live Free TV") |
| **Primary Target** | bKash (Bangladeshi MFS) |
| **Secondary Targets** | Nagad, Rocket, mobile banking apps |
| **Outer Package** | `com.mmv.jnkh.rql7.tc8szt0d` |
| **Payload Package** | `com.d9fe4v4.pmpgv.eai.uszaw` |
| **Stages** | 3 (Stub → Injected DEX → Banking APK) |
| **Confidence** | 95% |
| **Analysis Type** | Static only (no execution) |
| **Analysis Date** | 2026-06-24 |

---

## 📁 Repository Structure

```
govv-banking-trojan-analysis/
├── README.md                    ← This file (overview + quick summary)
├── ANALYSIS.md                  ← Full technical writeup
├── IOCs.md                      ← All indicators of compromise
├── TIMELINE.md                  ← Incident & infection timeline
├── MITIGATIONS.md               ← Protection tips for users & defenders
├── static-analysis/
│   ├── manifest.txt             ← AndroidManifest.xml (decoded)
│   ├── permissions.txt          ← All declared permissions
│   ├── findings.md              ← Static analysis findings summary
│   └── decompiled-classes/      ← Key class structure excerpts
├── dynamic-analysis/
│   ├── c2-communication.md      ← C2 protocol documentation
│   └── mitmproxy-log.txt        ← (placeholder — not captured)
├── malware-samples/
│   ├── SHA256-hashes.txt        ← Hashes only, NO binaries
│   ├── yara-rules.yar           ← YARA detection rules
│   └── virustotal-links.txt     ← VirusTotal report links
└── LICENSE                      ← CC0 1.0
```

---

## 🔗 Quick Links

- [Full Technical Analysis →](ANALYSIS.md)
- [Indicators of Compromise →](IOCs.md)
- [Attack Timeline →](TIMELINE.md)
- [How to Protect Yourself →](MITIGATIONS.md)
- [YARA Detection Rules →](malware-samples/yara-rules.yar)

---

## 💀 Attack Chain (Overview)

```
[Facebook Ad]
"World Cup Live Free TV" APK
        │
        ▼
[Stage 1: Stub APK]   com.mmv.jnkh.rql7.tc8szt0d
  App Name: "GO​VV" (invisible Unicode chars)
  • attachBaseContext() → decrypts NhxxcPuLOx (XOR+GZIP)
  • Injects payload.dex via ClassLoader hijacking
  • Extracts b.apk bundle from lAsFuQPphUK asset
        │
        ▼
[Stage 2: Injected DEX]   com.shell.a
  • Shows fake "Google Play Installing..." WebView
  • Silently installs b.apk
  • Starts PpVpn → routes ALL traffic (0.0.0.0/0)
        │
        ▼
[Stage 3: Banking Trojan]   com.d9fe4v4.pmpgv.eai.uszaw
  • Requests Accessibility Service (fake tutorial)
  • Intercepts SMS OTP
  • Overlays banking apps with fake UI
  • Full RAT: keylogger, screen capture, crypto miner
        │
        ▼
[Impact]
  bKash PIN + OTP captured → BDT 20,000 stolen
```

---

## 🛡️ Key Capabilities Discovered

| Capability | Confirmed |
|-----------|-----------|
| VPN traffic interception (100%) | ✅ |
| Banking app overlay attack | ✅ |
| SMS OTP theft | ✅ |
| Keystroke logging | ✅ |
| Live screen streaming | ✅ |
| Camera recording | ✅ |
| Microphone recording | ✅ |
| GPS location tracking | ✅ |
| Cryptocurrency miner | ✅ |
| DoS engine | ✅ |
| Remote shell / Telnet | ✅ |
| Factory reset capability | ✅ |
| Phone cloning | ✅ |
| Contact & SMS exfiltration | ✅ |
| Camera mic indicator hiding | ✅ |
| Boot persistence | ✅ |
| Self-update mechanism | ✅ |

---

## 🔒 Encryption Scheme (Reversed)

The malware uses a **3-layer encryption** stack:

```python
# Layer 1: Java Random XOR + GZIP
SEED = 3017671131121758624  # 0x29DF7E6ADE0B0FA0

def decrypt_asset(asset_bytes):
    skip_header(24)          # fixed 24-byte header
    enc_len = read_int_BE()  # big-endian length
    xor_decrypted = java_random_xor(enc_data, SEED)
    return gzip.decompress(xor_decrypted)

# Layer 2: Repeating-key XOR (for DEX strings)
def decrypt_string(ciphertext, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))

# Layer 3: Runtime key from C2 (for .bt overlay files)
# Cannot decrypt statically — key sent via rckey from C2 server
```

---

## 📊 Sample Hashes

| File | SHA256 |
|------|--------|
| Outer stub APK | `cee63a18cf8f25fad52a8184fbc3a617618cba3760d55528aa02975cc140d61d` |
| Stage 3 banking APK (b.apk) | `449524566579de83d8a810bb06de985ed5a17ac533909968d5629d30bcb9bbe3` |
| Decrypted payload DEX | `5f229ccf7c30d914aba8970a65cca750c35519e8912a750825e8422e5b6c9152` |

---

## 📢 Reporting

This incident has been reported to:
- [x] bKash Security Team
- [x] Bangladesh Bank Cybersecurity Cell
- [x] CERT-BD (BGD e-GOV CIRT)
- [x] VirusTotal (hashes submitted)
- [x] Facebook (ad reported)

---

## 📖 References

- [VirusTotal Report](https://www.virustotal.com) *(search by hash)*
- [MITRE ATT&CK Mobile — T1417: Input Capture](https://attack.mitre.org/techniques/T1417/)
- [MITRE ATT&CK Mobile — T1430: Location Tracking](https://attack.mitre.org/techniques/T1430/)
- [MITRE ATT&CK Mobile — T1406: Obfuscated Files](https://attack.mitre.org/techniques/T1406/)
- [Android VPN Service Abuse](https://developer.android.com/reference/android/net/VpnService)

---

*Analysis performed on Linux using androguard, Python, and custom decryption scripts. No malware was executed at any point.*
