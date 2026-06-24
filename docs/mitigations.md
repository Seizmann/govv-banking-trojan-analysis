# Mitigations & Protection Guide

**Audience:** General users, IT administrators, financial institutions, security teams

---

## 🚨 If You Are Currently Infected

### Immediate Steps (Do These NOW)

1. **Do NOT open bKash, Nagad, or any banking app** on the infected device
2. **From a DIFFERENT device** (friend's phone or computer):
   - Change bKash PIN immediately: call **16247** or use bKash app on safe device
   - Change Nagad PIN: call **16167**
   - Contact your bank and freeze mobile banking
3. **Put the infected phone in Airplane Mode** — this stops C2 communication
4. **Factory reset the device:**
   - Settings → General Management → Reset → Factory Data Reset
   - Do NOT restore from backup (backup may re-infect)
5. **After reset:** change all passwords from a safe device before logging in on the phone
6. **Report to bKash:** Call **16247** and report unauthorized transactions
7. **File a police report** (GD) at your local police station — required for bKash fraud recovery

---

## 👤 For General Users

### Prevention

| Action | Why |
|--------|-----|
| **Only install apps from Google Play** | This APK was a sideloaded APK — Play Protect would have blocked it |
| **Never install APKs from Facebook ads, Messenger links, or WhatsApp** | Legitimate apps don't distribute via social media |
| **Keep "Unknown Sources" / "Install Unknown Apps" DISABLED** | Default Android setting — don't change it for random apps |
| **Never enable Accessibility Service for untrusted apps** | Banking trojans require this to read your screen |
| **Never enable VPN for untrusted apps** | Check VPN key icon in notification bar |
| **Enable Play Protect** | Settings → Google → Play Protect → Scan apps |
| **Use a separate phone for mobile banking** | Reduces attack surface dramatically |
| **Check installed apps regularly** | Look for apps you don't remember installing |

### Warning Signs of Infection

```
❗ Phone freezes or becomes slow after installing a new app
❗ Battery drains unusually fast
❗ VPN key icon (🔑) appears without installing a VPN app
❗ Accessibility service is enabled for an unknown app
❗ Unknown app installed alongside the one you intended
❗ bKash/Nagad shows transactions you didn't make
❗ Phone stays warm when idle (crypto miner running)
❗ Unknown apps in "Device Admin" list
```

### Verify Your Device Right Now

```
Check VPN:
  Settings → Network → VPN → Is anything listed? Should be empty.

Check Accessibility:
  Settings → Accessibility → Downloaded Apps → Any unknown apps?

Check Device Admin:
  Settings → Biometrics & Security → Device Admin Apps → Any unknown?

Check running services:
  Settings → Battery → Battery Usage → Any suspicious apps?
```

---

## 🏦 For Financial Institutions (bKash, Nagad, Banks)

### Detection Signals

Flag accounts where:
```
• Multiple OTP requests in rapid succession
• Transaction from a new device immediately after OTP
• Transaction value near account maximum
• Geographic mismatch (device IP vs registered location)
• Transaction during unusual hours for the account
• OTP delivered but transaction initiated from different network
• VPN exit node IP used for transaction
```

### Recommended Controls

1. **Behavioral biometrics** on transaction screen — detects overlay attacks
2. **Device fingerprint change alerts** — new device = extra verification
3. **Transaction confirmation callback** — call-back to registered phone number
4. **IP reputation checking** — flag VPN/proxy IPs for extra verification
5. **Time-of-day anomaly detection**
6. **Rapid successive OTP request rate-limiting**
7. **In-app SSL pinning** — prevents traffic MITM even through VPN
8. **Root/emulator detection** — high-risk device flag

### IOCs to Block (Share with Threat Intel Team)

```
Certificate SHA1:  61ed377e85d386a8dfee6b864bd85b0bfaa5af81
Package:           com.d9fe4v4.pmpgv.eai.uszaw
Package:           com.mmv.jnkh.rql7.tc8szt0d
File hash (APK):   cee63a18cf8f25fad52a8184fbc3a617618cba3760d55528aa02975cc140d61d
C2 path pattern:   /yaarsa/private/*.php
```

---

## 🔒 For Android Users — Hardening Checklist

### Essential Settings

```
✅ Google Play Protect: ON
   → Settings → Google → Play Protect

✅ Unknown sources: OFF
   → Settings → Biometrics & Security → Install Unknown Apps
   → Make sure ALL apps show "Not allowed"

✅ Developer options: OFF (if you're not a developer)
   → If enabled: Settings → Developer Options → toggle OFF

✅ Verify apps: ON
   → Settings → Biometrics & Security → Google Play Protect

✅ Automatic updates: ON
   → Play Store → Profile → Settings → Network preferences → Auto-update

✅ Screen lock: PIN/pattern/biometric
   → Settings → Lock Screen → Screen Lock Type
```

### Advanced (Tech-Savvy Users)

```
✅ Use a separate budget phone for mobile banking only
   → Minimal apps, no social media, no games

✅ Check app permissions after every install
   → Settings → Apps → [App] → Permissions

✅ Monthly: Review Device Admin list
   → Settings → Security → Device Admin Apps

✅ Monthly: Review Accessibility services
   → Settings → Accessibility → Installed Services

✅ Enable DNS-over-HTTPS
   → Settings → Network → Private DNS → dns.google

✅ Consider GrapheneOS for high-security users
```

---

## 📱 For IT/MDM Administrators

### MDM Policy Recommendations

```
# Deny high-risk permissions by policy:
- BIND_VPN_SERVICE: Block for non-MDM-approved VPN apps
- BIND_ACCESSIBILITY_SERVICE: Block for non-approved apps
- BIND_DEVICE_ADMIN: Block for non-MDM apps
- REQUEST_INSTALL_PACKAGES: Block entirely
- SYSTEM_ALERT_WINDOW: Block for non-approved apps

# App control:
- Whitelist-only app installs
- Block sideloading (INSTALL_PACKAGES permission = deny)
- Certificate pinning enforcement for financial apps

# Network:
- Block known C2 paths: /yaarsa/private/
- Alert on WebSocket connections to PHP endpoints from mobile devices
```

### YARA / Network Detection

See [`malware-samples/yara-rules.yar`](malware-samples/yara-rules.yar) for file-based detection.

---

## 📢 Reporting This Malware

### Report to (Bangladesh):

| Organization | Contact |
|-------------|---------|
| BGD e-GOV CIRT | https://www.cirt.gov.bd |
| Bangladesh Bank | cybersecurity@bb.org.bd |
| bKash Security | 16247 (hotline) |
| Nagad Security | 16167 (hotline) |
| Police Cybercrime | https://cybercrime.gov.bd |
| Facebook (ad abuse) | https://www.facebook.com/help/reportlinks |

### Report to (International):

| Organization | Contact |
|-------------|---------|
| VirusTotal | https://www.virustotal.com (submit hash) |
| ANY.RUN | https://app.any.run (submit sample) |
| MalwareBazaar | https://bazaar.abuse.ch (submit sample) |
| Google Safe Browsing | https://safebrowsing.google.com/safebrowsing/report_phish/ |
| APWG | https://apwg.org/reportphishing/ |

---

## 🛡️ Technical Mitigations for App Developers

If you develop mobile financial apps (bKash, Nagad, etc.):

```java
// 1. Detect Accessibility Services (may indicate RAT)
AccessibilityManager am = (AccessibilityManager) getSystemService(ACCESSIBILITY_SERVICE);
List<AccessibilityServiceInfo> services = am.getEnabledAccessibilityServiceList(
    AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
// Flag if unknown services are enabled

// 2. Detect VPN (traffic may be intercepted)
ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
Network[] networks = cm.getAllNetworks();
for (Network network : networks) {
    NetworkCapabilities nc = cm.getNetworkCapabilities(network);
    if (nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
        // Warn user or require additional verification
    }
}

// 3. Certificate pinning (blocks VPN MITM)
OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(new CertificatePinner.Builder()
        .add("api.bkash.com", "sha256/YOUR_CERT_HASH")
        .build())
    .build();

// 4. Root detection
// Use SafetyNet Attestation API or Play Integrity API

// 5. Screen recording detection (API 34+)
getWindow().setFlags(
    WindowManager.LayoutParams.FLAG_SECURE,
    WindowManager.LayoutParams.FLAG_SECURE
);
```
