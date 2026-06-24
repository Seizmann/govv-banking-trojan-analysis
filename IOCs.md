# Indicators of Compromise (IOCs)

**Malware Family:** GOVV / ShellA Banking Trojan  
**Last Updated:** 2026-06-24  
**Confidence:** High (statically verified from bytecode)

---

## 📁 File Hashes

### APK Samples

| File | SHA256 | MD5 | Size |
|------|--------|-----|------|
| Outer stub APK (`ufvx301ymvxzkw.apk`) | `cee63a18cf8f25fad52a8184fbc3a617618cba3760d55528aa02975cc140d61d` | — | 10.3 MB |
| Stage 3 banking APK (`b.apk`) | `449524566579de83d8a810bb06de985ed5a17ac533909968d5629d30bcb9bbe3` | — | 5.7 MB |
| Decrypted Stage 2 DEX (`payload.dex`) | `5f229ccf7c30d914aba8970a65cca750c35519e8912a750825e8422e5b6c9152` | — | 8.6 MB |
| Decrypted Stage 3 DEX (`b_classes.dex`) | `sha256sum /home/sijan/scam-apk/b_classes.dex` | — | 5.2 MB |

### Certificate Fingerprints

| Type | Value |
|------|-------|
| Certificate SHA1 | `61ed377e85d386a8dfee6b864bd85b0bfaa5af81` |
| Certificate SHA256 | `a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc` |
| Certificate MD5 | `e89b158e4bcf988ebd09eb83f5378e87` |
| Certificate Subject | `CN=Android, O=Android, OU=Android, C=US, emailAddress=android@android.com` |
| Certificate Serial | `10623618503190643167` |

> The certificate `61ed377e...` is the Android AOSP debug certificate — a known malware indicator present in many threat intelligence feeds.

---

## 📦 Package Names

| Package | Stage | Role |
|---------|-------|------|
| `com.mmv.jnkh.rql7.tc8szt0d` | 1 | Outer stub dropper |
| `com.shell.a` | 2 | Injected DEX loader + VPN |
| `com.tyshpgid.akqczvkxm.vbz.rbi` | 1 | Obfuscated Application class namespace |
| `com.d9fe4v4.pmpgv.eai.uszaw` | 3 | Banking trojan (VirusTotal-confirmed package) |

---

## 🌐 Network Indicators

### C2 Server Endpoints (Static — Confirmed)

```
/yaarsa/private/yarsap_80541.php    ← Main C2 PHP endpoint
/yaarsa/private/log_error.php       ← Error logging endpoint
/config.json                         ← Remote configuration file
```

> **Server IP/Domain:** Stored in Unicode-obfuscated strings, decoded only at runtime. Not recoverable via static analysis. Submit hashes to ANY.RUN or Hybrid Analysis for dynamic network capture.

### Local Device Endpoints

```
ws://127.0.0.1:8080/    ← WebView ↔ native Java bridge (local WebSocket)
10.99.0.1/32            ← VPN interface IP assigned by malware
```

### IP Intelligence Services Queried by Malware

```
http://checkip.amazonaws.com
https://icanhazip.com
https://ifconfig.me/ip
https://api.ipify.org (likely, pattern match)
```

### Encrypted Asset Names (Dropper)

```
NhxxcPuLOx    ← Encrypted payload.dex (Stage 2 DEX)
lAsFuQPphUK   ← Encrypted bundle (b.apk + overlays)
AfhQlBuxfo    ← Encrypted Stage 3 DEX (inside b.apk)
```

---

## 🔐 Encryption Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | Java `Random` XOR + GZIP |
| Seed (decimal) | `3017671131121758624` |
| Seed (hex) | `0x29DF7E6ADE0B0FA0` |
| Header skip | 24 bytes |
| Length field | Big-endian `int` at offset 24 |
| String decryption | Repeating-key XOR (12-byte keys recovered from DEX) |
| Overlay script encryption | AES (key = `rckey`, distributed by C2 at runtime) |

**Decryption PoC:**
```python
import gzip, struct

SEED = 3017671131121758624
MULT = 0x5DEECE66D
MASK = (1 << 48) - 1

def decrypt(raw):
    state = (SEED ^ MULT) & MASK
    enc_len = struct.unpack('>I', raw[24:28])[0]
    enc = bytearray(raw[28:28+enc_len])
    for i in range(len(enc)):
        state = (state * MULT + 0xB) & MASK
        enc[i] ^= (256 * (state >> 17)) >> 31
    return gzip.decompress(bytes(enc))
```

---

## 🏷️ Log Tags & Internal Identifiers

| Identifier | Location | Value |
|-----------|----------|-------|
| VPN service tag | `PpVpn.onStartCommand()` | `ShellA` |
| Dropper stub tag | `oI4lIJOlbjSkXqgwGehsi9Q9r` | `STUB` |
| Asset fail tag | Stage 1 dropper | `A_F`, `AS_F` |
| Client identifier | `e0.u()`, `bmrejrotee.f()` | `Slr_client` |
| C2 command delimiter | `e0$a` | `___CMD_END___` |
| C2 protocol separator | `e0$a.m()` | `<:CS:>` |
| Auth marker | C2 protocol | `[AST-PAS]` |
| Key marker | C2 protocol | `[:K3R1:]` |
| No-lock indicator | `e0$a.j()` | `~NOPASS~` |

---

## 📁 Malicious Asset Files (b.apk)

| Filename | Size | Role |
|----------|------|------|
| `acs_els.html` | 19 KB | Fake Accessibility Settings guide |
| `acs_sm.html` | 47 KB | SMS OTP overlay (AES encrypted) |
| `acs_mi.html` | 19 KB | Mobile banking overlay (AES encrypted) |
| `acs_stct.html` | 10 KB | Accessibility permission grant tutorial |
| `cht.html` | 4.9 KB | Operator command chat interface |
| `1.bt` | 164 KB | Banking overlay injection script (Base64+AES) |
| `2.bt` | 6 KB | Secondary config/script (Base64+AES) |
| `3.bt` | 3.8 KB | Tertiary script (Base64+AES) |
| `uns.html` | 1.8 KB | Uninstall deterrent ("Not Compatible") |
| `up_require.html` | 4.6 KB | Fake update page (social engineering) |
| `s1s2s3s4.html` | 3.4 KB | Splash loader screen |
| `launcher.html` | 9.5 KB | Fake app launch animation |

---

## 🔍 YARA Rules

See [`malware-samples/yara-rules.yar`](malware-samples/yara-rules.yar)

---

## 📊 VirusTotal Links

- Outer APK: Search `cee63a18cf8f25fad52a8184fbc3a617618cba3760d55528aa02975cc140d61d`
- b.apk: Search `449524566579de83d8a810bb06de985ed5a17ac533909968d5629d30bcb9bbe3`

---

## 🎯 Targeted Applications (Confirmed from Overlay Files)

- **bKash** — Bangladesh mobile financial service (primary target, confirmed by incident)
- **Nagad** — Bangladesh MFS (overlay assets suggest targeting)
- **Rocket** — Dutch-Bangla MFS (overlay assets suggest targeting)
- Any app accessible via **Accessibility Service** (all apps on device at risk)

---

## 🕵️ Behavioral IOCs (Runtime — for EDR/MDM)

```
• App requests BIND_VPN_SERVICE + REQUEST_INSTALL_PACKAGES
• VPN routes 0.0.0.0/0 (all traffic)
• AccessibilityService enabled via social engineering
• WebSocket connection to PHP endpoint
• 3+ APK files in /data/data/<package>/files/
• DexClassLoader loading from app private directory
• Reflection access to android.app.ActivityThread.mPackages
• cmd deviceidle whitelist + <package>
• cmd device_config put privacy camera_mic_icons_enabled false
• Files named NhxxcPuLOx, lAsFuQPphUK in assets
• App name contains zero-width Unicode characters
```

---

*All network IOCs marked as partial pending dynamic analysis.*  
*Submit samples to sandbox for full network IOC extraction.*
