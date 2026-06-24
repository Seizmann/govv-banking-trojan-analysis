# GOVV Banking Trojan — Full Technical Analysis

**Sample:** `ufvx301ymvxzkw.apk`  
**Analysis Date:** 2026-06-24  
**Analyst:** Static analysis — no execution, no emulator  
**Tools:** androguard 4.1.4, Python 3.12, strings, openssl  

---

## Table of Contents

1. [Incident Summary](#1-incident-summary)
2. [Sample Overview](#2-sample-overview)
3. [Attack Chain](#3-attack-chain)
4. [Stage 1 — Stub Dropper](#4-stage-1--stub-dropper)
5. [Stage 2 — Injected DEX Loader](#5-stage-2--injected-dex-loader)
6. [Stage 3 — Banking Trojan](#6-stage-3--banking-trojan)
7. [Encryption Analysis](#7-encryption-analysis)
8. [C2 Infrastructure](#8-c2-infrastructure)
9. [Capability Analysis](#9-capability-analysis)
10. [Certificate Analysis](#10-certificate-analysis)
11. [MITRE ATT&CK Mapping](#11-mitre-attck-mapping)
12. [Conclusions](#12-conclusions)

---

## 1. Incident Summary

A Bangladesh-based victim's father installed an Android APK advertised via **Facebook Ads** as a "World Cup Live Free TV" application. Shortly after installation:

- The device froze and became unresponsive
- The victim lost control of the device
- Approximately **BDT 20,000** was transferred from the victim's **bKash** account without authorization
- The device eventually recovered but suspicious behavior continued until factory reset

The APK was extracted from the device before factory reset for forensic analysis. VirusTotal classified it as **Dropper / Banker / Trojan**.

---

## 2. Sample Overview

| Field | Value |
|-------|-------|
| Filename | `ufvx301ymvxzkw.apk` |
| SHA256 | `cee63a18cf8f25fad52a8184fbc3a617618cba3760d55528aa02975cc140d61d` |
| File Size | 10.3 MB |
| Package (outer) | `com.mmv.jnkh.rql7.tc8szt0d` |
| App Name | `GO​VV` *(contains invisible Unicode zero-width chars)* |
| Version | 1.5.4 (build 460) |
| Min SDK | 24 (Android 7.0) |
| Target SDK | 35 (Android 15) |
| Certificate | Android AOSP Debug Cert (SHA1: `61ed377e85d386a8dfee6b864bd85b0bfaa5af81`) |

**Red flags at a glance:**
- App name uses invisible Unicode characters to appear innocuous
- Signed with AOSP debug certificate (never used by legitimate apps)
- Package name is randomly obfuscated (`com.mmv.jnkh.rql7.tc8szt0d`)
- Distributed outside Google Play via social media ads

---

## 3. Attack Chain

```
Facebook Ad
    │  "World Cup Live Free TV"
    │  Leads to direct APK download (sideload)
    ▼
┌─────────────────────────────────────────────────────┐
│ STAGE 1: Stub APK                                   │
│ Package: com.mmv.jnkh.rql7.tc8szt0d               │
│ Classes: 5 (pure dropper)                          │
│                                                     │
│ attachBaseContext() [runs before anything]:         │
│   1. Open asset "NhxxcPuLOx" (3.3 MB encrypted)   │
│   2. XOR decrypt with Java Random seed             │
│   3. GZIP decompress → payload.dex (8.6 MB)        │
│   4. Replace system ClassLoader via reflection      │
│                                                     │
│ onCreate():                                         │
│   1. Open asset "lAsFuQPphUK" (4.5 MB encrypted)  │
│   2. Decrypt → bundle: b.apk + HTML + images        │
│   3. Extract to app private directory               │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│ STAGE 2: Injected DEX (payload.dex)                │
│ Package: com.shell.a (6,645 classes)               │
│                                                     │
│ MainActivity:                                       │
│   • Shows fake Google Play "Installing..." WebView  │
│   • Loads installing.html (local fake UI)           │
│   • Silently installs b.apk via session installer   │
│   • Monitors install via InstallResultReceiver      │
│                                                     │
│ PpVpn (VPN Service):                               │
│   • addAddress("10.99.0.1", 32)                    │
│   • addRoute("0.0.0.0", 0) ← ALL traffic           │
│   • Intercepts 100% of device network traffic       │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│ STAGE 3: Banking Trojan (b.apk)                    │
│ Package: com.d9fe4v4.pmpgv.eai.uszaw               │
│ Classes: 4,522 (full-featured RAT)                 │
│                                                     │
│ • Accessibility service abuse (guided setup)        │
│ • SMS OTP interception                              │
│ • Banking overlay injection via .bt scripts         │
│ • Full Remote Access Trojan capabilities            │
└─────────────────────────────────────────────────────┘
```

---

## 4. Stage 1 — Stub Dropper

### 4.1 Package Information

The outer APK contains only **5 DEX classes** — an extreme minimum indicating a pure dropper:

```
Lcom/tyshpgid/akqczvkxm/vbz/rbi/HpgFbwysCCJsnzoUH33TYeM72G2;
Lcom/tyshpgid/akqczvkxm/vbz/rbi/ODtyODdeGKP8Qdxn2rv11NC;
Lcom/tyshpgid/akqczvkxm/vbz/rbi/QFACMW3yiHwtbZuvCaivK4glJAr;
Lcom/tyshpgid/akqczvkxm/vbz/rbi/SERPXHvJXQ9NKa9059a6NQFkljxTn;
Lcom/tyshpgid/akqczvkxm/vbz/rbi/oI4lIJOlbjSkXqgwGehsi9Q9r;  ← Application class
```

All class/method names are randomly obfuscated. The Application subclass (`oI4lIJOlbjSkXqgwGehsi9Q9r`) is the dropper entry point.

### 4.2 Declared Permissions (Stage 1 only)

| Permission | Risk | Purpose |
|-----------|------|---------|
| `BIND_VPN_SERVICE` | 🔴 Critical | Intercept all network traffic |
| `REQUEST_INSTALL_PACKAGES` | 🔴 High | Install additional APKs silently |
| `POST_NOTIFICATIONS` | 🟡 Medium | Display deceptive notifications |

> **Note:** Only 3 external permissions declared. Actual malicious permissions reside in Stage 3's encrypted manifest — a deliberate evasion technique to pass automated permission scanners.

### 4.3 ClassLoader Injection (Bytecode Verified)

The dropper uses sophisticated reflection to inject its payload without user awareness:

```smali
; attachBaseContext() — runs before Application.onCreate()
new-instance v0, Ldalvik/system/DexClassLoader;

; Open encrypted asset
invoke-virtual v3, Landroid/content/res/AssetManager;->open("NhxxcPuLOx")

; XOR decrypt + GZIP decompress → payload.dex
new-instance v6, Ljava/util/Random;
invoke-direct v6, v7, v8, Ljava/util/Random;-><init>(3017671131121758624)

; ClassLoader injection via reflection
invoke-static "android.app.ActivityThread", Ljava/lang/Class;->forName
invoke-virtual v6, "mPackages", getDeclaredField    ; internal Android field
invoke-virtual v6, v1, 1, setAccessible(true)       ; bypass access control
invoke-virtual v5, v4, v0, Field;->set(thread, newDexClassLoader)
```

The `mPackages` → `mClassLoader` replacement makes the injected payload indistinguishable from the original application's code.

### 4.4 Encrypted Asset Files

| Asset File | Size (raw) | Decrypted Content |
|-----------|-----------|-------------------|
| `NhxxcPuLOx` | 3.3 MB | `payload.dex` — 8.6 MB, 6,645 classes |
| `lAsFuQPphUK` | 4.5 MB | Bundle: `b.apk` (5.7 MB) + HTML overlays |

### 4.5 APK Structure Obfuscation

All 900+ resource files have randomly generated names:

```
0AV0co8K33z3HIYGkA/7JkPosajre9JIKh.xml
0b1TR7SVaWJWwzlZqgAJct9YTF/SncpaE5CSRV5T2Dxb0ZSBllo.xml
...
```

Top-level files without extensions contain additional encrypted payloads.

---

## 5. Stage 2 — Injected DEX Loader

### 5.1 Components

After ClassLoader injection, the following `com.shell.a` components become active:

| Component | Type | Function |
|-----------|------|---------|
| `MainActivity` | Activity | Fake install UI, drops b.apk |
| `PpVpn` | Service (VpnService) | Full-device traffic interception |
| `InstallResultReceiver` | BroadcastReceiver | Monitors b.apk installation |

### 5.2 Social Engineering — Fake UI

`MainActivity` loads a local WebView with `installing.html` — a pixel-perfect clone of the Google Play installation progress screen, complete with animated spinner and progress bar. This distracts the user while b.apk is installed silently in the background.

```java
// MainActivity.onCreate() — simplified
webView.loadUrl("file://" + filesDir + "/assets_i/installing.html");
// Meanwhile, in background coroutine:
installBFromAssets()   // extracts and installs b.apk
startSessionInstall()  // uses PackageInstaller session API
```

### 5.3 VPN Traffic Interception

```smali
; PpVpn.onStartCommand() — verified from bytecode
new-instance v0, Landroid/net/VpnService$Builder;
invoke-virtual v0, "10.99.0.1", 32, addAddress    ; VPN interface
invoke-virtual v0, "0.0.0.0", 0, addRoute         ; ALL traffic → VPN tunnel
invoke-virtual v0, establish()                     ; Create TUN device

; Internal log tag confirms family name
Log.i("ShellA", "PpVpn started, instance set")
```

`addRoute("0.0.0.0", 0)` routes every network packet — including bKash API calls, SMS gateway traffic, and bank servers — through the VPN tunnel. The bundled `ads.txt` (2 MB AdAway hosts blocklist) is used as a VPN-side DNS filter to block ad-tracking domains, reducing detection surface.

---

## 6. Stage 3 — Banking Trojan

### 6.1 Package Info

| Field | Value |
|-------|-------|
| Package | `com.d9fe4v4.pmpgv.eai.uszaw` |
| DEX (encrypted) | `AfhQlBuxfo` asset in b.apk (2.4 MB) |
| DEX (decrypted) | 5.18 MB, 4,522 classes |
| Decryption | Same XOR+GZIP scheme, same seed `3017671131121758624` |

### 6.2 Key Classes

| Class | Function |
|-------|---------|
| `BootReceiver` | Auto-start on device boot |
| `CallBacker` | C2 callback & command dispatch |
| `SendSms` | SMS sending capability |
| `MyDeviceAdminReceiver` | Device administrator (persistence) |
| `DownloadForegroundService` | Downloads additional payloads |
| `HomeSIM` | SIM card info harvesting |
| `Inputyvdcvtink` | Keystroke monitoring |
| `dqssgbaajsdc` | Accessibility service (main RAT service) |
| `e0` | WebSocket C2 client (OkHttp3) |
| `e0$a` | C2 command handler (30+ commands) |
| `bmrejrotee` | Camera recording service |
| `cbjjyszzrrzhzovehl` | Screen overlay + sensor service |
| `FFmpegKit` | Screen recording library |

### 6.3 String Obfuscation — Two-Layer System

**Layer 1 — Fill-array-data XOR:**
```java
// l50.b() — the decryption function (bytecode-recovered)
byte[] decrypt(byte[] ciphertext, byte[] key) {
    for (int i = 0, j = 0; i < ciphertext.length; i++, j++) {
        if (j >= key.length) j = 0;   // repeating key
        ciphertext[i] ^= key[j];
    }
    return ciphertext;
}
```

**Layer 2 — Unicode char encoding:**  
Strings are stored as Arabic Extended Unicode characters (U+06D6–U+06ED), decoded at runtime via switch-on-hashCode lookup tables in methods `B()` through `O()` of the `cbjjyszzrrzhzovehl` class.

### 6.4 Overlay Attack Assets (b.apk)

| Asset | Size | Content |
|-------|------|---------|
| `acs_els.html` | 19 KB | Fake Accessibility Settings tutorial |
| `acs_sm.html` | 47 KB | SMS OTP overlay (custom encrypted) |
| `acs_mi.html` | 19 KB | Mobile banking app overlay (custom encrypted) |
| `acs_stct.html` | 10 KB | Step-by-step accessibility grant guide |
| `1.bt` | 164 KB | Banking overlay script (AES, rckey) |
| `2.bt` | 6 KB | Config/secondary script (AES, rckey) |
| `3.bt` | 3.8 KB | Tertiary script (AES, rckey) |
| `cht.html` | 4.9 KB | Operator chat UI (WebView bridge) |
| `ads.txt` | 2 MB | AdAway hosts list (VPN DNS filter) |
| `t.conf` | 1.3 KB | UI config (base64 PNG) |
| `uns.html` | 1.8 KB | "Not Compatible" uninstall deterrent |
| `up_require.html` | 4.6 KB | Fake "Update Required" social engineering |

> **`.bt` files:** Base64-encoded, then encrypted with a key (`rckey`) sent dynamically from the C2 server. Cannot be decrypted via static analysis. These are the banking app injection scripts targeting bKash and other MFS apps.

---

## 7. Encryption Analysis

### 7.1 Primary Encryption (XOR + GZIP)

Used for: `NhxxcPuLOx`, `lAsFuQPphUK` (Stage 1 assets), `AfhQlBuxfo` (Stage 3 DEX)

```python
import gzip, struct

SEED = 3017671131121758624
MULTIPLIER = 0x5DEECE66D
MASK = (1 << 48) - 1

def java_random_xor(data, seed):
    state = (seed ^ MULTIPLIER) & MASK
    result = bytearray(len(data))
    for i in range(len(data)):
        state = (state * MULTIPLIER + 0xB) & MASK
        xv = (256 * (state >> 17)) >> 31
        result[i] = data[i] ^ (xv & 0xFF)
    return bytes(result)

def decrypt_asset(raw_bytes):
    # Skip 24-byte header
    enc_len = struct.unpack('>I', raw_bytes[24:28])[0]
    enc_data = raw_bytes[28:28 + enc_len]
    return gzip.decompress(java_random_xor(enc_data, SEED))
```

### 7.2 String Decryption (Repeating-Key XOR)

Used for: all hardcoded strings in Stage 3 DEX classes

```python
def decrypt_string(ciphertext: bytes, key: bytes) -> str:
    result = bytearray(len(ciphertext))
    for i in range(len(ciphertext)):
        result[i] = ciphertext[i] ^ key[i % len(key)]
    return result.rstrip(b'\x00').decode('utf-8')
```

### 7.3 Overlay Script Encryption (`.bt` files)

Format: `Base64(AES_ENCRYPTED_PAYLOAD)`

- **Key source:** `rckey` field received from C2 server at runtime
- **Cannot be decrypted statically**
- All three `.bt` files share the same 32-byte header (`8bcdb2b5...a59213e6`), indicating a common key/IV structure
- Decryption performed in native code (`libssl.so.1.1`, `libcrypto.so.1.1`)

---

## 8. C2 Infrastructure

### 8.1 Server Endpoint (Confirmed via String Decryption)

```
Path:        /yaarsa/private/yarsap_80541.php
Error log:   /yaarsa/private/log_error.php
Config:      /config.json
Local WS:    ws://127.0.0.1:8080/
```

> **Server IP/Domain:** Stored in Unicode-encoded strings, decoded only at runtime. Not recoverable via static analysis. Dynamic analysis (network capture) required.

### 8.2 C2 Protocol

The malware uses **OkHttp3 WebSocket** (`e0` class) as its primary C2 channel.

**Message format:**
```
COMMAND<:CS:>DATA
```

**Connection parameters:**
```
Deviceid    → device unique identifier
Slr_client  → client type identifier
subc        → subscription/group
conk        → connection key
```

**C2 → Device commands (30+ decoded):**

| Command | Function |
|---------|---------|
| `browser` | Open URL in victim's browser |
| `screen` / `livescreen` | Screenshot / live screen stream |
| `scread` | Screen reader (accessibility data) |
| `chat` | Open operator chat panel |
| `micm` | Microphone recording |
| `call` | Call management / blocking |
| `SMS` | SMS read / send |
| `keystrokes` | Retrieve keylogger data |
| `clone` | Phone cloning |
| `ject` | Inject banking overlay (.bt script) |
| `lock` | Lock/unlock device |
| `blker` | Call/SMS blocker |
| `snap` | Silent screenshot |
| `mining` | Start/stop cryptocurrency miner |
| `tols` | Start/stop DoS engine |
| `terminal` | Remote shell / Telnet access |
| `fetch` | Download file from URL |
| `upload` | Upload file to C2 |
| `location` | Get GPS coordinates |
| `update` | Self-update APK |
| `addA` | Add contact |
| `reip` | Update C2 redirect IP (`red_ip`) |
| `rckey` | Update decryption key for .bt files |

**Authentication markers:**
```
[AST-PAS]     → session authentication
[:K3R1:]      → key rotation marker
~NOPASS~      → no screen lock detected
___CMD_END___ → command terminator
```

### 8.3 IP Checking Services Used

The malware queries public IP-lookup services to determine the victim's external IP:

```
http://checkip.amazonaws.com
https://icanhazip.com
https://ifconfig.me/ip
```

### 8.4 Operator Chat Interface (`cht.html`)

```html
<!-- The operator types commands here -->
<input type="text" id="chatInput" placeholder="Type a message...">

<!-- JavaScript bridge to native Java -->
<script>
async function sendMessage() {
    const text = inputField.value.trim();
    if (text) {
        mybridge.sendit(text);  // ← Android WebView.addJavascriptInterface()
    }
}
</script>
```

No WebSocket URL appears in `cht.html` — all server communication is handled in native Java via `e0` class. The `[NAME]` placeholder in the title is dynamically replaced with the victim's device name.

---

## 9. Capability Analysis

### 9.1 Financial Theft

1. **VPN interception:** All bKash traffic routed through attacker-controlled tunnel
2. **SMS OTP theft:** `acs_sm.html` overlay intercepts OTP before user sees it
3. **PIN capture:** Overlay captures PIN entry; `LockType: Password, Pass:` confirms capture
4. **Keylogger:** Accessibility-based keystroke capture: `Live Key-logs`, `At.acc.keystrk`
5. **Screen capture:** Silent screenshot + live streaming reveals on-screen data

### 9.2 Persistence

```java
// BootReceiver — survives device restart
// MyDeviceAdminReceiver — device admin prevents uninstall
// ResetServices — watchdog restarts killed services
// uns.html — "Not Compatible" deters manual uninstall
// Camera mic icon hidden: cmd device_config put privacy camera_mic_icons_enabled false
```

### 9.3 Surveillance

| Data Type | Method |
|-----------|--------|
| Screen content | FFmpegKit continuous video + silent screenshot |
| Keystrokes | Accessibility service input monitoring |
| SMS messages | `content://sms/inbox`, `content://sms/sent` |
| Contacts | `contact_id` content provider |
| Calls | Call log access + real-time blocking |
| GPS | Location provider + AccessibilityEvent URL capture |
| Camera | `bmrejrotee` service — `continuous-video` mode |
| Microphone | Audio recording service |
| Clipboard | `clip` command |
| Browser history | `visitedlinks`, `visitedapps` |
| App activity | `Rec_Activity`, `Rec_Notifications` |

### 9.4 Additional Capabilities

- **Cryptocurrency miner:** `Mining`, `miner not active` → mines on victim device
- **DoS engine:** `Dos Engine` → turns victim into attack node
- **Remote terminal:** `telnet` with `host/user/pass/port` → full shell access
- **File manager:** Create folders, open files, exfiltrate data
- **Factory reset:** `com.android.settings:id/clear_all_data_text` → automation
- **Phone cloning:** `App.BAK.SYNC`, `App.BAK.LOAD` → clones apps/data to C2

### 9.5 Evasion Techniques

| Technique | Implementation |
|-----------|---------------|
| 3-stage dropper | Payload not in original APK |
| ClassLoader injection | Bypasses static analysis |
| Debug certificate | Common AOSP cert, not suspicious on its own |
| App name obfuscation | Invisible Unicode zero-width chars in "GO​VV" |
| String encryption | 2-layer XOR + Unicode encoding |
| Asset encryption | XOR + GZIP with Java Random |
| Overlay script encryption | AES with runtime key from C2 |
| Camera/mic icon hiding | System command to disable privacy indicators |
| Resources obfuscation | All 900+ resource files have random names |

---

## 10. Certificate Analysis

| Field | Value |
|-------|-------|
| Subject | `CN=Android, O=Android, OU=Android, C=US` |
| Issuer | Self-signed (identical to subject) |
| Email | `android@android.com` |
| Type | **AOSP Debug / Test Certificate** |
| SHA1 | `61ed377e85d386a8dfee6b864bd85b0bfaa5af81` |
| SHA256 | `a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc` |
| MD5 | `e89b158e4bcf988ebd09eb83f5378e87` |
| Valid | 2008-02-29 → 2035-07-17 |
| Serial | `10623618503190643167` |

The use of the Android AOSP debug certificate (`61ed377e`) is a well-known indicator of malware. No legitimate app published to users is signed with this certificate. This hash is present in many threat intelligence databases as a malware indicator.

---

## 11. MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|----|
| Input Capture — Keylogging | T1417.001 | Accessibility-based keystroke logging |
| Input Capture — GUI Input Capture | T1417.002 | Banking overlay PIN capture |
| Location Tracking | T1430 | GPS and network-based location |
| Capture SMS Messages | T1412 | Direct SMS inbox access |
| Access Notifications | T1517 | Notification listener |
| Network Information Discovery | T1421 | IP, operator, SIM info |
| Screen Capture | T1513 | FFmpegKit + silent screenshot |
| Audio Capture | T1429 | Microphone recording |
| Video Capture | T1418.001 | Continuous camera recording |
| Obfuscated Files or Information | T1406 | Multi-layer encryption |
| Native Code | T1408 | libssl, libcrypto native libs |
| Exfiltration Over C2 Channel | T1646 | WebSocket C2 data exfil |
| Download New Code at Runtime | T1407 | .bt overlay script download |
| Abuse Accessibility Features | T1532 | Accessibility service RAT |
| Foreground Persistence | T1624.001 | Foreground service |
| Boot or Logon Autostart | T1398 | BootReceiver persistence |
| Device Administrator Permissions | T1401 | MyDeviceAdminReceiver |

---

## 12. Conclusions

This malware represents a **professionally developed banking trojan** with capabilities far exceeding typical Android banking malware:

1. **3-stage dropper architecture** evades static analysis and permission scanning
2. **VPN-based traffic interception** is more powerful than typical overlay attacks — it works on ALL apps, not just targeted ones
3. **Dual C2 channels** (WebSocket + HTTP POST) provide resilience
4. **Dynamic key distribution** for overlay scripts prevents static recovery of targeted banks
5. **Full RAT capabilities** (terminal, miner, DoS, camera, mic) indicate this is a commercial or semi-professional criminal tool, not a one-off attacker
6. **Multi-language UI** (English, Spanish, Portuguese, Turkish) indicates this malware kit is sold or deployed across multiple countries
7. **The `Slr_client` identifier** and structured command protocol suggest a larger malware-as-a-service (MaaS) operation

The combination of VPN interception + SMS OTP theft + banking overlay is a complete solution for mobile financial account takeover. The victim's bKash account compromise is fully explained by this malware's capabilities.

---

*Analysis performed using static methods only. No binary was executed.*  
*All byte sequences confirmed from DEX bytecode disassembly.*
