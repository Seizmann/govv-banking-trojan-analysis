# Incident & Analysis Timeline

---

## 📅 Infection Timeline

> *Exact timestamps are reconstructed from victim account. Device clock not verified independently.*

```
[T+0:00]  Facebook ad appears on victim's father's feed
           → Ad claims: "World Cup Live Free TV — Watch Free!"
           → Ad looks legitimate with Play Store-style graphics

[T+0:05]  Victim clicks ad → redirected to external APK download
           → Browser prompts: "Allow downloads from this source?"
           → Victim allows → APK downloaded (~10 MB)

[T+0:07]  Android warns: "Install from unknown sources"
           → Victim enables "Unknown Sources" setting
           → APK installed: com.mmv.jnkh.rql7.tc8szt0d ("GO​VV")

[T+0:07]  [BACKGROUND — STAGE 1 BEGINS IMMEDIATELY]
           → attachBaseContext() fires before UI appears
           → Decrypts NhxxcPuLOx → payload.dex (8.6 MB)
           → Replaces system ClassLoader via reflection
           → Decrypts lAsFuQPphUK → b.apk extracted to private dir

[T+0:08]  Victim sees: fake Google Play "Installing..." screen
           → Animated spinner, progress bar
           → Reads: "Installing update... please wait"

[T+0:08]  [BACKGROUND — STAGE 2 ACTIVE]
           → b.apk (com.d9fe4v4.pmpgv.eai.uszaw) silently installed
           → PpVpn service starts
           → VPN established: ALL traffic now intercepted
           → WebSocket C2 connection initiated

[T+0:09]  Victim sees: Accessibility permission request
           → acs_els.html shows fake Android Settings tutorial
           → Step-by-step guide with animations
           → Victim follows guide → Accessibility Service enabled

[T+0:10]  [BACKGROUND — STAGE 3 FULLY ACTIVE]
           → dqssgbaajsdc accessibility service running
           → Keylogger active
           → Screen capture service started
           → C2 operator notified (BotState, Slr_client connection)
           → rckey (overlay decryption key) received from C2

[T+0:10]  [BACKGROUND — BANKING OVERLAY LOADED]
           → 1.bt decrypted with received rckey
           → bKash overlay injection ready
           → acs_sm.html SMS OTP overlay armed

[T+??]    Victim opens bKash app
           → Banking overlay displayed (fake bKash UI)
           → Victim enters bKash PIN
           → PIN captured via Accessibility keylogger + overlay

[T+??]    bKash sends OTP SMS to victim's phone
           → SMS intercepted BEFORE it reaches victim's SMS app
           → OTP forwarded to C2 operator via WebSocket

[T+??]    C2 operator uses captured PIN + OTP
           → Unauthorized bKash transaction initiated
           → BDT 20,000 transferred to attacker's account

[T+??]    Victim's phone freezes / becomes unresponsive
           → Likely: operator using live screen + input injection
           → Victim unable to cancel transaction

[LATER]   Victim regains phone control
           → Discovers unauthorized bKash transaction
           → Uninstalls "GO​VV" app
           → Suspicious activity continues (b.apk still installed)

[LATER]   Device factory reset
           → Before reset: APK extracted for analysis
           → Post-reset: device clean

```

---

## 🔬 Analysis Timeline

```
2026-06-24 06:24  APK file identified in /home/sijan/scam-apk/
                  Filename: ufvx301ymvxzkw.apk (10.3 MB)

2026-06-24 06:26  Tools installed: androguard 4.1.4

2026-06-24 06:28  Stage 1 manifest decoded via androguard
                  → Package: com.mmv.jnkh.rql7.tc8szt0d
                  → Only 5 DEX classes → pure dropper confirmed
                  → 3 permissions only (VPN, INSTALL_PACKAGES, NOTIFY)

2026-06-24 06:30  DEX bytecode disassembly
                  → attachBaseContext() XOR+GZIP decryption confirmed
                  → DexClassLoader + reflection injection confirmed
                  → Asset names: NhxxcPuLOx, lAsFuQPphUK identified

2026-06-24 06:32  Encryption scheme reversed from bytecode
                  → Seed: 3017671131121758624
                  → Algorithm: Java Random XOR + GZIP

2026-06-24 06:34  NhxxcPuLOx successfully decrypted
                  → payload.dex: 8.6 MB, 6,645 classes
                  → com.shell.a package confirmed
                  → PpVpn VPN service confirmed

2026-06-24 06:36  lAsFuQPphUK successfully decrypted
                  → b.apk extracted: 5.7 MB
                  → HTML overlay files identified
                  → installing.html (fake Google Play UI)
                  → acs_*.html (banking overlays)

2026-06-24 06:38  b.apk structure analyzed
                  → AndroidManifest + classes.dex: password-encrypted ZIP
                  → AfhQlBuxfo asset identified
                  → Decryption confirmed: same seed + format

2026-06-24 06:40  b_classes.dex decrypted: 5.18 MB, 4,522 classes
                  → Package: com.d9fe4v4.pmpgv.eai.uszaw confirmed
                  → e0 (WebSocket C2) class found
                  → dqssgbaajsdc (Accessibility RAT) confirmed
                  → FFmpegKit (screen recording) found

2026-06-24 06:45  String decryption algorithm reversed
                  → l50.b() = repeating-key XOR
                  → All DEX strings decrypted
                  → C2 path: /yaarsa/private/yarsap_80541.php
                  → C2 error log: /yaarsa/private/log_error.php

2026-06-24 06:50  C2 command protocol fully decoded
                  → 30+ commands identified
                  → WebSocket message format: CMD<:CS:>DATA
                  → Authentication markers: [AST-PAS], [:K3R1:]

2026-06-24 06:55  .bt file analysis
                  → Format: Base64(AES_ENCRYPTED)
                  → Key: rckey (runtime, from C2)
                  → Cannot decrypt statically — confirmed

2026-06-24 07:00  cht.html analyzed
                  → Operator chat interface
                  → mybridge.sendit() Java bridge (no URL in HTML)
                  → C2 URL in native Java only

2026-06-24 07:12  PDF report generated (146 KB)

2026-06-24 07:30  GitHub repository prepared

```

---

## 📊 Malware Version History (Inferred)

| Version | Evidence | Notes |
|---------|----------|-------|
| 1.5.4 | `VERSION_NAME` in BuildConfig | Current sample |
| Build 460 | `VERSION_CODE` in BuildConfig | High build number → active development |

The build number 460 suggests this is a **mature, actively maintained** piece of malware — not a first release.

---

## 🌍 Geographic Distribution (Inferred)

Multi-language strings found in the Stage 3 binary suggest deployment across multiple countries:

| Language | Strings Found |
|----------|--------------|
| English | Primary UI |
| Spanish | "Buscando actualizaciones", "Ingrese la contraseña" |
| Portuguese | "Procurando atualizações", "Por favor, aguarde" |
| Turkish | "Güncellemeler aranıyor", "Lütfen bekleyin" |

The Bangladesh / bKash targeting is confirmed by the incident. Other language strings indicate this is either a **commercial malware kit** used by different threat actors globally, or a single group targeting multiple markets.
