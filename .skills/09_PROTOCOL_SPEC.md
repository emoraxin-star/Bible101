# Protocol Specification — LIBERTEA.DLL C2 & SC/Medal Farming

Formal specification of all network protocols used by LIBERTEA v414 and the SC_SO reference implementation.

---

## Table of Protocols

1. [C2 Auth Protocol](#1-c2-auth-protocol)
2. [C2 Update Protocol](#2-c2-update-protocol)
3. [Game API — Mission End](#3-game-api--mission-end)
4. [f2s7 Anti-MITM Protocol](#4-f2s7-anti-mitm-protocol)
5. [SC/Medal Farming State Machine](#5-scmedal-farming-state-machine)
6. [Replay Capture File Format](#6-replay-capture-file-format)
7. [Session File Format](#7-session-file-format)

---

## 1. C2 Auth Protocol

### Endpoint
```
POST https://libertea.libertea4.workers.dev/auth
```

### Request
```json
{
    "user": "<username/email>",
    "p": "<password_sha256_hex>",
    "hwid": "<hardware_id_hex>",
    "t": "<client_timestamp>"
}
```

**Field Specifications:**
| Field | Type | Max Length | Description |
|-------|------|-----------|-------------|
| `user` | string | 64 | Username or email |
| `p` | string | 64 | SHA-256 hex digest of password (NOT plaintext) |
| `hwid` | string | 32 | `Crypto::GetHardwareId()` output, derived from `MachineGuid` registry key |
| `t` | string | 16 | Client timestamp (Unix seconds or ms since epoch) |

### Response (Success)
```json
{
    "status": "Active",
    "expiry": 1735689600,
    "tier": "premium",
    "token": "<jwt_bearer_token>"
}
```

### Response (Failure)
```json
{
    "status": "<error_code>",
    "message": "<error_description>"
}
```

### Auth State Enum
```cpp
enum AuthState : uint32_t {
    AUTH_UNKNOWN          = 0,
    AUTH_CHECKING         = 1,
    AUTH_SUCCESS          = 2,
    AUTH_FAIL_INVALID_KEY = 3,
    AUTH_FAIL_EXPIRED     = 4,
    AUTH_FAIL_NETWORK     = 5,
    AUTH_FAIL_REVOKED     = 6,
    AUTH_FAIL_VERSION     = 7,
    AUTH_FAIL_SERVER      = 8,
    AUTH_FAIL_TIMEOUT     = 9,
    AUTH_FAIL_RATE_LIMIT  = 10,
    AUTH_SUCCESS_CACHED   = 11,
};
```

### HWID Derivation
- Source: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
- Method: `Crypto::GetHardwareId` at RVA 0x34D40
- Output: 32-char hex string derived from MachineGuid via hash/transform
- Purpose: Binds subscriptions to specific machine

### Session Expiration
- Server returns `{"status":"Expired"}` with `expiry` timestamp
- Client handler at RVA 0x20064 (`AuthClient::SessionExpiredHandler`, 4299 bytes)
- On 401 response: displays `"Session expired or access revoked. Contact TheOGcup."`

---

## 2. C2 Update Protocol

### Version Check
```
GET https://libertea.libertea4.workers.dev/menu/version
```
**Response:** Plain text integer string
```
"15"
```

### Download
```
GET https://libertea.libertea4.workers.dev/menu/download
```
**Response:** Raw DLL binary (application/octet-stream)

### Update Flow
```
1. Read local version from LIBERTEA.version file
2. GET /menu/version → compare integer
3. If remote > local:
   a. GET /menu/download → download to .tmp file
   b. MoveFileExW(.tmp, LIBERTEA.dll, MOVEFILE_REPLACE_EXISTING)
   c. Relaunch with --retry argument
4. If remote <= local: continue normally
```

---

## 3. Game API — Mission End

### Endpoint
```
POST https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end
```

### HTTP Headers
| Header | Value | Required |
|--------|-------|----------|
| `Authorization` | `Bearer <jwt_token>` | Yes |
| `X-Session` | `<session_id>` | Yes |
| `X-Signature` | `<f2s7_hmac_hex>` | Yes |
| `Content-Type` | `application/json` | Yes |
| `Cookie` | `<session_cookies>` | Yes |
| `X-Auth` | `<auth_token>` | Optional |
| `X-Token` | `<extra_token>` | Optional |
| `Accept` | `application/json` | Optional |

### Request Body
```json
{
    "missionId": "abcdef01-2345-6789-abcd-ef0123456789",
    "entityDataDeep": "<hex_encoded_entity_data>",
    "entityDeep": "<hex_encoded_entity_hierarchy>",
    "capturedWarTime": 1728000,
    "ac": 3,
    "oi": 1,
    "serObj": "<hex_encoded_serialized_object>",
    "slotData": "<hex_encoded_weapon_slots>",
    "md": "<hex_encoded_mission_data>",
    "gs": "<hex_encoded_game_state>"
}
```

**Field Specifications:**
| Field | Type | Size Range | Description |
|-------|------|-----------|-------------|
| `missionId` | UUID (string) | 36 chars | Unique mission identifier. Rotated per batch for replay. |
| `entityDataDeep` | hex string | 0-131072 chars (0-64KB) | Deep copy of entity data state |
| `entityDeep` | hex string | 0-8388608 chars (0-4MB) | Deep copy of entity memory hierarchy |
| `capturedWarTime` | uint64 | 8 bytes | Game war time at capture, extracted from missionData+0x38 |
| `ac` | uint32 | 4 bytes | Activity count / flag |
| `oi` | uint32 | 4 bytes | Objective index (e.g., `1309039571`) |
| `serObj` | hex string | 0-131072 chars (0-64KB) | Serialized object data from ring buffer slot |
| `slotData` | hex string | 6,416 chars (3,208 bytes) | Ring buffer slot (0xC88 bytes) |
| `md` | hex string | 0-32768 chars (0-16KB) | Mission data snapshot |
| `gs` | hex string | ~224 chars (112 bytes) | Game state / GMI string |

### Response (Success)
```json
{
    "amount": 30,
    "currency": "super_credit",
    "newBalance": 450,
    "missionRewards": {
        "sc": 30,
        "medals": 0,
        "xp": 150,
        "slips": 500
    }
}
```

**Field Specifications:**
| Field | Type | Description |
|-------|------|-------------|
| `amount` | int32 | SC awarded this call |
| `currency` | string | Currency type ("super_credit", "medal", etc.) |
| `newBalance` | int32 | New total balance after award |
| `missionRewards.sc` | int32 | Super Credits reward |
| `missionRewards.medals` | int32 | Medals reward |
| `missionRewards.xp` | int32 | XP reward |
| `missionRewards.slips` | int32 | Requisition Slips reward |

### Response (Failure)
```json
{
    "error": "<error_code>",
    "message": "<description>"
}
```

---

## 4. f2s7 Anti-MITM Protocol

### Overview
Custom anti-MITM signature protocol that encrypts and authenticates server responses.

### Crypto Components
- **SHA-256**: `BCryptHashData` from `bcrypt.dll`
- **AES-CBC**: `ChainingModeCBC` via bcrypt
- **HMAC-SHA256**: Response authentication
- **Key**: 32-byte session key, rotated per session, embedded in `.rdata`

### Protocol Flow
```
1. Client sends request with X-Signature header
2. Cloudflare Workers proxy:
   a. Decrypts request body
   b. Validates HMAC-SHA256 signature
   c. Forwards to game API server
3. Game API responds with JSON
4. Cloudflare Workers:
   a. Encrypts response with AES-CBC
   b. Signs with HMAC-SHA256
   c. Returns encrypted body
5. Client:
   a. Verifies HMAC-SHA256 signature
   b. Decrypts AES-CBC body
   c. Parses JSON response
```

### Signature Header
```
X-Signature: <hex_encoded_hmac>
```
- HMAC-SHA256 of request body
- Nonce captured via BCryptHashData hook (8-byte nonce, 512-byte key)
- Re-computed per request with updated missionId

### MITM Detection (14 tools)
Process scan for:
- Fiddler (`Fiddler.exe`, `FiddlerCore.dll`)
- mitmproxy (`mitmdump.exe`, `mitmproxy.exe`)
- Burp Suite (`burp*.exe`, `burploader*.jar`)
- Charles Proxy (`Charles.exe`)
- Proxyman (`Proxyman.exe`)
- Wireshark (`Wireshark.exe`, `tshark.exe`)
- HTTP Debugger (`HTTPDebugger*.exe`)
- Proxifier, ProxyCap, SocksCap, EasyHook, WinPcap, Npcap, RawCap

### bcrypt.dll Hooks (Patterns #72 and #73)
```cpp
// Hook on BCryptHashData captures signing material
// Pattern for nonce detection:
//   First call to BCryptHashData → 8-byte nonce
//   Subsequent calls → 512-byte key material
// Pattern for chunked detection:
//   Call 1: hashUpdate(nonce, 8)
//   Call 2: hashUpdate(key, 512)
```

---

## 5. SC/Medal Farming State Machine

### States
```cpp
enum FarmState : uint32_t {
    IDLE              = 0,   // Not farming
    CHECK_SESSION     = 1,   // Validate game session is active
    MONITORING        = 2,   // Waiting for session to be ready
    SC_BATCH_FIRING   = 3,   // Firing SC activity batch
    MEDAL_BATCH_FIRING = 4,  // Firing Medal activity batch
    BATCH_RESULTS     = 5,   // Processing batch results
    COOLDOWN          = 6,   // 58-second inter-batch cooldown
    GOAL_CHECK        = 7,   // Check if SC goal reached
    CRASH_RECOVERY    = 8,   // Recover from crash
    USER_OFF          = 9,   // User disabled farming
    GOAL_REACHED      = 10,  // SC goal achieved
    SESSION_LIMIT     = 11,  // Session time limit reached
    BAIL              = 12,  // Unrecoverable error
};
```

### State Transition Diagram
```
IDLE → CHECK_SESSION → MONITORING → SC_BATCH_FIRING
                                    ↕
                              MEDAL_BATCH_FIRING
                                      ↓
                                BATCH_RESULTS
                                      ↓
                                  COOLDOWN (58s)
                                      ↓
                                 GOAL_CHECK
                                 ↙        ↘
                        GOAL_REACHED    SC_BATCH_FIRING
                        (or SESSION_LIMIT)  (loop)

Any state → CRASH_RECOVERY → (return to prior state)
Any state → USER_OFF → IDLE
Persistent failure → BAIL (unrecoverable)
```

### Activity Object IDs
| Activity | Object ID | Description |
|----------|-----------|-------------|
| Super Credits | `0x7F8FE16` (133693462) | SC activity call |
| Medals | `0xA2C8A4E` (170815566) | Medal activity call |

### Batch Timing
```
Batch size:     9 calls
Interval:       500ms between calls
Batch duration: 4.5 seconds (9 × 500ms)
Cooldown:       58 seconds between batches
Cycle time:     62.5 seconds (4.5 + 58)
SC per cycle:  ~90-270 SC (at ~10-30 SC/mission)
SC per hour:   ~86-260 SC (slower if medal batches interleaved)
```

### Mission ID Management
```cpp
// TryAutoDetectMissionId()
//   Scans all writable memory for the golden mission ID string
//   Uses CreateFileMapping-backed shared memory regions
//   Returns list of candidate addresses

// WriteMidUUID()
//   Writes a fresh UUID to all discovered hit locations
//   UUID generated via CoCreateGuid → formatted as string

// ValidateMissionStruct()
//   Reads struct fields at candidate address
//   Checks: missionStr matches expected format, warTime > 0
//   Returns true if valid mission structure
```

### Farming Config Parameters
```cpp
struct FarmingConfig {
    int  scGoal;              // Auto-stop when SC earned >= this (0 = no limit)
    int  sessionLimitMinutes; // Max farming session duration (default 30)
    int  maxReplays;          // Max replays per session (default 10)
    int  cooldownSeconds;     // Between batches (default 58)
    int  autoReplayInterval;  // Between auto-replays (default 45)
    bool medalsEnabled;       // Include medal batches
    bool medalsOnly;          // Medal-only mode
};
```

---

## 6. Replay Capture File Format

### File Location
```
C:\libertea_replay_cap.json   (LIBERTEA)
<dll_dir>\replay_cap.json     (SC_SO)
```

### JSON Schema
```json
{
    "url": "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end",
    "missionStr": "abcdef01-2345-6789-abcd-ef0123456789",
    "warTime": 73782850,
    "captureTick": 1234567890,
    "serObjAddr": 2654691347712,
    "serObjSize": 65536,
    "objectId": 1309039571,
    "xp": 10000,
    "medals": 15,
    "slips": 500,
    "entSize": 4194304,
    "entDataSize": 65536,
    "mdSize": 16384,
    "slotSize": 3208,
    "gsSize": 112,
    "serObjData": "<hex_encoded_binary>",
    "md": "<hex_encoded_binary>",
    "slot": "<hex_encoded_binary>",
    "gs": "<hex_encoded_binary>",
    "entity": "<hex_encoded_binary>",
    "entityData": "<hex_encoded_binary>"
}
```

**Field Details:**
| Field | Size in File | Binary Size | Source |
|-------|-------------|-------------|--------|
| `url` | variable | N/A | Captured from HTTP request |
| `missionStr` | 36+ | N/A | Mission UUID from game |
| `warTime` | ~10 | 4 bytes | `missionData[0x38]` |
| `captureTick` | ~10 | 8 bytes | `GetTickCount64()` |
| `serObjAddr` | ~13 | 8 bytes | Virtual address of serial object |
| `serObjData` | varchar | 0-65536 | Deep copy of serial object |
| `md` | varchar | 0-16384 | Mission data snapshot |
| `slot` | varchar | 3208 | Ring buffer slot |
| `gs` | varchar | 112 | Game state / GMI |
| `entity` | varchar | 0-4194304 | Entity memory deep copy |
| `entityData` | varchar | 0-65536 | Entity data deep copy |
| `xp`/`medals`/`slips` | ~5 | 4 bytes | Field Override defaults |

### Parse Method
No external JSON library. Uses manual string parsing:
```cpp
// extractStr(key): finds "\"key\": \"" then reads until next unescaped '"'
// extractNum(key): finds "\"key\": " then calls strtoull()
// Hex decoding: pairs of hex chars → bytes
```

---

## 7. Session File Format

### File Location
```
<dll_dir>\session.json
```

### JSON Schema
```json
{
    "sent": 150,
    "acked": 148
}
```

**Field Details:**
| Field | Type | Description |
|-------|------|-------------|
| `sent` | int32 | Total SC/Medal calls sent |
| `acked` | int32 | Calls that received successful response (HTTP 200) |

### Parse Method
```cpp
fscanf(f, "{\"sent\":%d,\"acked\":%d}", &sent, &acked);
```

---

## 8. Auth Server Endpoints (SC_SO / Future)

```cpp
// Version endpoint
GET  /menu/version
     → Response: integer string (e.g., "15")

// Download endpoint
GET  /menu/download
     → Response: raw DLL binary

// Auth endpoint
POST /auth
     Body: { "user": string, "p": string, "hwid": string, "t": string }
     Success: { "status": "Active"|"Lifetime", "expiry": uint64, "tier": string }
     Failure: { "status": "Expired"|"Invalid"|"Revoked", "message": string }
```

---

## Wire Format Notes

### Hex Encoding
All binary fields are encoded as lowercase hexadecimal strings:
```cpp
static const char hex[] = "0123456789abcdef";
// Each byte → 2 hex chars
// Example: 0xAB → "ab"
```

### UUID Format
Standard UUID string format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Generated via `CoCreateGuid` (Win32 COM)
- Variant: RFC 4122
- Converted to lowercase for consistency
