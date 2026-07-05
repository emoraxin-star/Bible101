# Network Protocol & SC/Medal Farming — LIBERTEA.DLL Skill

You are a network protocol and game farming specialist focused on **LIBERTEA.DLL**. Your expertise covers the SC/Medal replay attack protocol, HTTP capture/replay, f2s7 anti-MITM, auth system, and VEH crash recovery.

## Key References
- **Master Knowledgebase**: `.skills/00_MASTER_KNOWLEDGEBASE.md`
- **Docs**: `docs/05_network_protocol/sc_farming_analysis.txt`
- **Logs**: `logs/agentG_f2s7_spec.txt`

## HTTP Stack Architecture

### Priority Order
1. libcurl.dll → libcurl-x64.dll → curl.dll → wininet.dll
2. winhttp.dll (resolved via GetProcAddress)
3. wininet.dll (last resort fallback)

### Key Network Endpoints
| Endpoint | Purpose |
|----------|---------|
| `libertea.libertea4.workers.dev` | C2, Auth, Updates, Version |
| `api.live.prod.thehelldiversgame.com/api/Operation/Mission/end` | Game API (SC/Medal target) |
| `discord.gg/exCgdvYPxd` | Community/Distribution |

### SC_SO Source Implementation Details
The `SC_SO` reference implementation provides specific details on the HTTP interception layer:

**libcurl Hook Points**:
- `curl_easy_setopt`: Used to capture the target URL, POST body, and custom headers.
- `curl_easy_perform`: The primary intercept point to inject `missionId` and capture the response.
- `curl_easy_cleanup`: Used to release slot tracking for the curl handle.

**Response Parsing**:
- Uses a custom `CURLOPT_WRITEFUNCTION` callback to intercept the raw response body.
- Parses JSON to extract `amount`, `currency`, `newBalance`, and `missionRewards` (sc, medals, xp, slips).

**Signature Capture**:
- Hooks `BCryptHashData` from `bcrypt.dll` to capture the 8-byte signing nonce and 512-byte signing key used for the `X-Signature` header.

**Lobby Sync**:
- `SC_AutoSyncLoop` polls the `PeerManager` every 2 seconds to read current lobby player IDs, which are then injected into the mission payload to distribute rewards.

### API Endpoint Details
- Method: POST
- Content-Type: application/json
- Headers: Authorization (Bearer JWT), X-Session, X-Signature (f2s7), Cookie
- Body: ~2KB-8KB JSON with 10+ fields

## SC/Medal Farming Protocol

### The Attack: Replay
1. **Capture**: Hook libcurl write callback, intercept real Mission/end POST
2. **Store**: Save to `C:\libertea_replay_cap.json`
3. **Replay**: Send captured POST repeatedly with modified missionId
4. **Bypass**: NOP hash table INSERT calls to prevent duplicate detection

### State Machine
```
IDLE(0) → CHECK_SESSION(1) → MONITORING(2)
  → SC_BATCH(3) / MEDAL_BATCH(4)
  → BATCH_RESULTS(5) → COOLDOWN(6, 58s)
  → GOAL_CHECK(7) → repeat or GOAL_REACHED(10)
  ← CRASH_RECOVERY(8) from any state
  ← USER_OFF(9) → IDLE
  BAIL(12) = unrecoverable error
```

### Batch Pattern
- **9 POST calls** per batch
- **500ms** interval between calls
- **58-second cooldown** between batches
- Alternates between SC batches and Medal batches
- Auto-stops when user-defined SC goal reached

### JSON Payload Structure
```json
{
  "missionId": "<UUID>",
  "entityDataDeep": "<hex entity state>",
  "entityDeep": "<hex entity hierarchy>",
  "capturedWarTime": 1728000,
  "ac": 3,
  "oi": 1,
  "serObj": "<hex serialized object>",
  "slotData": "<hex weapon slots>",
  "md": "<hex mission data>",
  "gs": "<hex game state>"
}
```

### Anti-Duplicate Bypass
**Hash Table NOP**: Two INSERT call sites in game.dll are NOP-patched:
- `PlayerSession+0xF0`: SC consumed entity hash table
- `PlayerSession+0xF8`: Medal consumed entity hash table  
- `PlayerSession+0x100`: Sample consumed entity hash table

Without this bypass, the server rejects replayed mission completions because the client reports "entity already consumed."

### MIDSWAP
Mission ID is modified each batch to a new UUID value, making each batch appear as a different mission.

### Auto-Sync
Modifies POST body per-player to distribute SC across all lobby members.

### Timing Analysis
```
9 calls × 500ms = 4.5s per batch
+ 58s cooldown = 62.5s per cycle
SC per cycle: ~90-270 SC (at ~10-30 SC/mission)
Per hour: ~86-260 SC
Overnight (8h): ~700-2,080 SC
Value: $7-$21 worth of SC per night
```

## f2s7 Protocol

### Overview
- Custom anti-MITM signature protocol
- Server-side response encryption (Cloudflare Workers)
- HMAC-SHA256 signature verification
- 32-byte key rotated per session
- XOR + byte permutation + length encoding transform

### MITM Detection (14 tools)
Fiddler, mitmproxy, Burp Suite, Charles Proxy, Proxyman, Wireshark, HTTP Debugger + 7 others

### Crypto Components
- `bcrypt.dll`: SHA-256 hashing, AES-CBC (ChainingModeCBC)
- Patterns #72, #73 target bcrypt.dll functions
- Nonce-based key exchange between client and server

## Auth & Subscription System

### Login Flow
1. Login screen (`##lock_screen`) blocks main UI
2. Credentials: `##userinput`, `##passinput`, `##keyinput`
3. Password SHA-256 hashed via bcrypt
4. POST to Cloudflare Workers `/auth` endpoint
5. Body: `{"user":"...","p":"...","hwid":"...","t":"..."}`
6. Response: `{"status":"Active"|"Lifetime"|"Expired","expiry":...,"tier":"..."}`

### Auth States Enum
```
AUTH_UNKNOWN(0), AUTH_CHECKING(1), AUTH_SUCCESS(2),
AUTH_FAIL_INVALID_KEY(3), AUTH_FAIL_EXPIRED(4), AUTH_FAIL_NETWORK(5),
AUTH_FAIL_REVOKED(6), AUTH_FAIL_VERSION(7), AUTH_FAIL_SERVER(8),
AUTH_FAIL_TIMEOUT(9), AUTH_FAIL_RATE_LIMIT(10), AUTH_SUCCESS_CACHED(11)
```

### HWID Binding
- `Crypto::GetHardwareId` at RVA 0x34D40
- Derived from `MachineGuid` registry key
- Binds subscriptions to specific machine hardware

### Session Expiration
- `AuthClient::SessionExpiredHandler` at RVA 0x20064 (4299 bytes)
- Handles 401 responses
- Message: "Session expired or access revoked. Contact TheOGcup."

### Update Protocol
```
GET /menu/version → integer (e.g., "15")
GET /menu/download → raw DLL binary
Compare vs LIBERTEA.version → if newer: save .tmp, MoveFileExW atomic rename, relaunch with --retry
```

## VEH Crash Recovery System

### Registration
`AddVectoredExceptionHandler(1, VEH_CrashHandler)` — first in handler chain

### Handled Exceptions
- ACCESS_VIOLATION (0xC0000005)
- STACK_OVERFLOW (0xC00000FD)
- ILLEGAL_INSTRUCTION (0xC000001D)

### Recovery Flow
1. Save SC loop state (ring index, batch progress, replay data)
2. Increment crash counter
3. Write: `"=== LIBERTEA CRASH LOG ==="`
4. Restore loop state on next iteration
5. Watchdog resets stuck `replayInProgress` flag

## Game API Specifics

### Mission/end POST Headers
```
Authorization: Bearer <jwt>
X-Session: <sessionId>
X-Signature: <f2s7_sig>
Content-Type: application/json
Cookie: <sessionCookies>
```

### Response Parsing
```json
{"amount":30,"currency":"super_credit","newBalance":450,
 "missionRewards":{"sc":30,"medals":0,"xp":150,"slips":500}}
```

### Replay File Format
Saved to `C:\libertea_replay_cap.json` with 12 JSON fields including captured HTTP headers, request body, server response, mission ID, and reward data.

## Web Research Elevations

### Helldivers 2 Game Updates (Post-v414)
Since LIBERTEA v414 was analyzed, Helldivers 2 has received:
- **v6.2.2** (April 2026): SC pickup patched server-side. The "pick up SC from ground" exploit no longer works. However, the replay attack (resend Mission/end POSTs) continues to function if hash table NOP bypass remains effective.
- **v6.2.5** (May 2026): Further anti-exploit hardening. Unknown if replay bypass still functional.
- **Graphics**: FSR 3.1.5, DLSS 4.5, XeSS 3.0, NVIDIA Reflex, AMD Anti-Lag 2
- **Anti-cheat**: GameGuard updated with AOB-based pattern scanning for known cheat signatures

### Engine Context
- **Autodesk Stingray** (formerly Bitsquid), acquired 2014, discontinued 2018
- HD2 uses a heavily modified fork maintained in-house
- **Asset identification**: MurmurHash64A(`"path/to/resource"`) — 64-bit hash for all assets
- **Community API**: `api.helldivers2.dev` — public game data (separate from live game API)
- **Archive tool**: `Stingray-Explorer`, `filediver`, `hd2re` — extract `.exploded_dat` archives

### HD2 Community API
`GET https://api.helldivers2.dev` 
Alternative endpoint that provides game data without authentication. Useful for:
- Mapping war state changes
- Verifying reward values
- Understanding game mechanics without reverse engineering game.dll

### SC Farming Viability Assessment
| Factor | Status (2026) |
|--------|---------------|
| Server-side SC pickup | Patched v6.2.2 |
| Replay attack (Mission/end replay) | May still work (unknown post-v6.2.5) |
| Hash table NOP | GameGuard AOB scan could detect |
| VEH crash handling | Still effective if no process-level monitoring |
| Detection risk | Increased — GameGuard kernel scanning detects injected DLLs |

### Protocol Analysis Tools
Modern toolkit for reverse engineering Helldivers 2's network protocol:
- **mitmproxy / BetterCap**: SSL interception (bypass f2s7 if local)
- **Wireshark**: Capture game API traffic on loopback
- **API Logger**: Proxy all game HTTP calls via custom local proxy
- **frida**: Inject JavaScript into game process to intercept function calls

### f2s7 Protocol Weakness (Updated)
The f2s7 protocol's reliance on bcrypt.dll means both hooks (#72, #73) are single points of failure:
- If GameGuard detects bcrypt.dll modifications, f2s7 verification breaks
- Server-side decryption at Cloudflare Workers means all traffic decrypts at CF edge → CF can log all traffic
- **Architecture weakness**: Single Cloudflare Workers account = single takedown target

## ScActivityAPC Structure
```
+0x00: vtable pointer
+0x08: actId32 (activity ID)
+0x0C: objId (object ID)
+0x10: ctr (control/state counter)
+0x14: flag (flags)
+0x18: ring (ring buffer index)
+0x20: url[0x40] (API URL)
+0x60: qDelta (queue delta)
+0x64: retry (retry count)
+0x68: missionData pointer
+0x70: missionId[0x40] (UUID)
```
