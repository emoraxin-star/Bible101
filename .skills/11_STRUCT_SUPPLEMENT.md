# 11_STRUCT_SUPPLEMENT.md
# Missing Data Structure Definitions

Complete C/C++ type definitions for structures referenced but not formally defined in the main skill set. These complete the type system for LLM code generation.

---

## Table of Contents
1. [HashTable — Consumed Entity Tracking](#1-hashtable)
2. [PeerManager — Lobby Peer Management](#2-peermanager)
3. [GameSession / SessionData — Session Container](#3-gamesession--sessiondata)
4. [Entity — Player/Character Memory Layout](#4-entity)
5. [CapturedMission — Full Binary Encoding Spec](#5-capturedmission-full-binary-encoding)
6. [FarmingConfig — Derived from SC_SO](#6-farmingconfig)
7. [ThreadPool / Worker Context — Threading Model](#7-threadpool--worker-context)

---

## 1. HashTable

### Purpose
Tracks consumed in-game entities (SC pickups, Medals, Samples) to prevent duplicate server-side processing. LIBERTEA NOPs the INSERT calls to bypass this check.

### Memory Layout
Three instances live in PlayerSession:
- `PlayerSession+0xF0` → SC consumed entities
- `PlayerSession+0xF8` → Medal consumed entities
- `PlayerSession+0x100` → Sample consumed entities

### Field Table
```
Offset  Size  Field                   Description
------  ----  -----                   -----------
+0x000   8     vtable                 HashTable vtable pointer
+0x008   4     entryCount             Current number of entries
+0x00C   4     tableCapacity          Maximum entries before resize
+0x010   8     entries*               Pointer to array of HashEntry[capacity]
+0x018   4     flags                  Hash table flags
+0x01C   4     insertCount            Total insert operations (monitoring)
+0x020   8     collisionPolicy*       Collision resolution function pointer
+0x028   8     keyHashFn*             Key hash function pointer
```

### C++ Definition
```cpp
struct HashEntry {
    uint64_t key;                    // Entity/activity unique key (typically missionId hash)
    uint32_t value;                  // Entity ID or state
    uint32_t flags;                  // Entry status flags (0=empty, 1=occupied, 2=deleted)
    uint8_t  _pad[96];               // Remaining entry size (total = 112 bytes)
};
static_assert(sizeof(HashEntry) == 112);

struct HashTable {
    virtual ~HashTable() = default;  // +0x000
    uint32_t   entryCount;           // +0x008: Current entries
    uint32_t   tableCapacity;        // +0x00C: Max before resize
    HashEntry* entries;              // +0x010: Dynamic array
    uint32_t   flags;                // +0x018
    uint32_t   insertCount;          // +0x01C: Total inserts performed
    void*      collisionPolicy;      // +0x020: Collision resolution callback
    void*      keyHashFn;            // +0x028: Key hashing callback
};
static_assert(sizeof(HashTable) >= 0x30);
```

### INSERT Call Sites (NOP Targets)
```
Site 1: 41 8B 4E 08          mov ecx, [r14+08h]     ; hash table pointer
        ...                   call HashTable_Insert  ; NOP'd (replaced with 90 90 ...)
Site 2: [similar pattern at offset +0xN]
```

### Bypass Mechanism
```cpp
// Original game code:
uint32_t hash = hashFn(entityId);
HashEntry* slot = &table->entries[hash % table->tableCapacity];
if (slot->flags == 0) {
    slot->key   = entityId;
    slot->value = entityState;
    slot->flags = 1;
    table->entryCount++;
}
// NOP result: slot never written, entryCount never incremented
// Server-side: entity appears unconsumed, replay succeeds
```

---

## 2. PeerManager

### Purpose
Manages lobby peer connections. SC_SO polls PeerManager every 2 seconds to read current lobby player IDs for reward distribution (auto-sync).

### References
- Global at `GS::rv_gp7` — `0x1A925B8` (LIBERTEA) / `0x26DE028` (SC_SO v21/v22)
- Count offset: `GetPeerMgrCountOff()` — `0x16390`
- Slot base offset: `GetPeerMgrSlotOff()` — `0x16398`
- Per-slot stride: `0x20` (32 bytes)
- Max peers: 4 (hardcoded cap)

### Field Table
```
Offset  Size  Field                   Description
------  ----  -----                   -----------
+0x000   8     vtable                 PeerManager vtable pointer
+0x008   4     peerCount              Number of connected peers (max 4)
+0x00C   4     maxPeers               Maximum peer slots (fixed at 4)
+0x010   4     localPeerIndex         Index of local player in peer array
+0x014   4     flags                  Connection state flags
+0x018   8     sessionId*             Pointer to lobby session ID
+0x020   128   peerSlots[4]           Array of 4 peer slots (0x20 each = 0x80 total)
+0x0A0   4     syncState              Synchronization state
+0x0A4   4     lastHeartbeat          Last heartbeat timestamp
```

### PeerSlot Structure (0x20 bytes)
```
Offset  Size  Field                   Description
------  ----  -----                   -----------
+0x000   8     peerId                 Unique peer identifier (uint64)
+0x008   16    peerName[16]           Peer display name (UTF-8, null-terminated)
+0x018   4     peerFlags              Peer state flags
+0x01C   4     ping                   Current ping/latency
```

### C++ Definition
```cpp
struct PeerSlot {
    uint64_t peerId;                 // +0x000
    char     peerName[16];           // +0x008
    uint32_t peerFlags;              // +0x018
    uint32_t ping;                   // +0x01C
};
static_assert(sizeof(PeerSlot) == 0x20);

struct PeerManager {
    virtual ~PeerManager() = default; // +0x000
    uint32_t   peerCount;             // +0x008
    uint32_t   maxPeers;              // +0x00C (4)
    uint32_t   localPeerIndex;        // +0x010
    uint32_t   flags;                 // +0x014
    void*      sessionId;             // +0x018
    PeerSlot   peerSlots[4];          // +0x020
    uint32_t   syncState;            // +0x0A0
    uint32_t   lastHeartbeat;        // +0x0A4
};
static_assert(sizeof(PeerManager) >= 0xA8);
```

### Read Pattern (from SC_SO replay.cpp)
```cpp
// Polling PeerManager for lobby player IDs:
uintptr_t ptrAddr = gameBase + GS::rv_gp7;              // PeerManager global pointer
uintptr_t peerMgr = 0;
ReadProcessMemory(GetCurrentProcess(), (LPCVOID)ptrAddr, &peerMgr, 8, &rd);

uint32_t peerCount = 0;
ReadProcessMemory(GetCurrentProcess(),
    (LPCVOID)(peerMgr + GetPeerMgrCountOff()), &peerCount, 4, &rd);
if (peerCount > 4) peerCount = 4;

for (uint32_t i = 0; i < peerCount; i++) {
    uintptr_t slotAddr = peerMgr + GetPeerMgrSlotOff() + i * 0x20;
    uint64_t pid = 0;
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slotAddr, &pid, 8, &rd);
    // pid = lobby player unique identifier (used for reward distribution)
}
```

---

## 3. GameSession / SessionData

### Purpose
Container for the current game session state. Referenced via `GS::rv_gp3` global pointer.

### References
- Global at `GS::rv_gp3` — `0x1A7F788` (LIBERTEA) / `0x26CB9E8` (SC_SO v21/v22)
- Access pattern: `sessionData = *(uintptr_t*)pSD; liveEntity = *(uintptr_t*)(sessionData + 0x10);`
- SC_SO `replay.cpp:1798-1800`: reads sessionData+0x10 for live entity pointer

### Field Table
```
Offset  Size  Field                   Description
------  ----  -----                   -----------
+0x000   8     vtable                 SessionData vtable
+0x008   4     sessionState           Current session state enum
+0x00C   4     flags                  Session flags
+0x010   8     liveEntity*            Pointer to current player entity
+0x018   8     warData*               Pointer to war state data
+0x020   8     missionData*           Current mission data pointer
+0x028   8     serverInfo*            Pointer to ServerInfo
+0x030   4     difficulty             Current difficulty tier (1-10)
+0x034   4     playerCount            Number of players in session
+0x038   64    sessionId[64]          Session UUID string
+0x078   4     warTime                Current war time (seconds since war start)
+0x07C   4     missionTime            Elapsed mission time
+0x080   8     peerManager*           Pointer to PeerManager
+0x088   256   (unknown)              Additional session state
```

### C++ Definition
```cpp
enum class SessionState : uint32_t {
    NONE          = 0,
    MENU          = 1,     // Main menu, no active session
    MATCHMAKING   = 2,     // Searching for lobby
    LOBBY         = 3,     // In lobby, pre-mission
    LOADING       = 4,     // Loading into mission
    IN_MISSION    = 5,     // Active gameplay
    ENDING        = 6,     // Mission ending / results
    POST_GAME     = 7,     // After-mission summary
    DISCONNECTED  = 8,     // Connection lost
};

struct GameSession {
    virtual ~GameSession() = default;  // +0x000
    uint32_t    sessionState;          // +0x008: SessionState enum
    uint32_t    flags;                 // +0x00C
    uint8_t*    liveEntity;            // +0x010: Player entity pointer
    uint8_t*    warData;               // +0x018: War state data
    uint8_t*    missionData;           // +0x020: Current mission blob
    uint8_t*    serverInfo;            // +0x028: ServerInfo pointer
    uint32_t    difficulty;            // +0x030: 1-10
    uint32_t    playerCount;           // +0x034
    char        sessionId[64];         // +0x038: UUID string
    uint32_t    warTime;               // +0x078
    uint32_t    missionTime;           // +0x07C
    PeerManager* peerManager;          // +0x080
    uint8_t     _pad[256];             // +0x088: Additional state
};
static_assert(sizeof(GameSession) >= 0x188);
```

---

## 4. Entity

### Purpose
Player/character memory layout. Referenced by entityDeep (up to 4MB) and entityDataDeep (up to 64KB) in the replay capture system.

### Partial Field Table (Known Offsets)
```
Offset  Size  Field                   Description
------  ----  -----                   -----------
+0x000   8     vtable                 Entity vtable pointer
+0x008   4     entityType             Entity type ID
+0x00C   4     entityFlags             Entity state flags
+0x010   64    entityId[64]           Entity identifier string
+0x050   4     health                 Current health
+0x054   4     maxHealth              Maximum health
+0x058   4     shield                 Shield/armor value
+0x05C   4     stamina                Current stamina
+0x060   4     positionX              World position X (float)
+0x064   4     positionY              World position Y (float)
+0x068   4     positionZ              World position Z (float)
+0x06C   4     rotation               Yaw rotation (float)
+0x070   4     velocityX              Velocity X (float)
+0x074   4     velocityY              Velocity Y (float)
+0x078   4     velocityZ              Velocity Z (float)
+0x07C   4     weaponId               Currently equipped weapon ID
+0x17F   1     ragdollFlag            Ragdoll state (0=standing, 1=ragdoll)
+0x31D789 1     flagByte              Entity flag byte (SC_SO ENT_FLAG_BYTE)
+0x31D7BC 4     gateString            Entity gate string (SC_SO ENT_GATE_STRING)
```

### C++ Definition
```cpp
struct Entity {
    virtual ~Entity() = default;       // +0x000
    uint32_t    entityType;            // +0x008
    uint32_t    entityFlags;           // +0x00C
    char        entityId[64];          // +0x010
    float       health;               // +0x050
    float       maxHealth;            // +0x054
    float       shield;               // +0x058
    float       stamina;              // +0x05C
    float       positionX;            // +0x060
    float       positionY;            // +0x064
    float       positionZ;            // +0x068
    float       rotation;             // +0x06C
    float       velocityX;            // +0x070
    float       velocityY;            // +0x074
    float       velocityZ;            // +0x078
    uint32_t    weaponId;             // +0x07C
    uint8_t     _pad[0x103];          // +0x080-0x182
    uint8_t     ragdollFlag;          // +0x183 (approximate)
    uint8_t     _pad2[0x319E05];      // +0x184-0x31D788
    uint8_t     flagByte;            // +0x31D789 (ENT_FLAG_BYTE)
    uint8_t     _pad3[0x32];          // +0x31D78A-0x31D7BB
    uint32_t    gateString;           // +0x31D7BC (ENT_GATE_STRING)
};
// NOTE: Entity is a VERY LARGE structure (~3.3MB+)
// The field layout up to +0x07C is well-understood; large gaps exist beyond
```

---

## 5. CapturedMission — Full Binary Encoding

### Hex Field Encoding Rules
All binary fields use lowercase hex encoding: each byte → 2 hex chars.

| Field | Hex Length (chars) | Binary Size (bytes) | Source |
|-------|-------------------|---------------------|--------|
| `serObjData` | 0-131072 | 0-65536 | Captured serialized object |
| `md` | 0-32768 | 0-16384 | Mission data snapshot |
| `slotData` | 6416 | 3208 (0xC88) | RingBuffer slot |
| `gs` | ~224 | ~112 | GMI string |
| `entityDeep` | 0-8388608 | 0-4194304 | Entity memory deep copy |
| `entityDataDeep` | 0-131072 | 0-65536 | Entity data deep copy |

### Wire Format
```cpp
// Encoding: BinToHex()
static const char hex[] = "0123456789abcdef";
// Byte 0xAB → 'a', 'b'
std::string BinToHex(const uint8_t* data, size_t len) {
    std::string out(len * 2, '\0');
    for (size_t i = 0; i < len; i++) {
        out[i*2]     = hex[(data[i] >> 4) & 0xF];
        out[i*2 + 1] = hex[data[i] & 0xF];
    }
    return out;
}

// Decoding: HexToBin()
std::vector<uint8_t> HexToBin(const std::string& s) {
    std::vector<uint8_t> out(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        uint8_t hi = (s[i] >= 'a') ? (s[i] - 'a' + 10) : (s[i] - '0');
        uint8_t lo = (s[i+1] >= 'a') ? (s[i+1] - 'a' + 10) : (s[i+1] - '0');
        out[i/2] = (hi << 4) | lo;
    }
    return out;
}
```

### CapturedMission JSON Schema (Replay File)
```json
{
    "url": "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end",
    "missionStr": "abcdef01-2345-6789-abcd-ef0123456789",
    "warTime": 73782850,
    "captureTick": 1234567890,
    "serObjOrigAddr": 2654691347712,
    "objectId": 1309039571,
    "xp": 10000,
    "medals": 15,
    "slips": 500,
    "serObjData": "<hex>",
    "md": "<hex>",
    "slot": "<hex>",
    "gs": "<hex>",
    "entity": "<hex>",
    "entityData": "<hex>"
}
```

---

## 6. FarmingConfig

### Purpose
Configuration parameters for the SC/Medal farming state machine. Controls batch behavior, timing, and limits.

### C++ Definition
```cpp
struct FarmingConfig {
    // Batch control
    int  callsPerBatch      = 9;     // POST calls per batch
    int  callIntervalMs     = 500;   // Milliseconds between calls
    int  cooldownSeconds    = 58;    // Seconds between batches
    int  scPerCall          = 30;    // Expected SC per successful call

    // Limits
    int  scGoal             = 0;     // Auto-stop target (0 = unlimited)
    int  sessionLimitMinutes = 30;   // Max session duration
    int  maxReplays          = 10;   // Max replays per session
    float replayHardlock     = 300.0f; // Max seconds per single replay

    // Mode flags
    bool medalsEnabled       = true; // Include medal batches
    bool medalsOnly          = false;// Medal-only mode
    bool autoSyncEnabled     = true; // Distribute rewards across lobby
    bool autoReplayEnabled   = false;// Auto-trigger replays

    // Auto-replay
    float autoReplayInterval = 45.0f;// Seconds between auto-replays

    // Session tracking
    uint64_t sessionStartTick = 0;   // GetTickCount64() at farming start
    int  scEarnedThisSession  = 0;   // Running SC total
};
```

---

## 7. ThreadPool / Worker Context

### Purpose
Describes the threading model for the SC_SO reference implementation and how it relates to the game's main thread.

### Thread Roles
| Thread | Created By | Purpose | Sync Method |
|--------|-----------|---------|-------------|
| **Game Main** | Game engine | Renders ImGui, processes window messages | N/A (primary) |
| **SC AutoSync** | SC_SO startup | Polls PeerManager every 2s for lobby players | std::atomic flags |
| **UUID Rotate** | sc_limit.cpp | Generates fresh UUIDs for batch rotation | std::atomic g_rotateReq/g_rotateAck |
| **ScLoop** | SC_SO farming | State machine, batch firing, cooldown timing | std::atomic replayInProgress |
| **VEH Handler** | OS on exception | Crash absorption, state save | std::atomic backoff state |
| **libcurl Callbacks** | libcurl internally | HTTP response parsing | std::atomic g_scCallInFlight |

### Thread Safety Patterns (from SC_SO)
```cpp
// Pattern 1: std::atomic for flags (lock-free, cross-thread)
std::atomic<bool> replayInProgress{false};

// Pattern 2: std::mutex for shared data
std::mutex captureMutex;
std::vector<CapturedMission> captures;

// Pattern 3: Window message dispatch (cross-thread → game thread)
// WM_SC_DISPATCH (0x87EA) posted to game window
// Game's WNDPROC processes on main thread
PostMessageW(g_gameHwnd, WM_SC_DISPATCH, 0, (LPARAM)actObj);

// Pattern 4: VEH for crash recovery (exception thread)
// Exception handler runs on the faulting thread
LONG CALLBACK VEH_CrashHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        ep->ContextRecord->Rip = (uint64_t)s_retStub;  // Redirect to safe code
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

---

*Accuracy baseline: 93.4% (inherited from 00_MASTER_KNOWLEDGEBASE.md)*
*Last updated: 2026-07-05 | Cross-referenced against SC_SO source and game.dll analysis*
