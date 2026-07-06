# Structure Definitions — LIBERTEA.DLL / SC_Replay_Source

Complete C/C++ type definitions for all critical game and cheat structures. These are the ground-truth layouts used by both LIBERTEA v414 and the SC_SO reference implementation.

---

## Game Engine Structures

### PlayerSession (game.dll)
Primary session object containing player state, activity queues, and hash tables.
```
Offset  Size  Field                    Description
------  ----  -----                    -----------
+0x000   8     vtable                  PlayerSession vtable pointer
+0x008   32    (unknown padding)
+0x028   56    primaryActivityRing     Ring buffer of ScActivityAPC* (278 code refs)
+0x060   8     missionData*            Pointer to current mission data blob
+0x068   8     missionDataSize         Size of mission data
+0x070   64    missionId[64]           UUID string of current mission (e.g., "abcdef01-...")
+0x0B0   64    (unknown padding)
+0x0F0   8     scConsumedHashTable*    Hash table of consumed SC entities (NOP target)
+0x0F8   8     medalConsumedHashTable* Hash table of consumed Medal entities (NOP target)
+0x100   8     sampleConsumedHashTable* Hash table of consumed Sample entities (NOP target)
+0x108   8     (unknown)
+0x110   4     commonSamples           Common sample count
+0x114   4     rareSamples             Rare sample count
+0x118   4     superSamples            Super sample count
+0x11C   4     (padding)
+0x120   8     (unknown)
+0x128   56    secondaryActivityRing   Secondary ring buffer
+0x130   8     serverInfo*             Pointer to ServerInfo struct
```

C++ Definition:
```cpp
struct PlayerSession {
    virtual ~PlayerSession() = default;          // +0x000: vtable
    /* +0x008-0x027: unknown */
    ScActivityAPC* primaryActivityRing[7];       // +0x028: 7-slot ring
    uint8_t*       missionData;                  // +0x060
    uint32_t       missionDataSize;              // +0x068
    char           missionId[64];                // +0x070
    /* +0x0B0-0x0EF: unknown */
    HashTable*     scConsumedEntities;           // +0x0F0
    HashTable*     medalConsumedEntities;        // +0x0F8
    HashTable*     sampleConsumedEntities;       // +0x100
    uint32_t       commonSamples;                // +0x110
    uint32_t       rareSamples;                  // +0x114
    uint32_t       superSamples;                 // +0x118
    /* +0x11C-0x127: unknown */
    ScActivityAPC* secondaryActivityRing[7];     // +0x128
    ServerInfo*    serverInfo;                   // +0x130
};
static_assert(sizeof(PlayerSession) >= 0x138);
```

### ScActivityAPC (game.dll)
Activity structure tracked in the ring buffer. Represents a single SC, Medal, or other activity call.
```
Offset  Size  Field                    Description
------  ----  -----                    -----------
+0x000   8     vtable                  ScActivityAPC vtable
+0x008   4     actId32                 Activity identifier hash
+0x00C   4     objId                   Object identifier (SC=0x7F8FE16, Medal=0xA2C8A4E)
+0x010   4     ctr                     Control/state counter
+0x014   4     flag                    Flags
+0x018   4     ring                    Ring buffer slot index (0-6)
+0x01C   4     (padding)
+0x020   64    url[64]                 API endpoint URL
+0x060   4     qDelta                  Queue delta/retry count
+0x064   4     retry                   Retry counter
+0x068   8     missionData*            Pointer to mission data
+0x070   64    missionId[64]           UUID string
```

C++ Definition:
```cpp
struct ScActivityAPC {
    virtual ~ScActivityAPC() = default;  // +0x000
    uint32_t actId32;                    // +0x008
    uint32_t objId;                      // +0x00C (SC=0x7F8FE16, Medal=0xA2C8A4E)
    uint32_t ctr;                        // +0x010
    uint32_t flag;                       // +0x014
    uint32_t ring;                       // +0x018
    char     url[64];                    // +0x020
    int32_t  qDelta;                     // +0x060
    int32_t  retry;                      // +0x064
    uint8_t* missionData;                // +0x068
    char     missionId[64];              // +0x070
};
static_assert(sizeof(ScActivityAPC) == 0xB0);
```

### ServerInfo (game.dll)
Global server information singleton containing ring buffers for activity queues.
```
Offset  Size  Field                    Description
------  ----  -----                    -----------
+0x000   8     vtable                  ServerInfo vtable
+0x008   4     ringIndex               Current ring buffer write index
+0x00C   4     (padding)
+0x010   8     ringBase*               Pointer to ring buffer array (RingSlot[64])
+0x018   4     flag                    Server info flags
+0x01C   4     (padding)
+0x020   64    url[64]                 Base API URL
+0x060   4     queueDelta              Queue processing delta
+0x064   4     (padding)
+0x068   8     requestBuffer*          Request queue buffer
```

C++ Definition:
```cpp
struct ServerInfo {
    virtual ~ServerInfo() = default;  // +0x000
    uint32_t  ringIndex;             // +0x008
    RingSlot* ringBase;              // +0x010 (array of 64)
    uint32_t  flag;                  // +0x018
    char      url[64];               // +0x020
    int32_t   queueDelta;            // +0x060
    uint8_t*  requestBuffer;         // +0x068
};
```

### RingSlot (game.dll)
Individual ring buffer slot containing mission activity data (0xC88 bytes).
```
Offset  Size  Field                    Description
------  ----  -----                    -----------
+0x000   4     flag                    Slot status flags
+0x004   4     typeHash                Activity type hash (e.g., 0x1E555EA6 = MissionEnd)
+0x008   4     version                 Slot version counter
+0x00C   4     (padding)
+0x010   3072  url[3072]               URL buffer
+0xC10   8     serialObj*              Pointer to serialized object
+0xC18   8     flags2                  Secondary flags
+0xC20   8     selfPtr                 Self-reference pointer
+0xC28   4     ready                   Ready state
+0xC2C   4     (padding)
+0xC30   48    (unknown)
+0xC60   4     sequence                Sequence number
+0xC64   4     (padding)
+0xC68   8     fixup*                  Entity fixup pointer
+0xC70   8     field_C70               (unknown)
+0xC78   8     entityData*             Entity data pointer
+0xC80   4     field_C80               (unknown)
+0xC84   4     field_C84               (unknown)
```

C++ Definition:
```cpp
struct RingSlot {
    uint32_t  flag;                    // +0x000
    uint32_t  typeHash;               // +0x004
    uint32_t  version;                // +0x008
    char      url[3072];              // +0x00C
    uint8_t*  serialObj;              // +0xC10
    uint64_t  flags2;                 // +0xC18
    uint64_t  selfPtr;                // +0xC20
    uint32_t  ready;                  // +0xC28
    uint32_t  sequence;               // +0xC60
    uint8_t*  fixup;                  // +0xC68
    uint64_t  field_C70;              // +0xC70
    uint8_t*  entityData;             // +0xC78
    uint32_t  field_C80;              // +0xC80
    uint32_t  field_C84;              // +0xC84
};
static_assert(sizeof(RingSlot) == 0xC88);
```

### WeaponStats (game.dll)
Weapon statistics structure targeted by the weapon editor.
```
Offset  Size  Field                    Description
------  ----  -----                    -----------
+0x000   48    (base stats)
+0x030   4     damage                  Weapon damage (float)
+0x034   4     penetration             Armor penetration (float)
+0x038   4     fireRate                Rate of fire (float)
```

C++ Definition:
```cpp
struct WeaponStats {
    uint8_t _pad[0x30];              // +0x000: base weapon stats
    float   damage;                   // +0x030
    float   penetration;              // +0x034
    float   fireRate;                 // +0x038
};
```

---

## Cheat Infrastructure Structures

### PatternEntry (LIBERTEA pattern table)
73-pattern hook database entry. 0x70 bytes each.
```cpp
enum class HookType : uint32_t {
    NOP_PATCH          = 0,  // Replace with 0x90 sled
    CODE_PATCH         = 1,  // Write custom code
    FUNCTION_PROLOGUE  = 2,  // Detour at function entry
    POINTER_RESOLVE    = 3,  // Read/modify pointer targets
    FUNCTION_RETURN    = 4,  // Patch return value (C3)
    CONDITIONAL_INVERT = 5,  // Flip JE/JNE
};

struct PatternEntry {
    uint32_t  patternId;             // Unique pattern identifier
    HookType  hookType;              // Hook type enum
    char      moduleName[16];        // Target module (e.g., "game.dll")
    char      featureName[16];       // Feature label (e.g., "GodMode")
    uint8_t   bytes[16];             // Pattern bytes
    uint8_t   mask[16];              // 0xFF=exact, 0x00=wildcard
    int32_t   offset;                // Added to matched address
    int32_t   patchSize;             // Bytes to write
    uint8_t   patchBytes[8];         // Replacement bytes
    uint64_t* pResolvedAddr;         // Runtime-resolved address
    uint64_t* pOriginalBytes;        // Saved original bytes
    bool      bResolved;             // Pattern matched
    bool      bInstalled;            // Hook installed
};
static_assert(sizeof(PatternEntry) == 0x70);
```

### AOBPattern (SC_SO scanner)
Array-of-Bytes pattern used for runtime scanning.
```cpp
struct AOBPattern {
    uint8_t         bytes[64];       // Pattern bytes (max 64)
    bool            mask[64];        // true=must match, false=wildcard
    uint32_t        length;          // Actual pattern length

    static AOBPattern parse(const char* idaPattern);
    // Parses "48 89 5C ?? 08 57 48 83" → bytes[] + mask[]
};
```

### SyscallStub (syscall infrastructure)
Describes a built syscall stub.
```cpp
struct SyscallStub {
    const char* functionName;        // NT function name (e.g., "NtAllocateVirtualMemory")
    uint32_t    syscallNumber;       // Resolved SSN
    uint8_t*    stubAddress;         // Address of built stub
    uint32_t    stubSize;            // Size of stub in bytes
    uint8_t     stubVariant;         // Which variant template was used (0-7)
    uint32_t    flags;               // Status flags
};
```

---

## SC_SO Capture & Replay Structures (from state.h)

### FieldOverride
Overrides for mission reward fields during replay.
```cpp
struct FieldOverride {
    int32_t  offset  = -1;           // Target field offset in mission data
    uint32_t value   = 0;            // Override value
    bool     enabled = false;        // Whether override is active
    char     label[32] = {};         // Display label ("XP", "Medals", "Slips")
};
```

### CapturedMission
Deep-copied mission state for replay.
```cpp
struct CapturedMission {
    uintptr_t serverInfo     = 0;    // Original serverInfo pointer
    uintptr_t entityPtr      = 0;    // Original entity pointer
    uintptr_t missionData    = 0;    // Original missionData pointer
    uintptr_t entityDataVal  = 0;    // Entity data pointer value
    uintptr_t entityVtable   = 0;    // Entity vtable pointer

    void*    entityDeepCopy      = nullptr;  // Deep copy of entity memory
    size_t   entityDeepCopySize  = 0;        // Up to 4MB
    void*    entityDataDeepCopy  = nullptr;  // Deep copy of entity data
    size_t   entityDataDeepCopySize = 0;     // Up to 64KB
    uint8_t  slotData[0xC88]     = {};       // Ring buffer slot snapshot
    std::vector<uint8_t> missionDataSnapshot; // Up to 16KB
    std::vector<uint8_t> serObjSnapshot;      // Up to 64KB
    uintptr_t serObjOrigAddr = 0;             // Original serial object address
    bool      valid          = false;         // Capture is usable
    uint64_t  captureTime    = 0;             // TickCount64 at capture
    char      missionStr[64] = {};            // Mission UUID
    char      url[256]       = {};            // API endpoint URL

    FieldOverride xpOverride     = {-1, 0, false, "XP"};
    FieldOverride medalsOverride = {-1, 0, false, "Medals"};
    FieldOverride slipsOverride  = {-1, 0, false, "Req.Slips"};
};
```

### ReplayState
Global replay engine state.
```cpp
struct ReplayState {
    std::atomic<bool> probeArmed{false};          // HW breakpoint probe active
    std::atomic<bool> hookInstalled{false};        // Hook installed flag
    std::atomic<bool> instantMissionEnabled{false}; // Instant complete active
    std::mutex captureMutex;
    std::vector<CapturedMission> captures;         // Captured missions (max 2)
    
    std::atomic<int>  replayCount{0};              // Total replays performed
    std::atomic<bool> replayInProgress{false};      // Replay currently executing
    float cooldownRemaining = 0.0f;                // Cooldown timer (58s default)
    float replayHardlock    = 300.0f;              // Max replay duration (300s)
    uint64_t lastReplayTick = 0;                   // Last replay timestamp
    
    bool autoReplayEnabled    = false;              // Auto-replay mode
    float autoReplayInterval  = 45.0f;              // Seconds between auto-replays
    bool sessionLimitEnabled  = false;              // Session time limit
    int  sessionLimitMinutes  = 30;                 // Default 30 min session
    bool replayLimitEnabled   = false;              // Replay count limit
    int  maxReplays           = 10;                 // Max replays per session
    
    std::atomic<bool> gatePatched{false};           // Game gate function patched
    uintptr_t gateAddress   = 0;                    // Gate function address
    uint8_t   gateOrigByte  = 0;                    // Original gate byte
    
    DWORD     gameThreadId    = 0;                  // Captured game thread ID
    HANDLE    gameThreadHandle = nullptr;            // Game thread handle
    uint32_t  capturedWarTime = 0;                  // War time at capture
    uint64_t  captureTickCount = 0;                 // Tick at capture
    
    uintptr_t gameBase      = 0;                    // game.dll base address
    uintptr_t gameEnd       = 0;                    // game.dll end address
    uintptr_t pServerInfo   = 0;                    // Resolved ServerInfo ptr
    uintptr_t pWarData      = 0;                    // Resolved war data ptr
    uintptr_t pEntityData   = 0;                    // Resolved entity data ptr
    
    std::mutex logMutex;
    std::vector<LogEntry> log;                      // Event log
    
    std::mutex replayLogMutex;
    std::vector<LogEntry> replayLog;                // Replay-specific log
    
    bool     activityCaptured    = true;             // Activity data captured
    char     activityGmiStr[256] = {};               // Hex-encoded GMI string
    uint32_t activityObjectId    = 1309039571u;      // Object ID from capture
};
```

### WeaponOverride
Weapon cycling state for XP farming.
```cpp
struct WeaponOverride {
    bool     enabled          = false;
    uint32_t targetId         = 0;        // Current weapon ID
    char     targetName[64]   = {};       // Current weapon name
    int      selectedIndex    = -1;       // Selected index in weapon table
    
    bool     allGunsMode      = false;    // Cycle through all 51 weapons
    int      allGunsIndex     = 0;        // Current all-guns position
    int      gunsReplaysPerWeapon = 9;    // Weapons switch every N replays
    
    bool     selectedGunsMode       = false;       // Cycle selected subset
    bool     selectedGunsChecked[51];               // Checkbox per weapon
    int      selectedGunsList[51];                  // Filtered weapon list
    int      selectedGunsCount      = 0;            // Count of selected
    int      selectedGunsPos        = 0;            // Position in selected list
    bool     forceNextWeapon        = false;        // Skip to next now
    
    int      scPerReplay            = 0;            // SC target per replay
};
```

### LogEntry
Log entry structure.
```cpp
struct LogEntry {
    char      message[256];            // Log message text
    bool      isError;                 // Error flag
    uint64_t  timestamp;               // TickCount64 at creation
};
```

### RvaReport (SC_SO resolver)
Reports a single resolved offset for version tracking.
```cpp
struct RvaReport {
    std::string name;                  // Human-readable label
    uintptr_t   hardcoded;             // Originally hardcoded value
    uintptr_t   resolved;              // Pattern-resolved value
    bool        found;                 // Pattern matched
    bool        updated;               // Differs from hardcoded
    char        method[48];            // Pattern description
};
```

---

## SC_SO Function RVA Table (offsets.h)

These are the RVAs used by SC_SO for game.dll function calls:

```cpp
namespace GS {
    // Function RVAs
    extern uintptr_t rv_fn0;  // 0xEEEA80  BuildPayload (entry-0x10 = capture point)
    extern uintptr_t rv_fn1;  // 0xEEF040  Activity function (SC/Medal activity execution)
    extern uintptr_t rv_fn5;  // 0xEF9030  Enqueue function
    extern uintptr_t rv_fn6;  // 0x525C3E  InstantComplete function
    extern uintptr_t rv_fn8;  // 0xEF74E0  Internal call
    extern uintptr_t rv_fn9;  // 0xEE9E00  Progression fetch function
    extern uintptr_t rv_gt;   // 0xF0889F  Gate function (JE→JMP patch target)
    
    // Global pointer RVAs
    extern uintptr_t rv_gp1;  // 0x1A7F738  ServerFactory global
    extern uintptr_t rv_gp3;  // 0x1A7F788  SessionData global
    extern uintptr_t rv_gp4;  // 0x1A91BA8  ServerInfo global
    extern uintptr_t rv_gp6;  // Entity pointer global
    extern uintptr_t rv_gp7;  // 0x1A925B8  PeerManager global
    
    // SC-specific RVAs
    extern uintptr_t rv_sc_act;  // Activity function (alt resolution)
    extern uintptr_t rv_sc_gbl;  // GameGlobal pointer
    extern uintptr_t rv_sc_mid;  // MissionId field offset
    extern uintptr_t rv_sc_ses;  // Session dispatch offset
    
    // Ring buffer constants
    constexpr uint32_t OFF_RING_INDEX  = 0x3E0F0;
    constexpr uint32_t OFF_RING_BASE   = 0x3E0F8;
    constexpr uint32_t RING_SLOT_SIZE  = 0xC88;
    constexpr uint32_t RING_SLOT_COUNT = 64;
    constexpr uint32_t RING_SLOT_MASK  = 0x3F;
    
    // Entity constants
    constexpr uint32_t ENT_SESSION_ID  = 0x11B0B0;
    constexpr uint32_t ENT_GATE_STRING = 0x31D7BC;
    constexpr uint32_t kEFS            = 0x33A5A0;
    
    // Activity type hashes
    constexpr uint32_t TYPE_MISSION_END = 0x1E555EA6;
    
    // Gate function opcodes
    constexpr uint8_t kGO = 0x74;  // JE opcode
    constexpr uint8_t kGP = 0xEB;  // JMP opcode
    
    // Enqueue function verification signature
    constexpr uint8_t ENQUEUE_SIG[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83 };
}
```

---

## SC_SO Module API Surface

### Probe API (probe.h)
```cpp
namespace Probe {
    bool Install(uintptr_t gameBase);         // Arm HW breakpoints (Dr2/Dr3)
    void Uninstall();                         // Clear all breakpoints
    void EnableInstantComplete(bool enable);  // Toggle instant mission completion
    bool IsInstantCompleteActive();
    void RearmIC();                           // Re-apply instant complete after fire
    void PauseDR2();                          // Suspend Dr2 for current thread
    void ResumeDR2();                         // Restore Dr2 on current thread
    
    struct PlayerInfo {
        uint64_t id;
        char     name[33];
        uint32_t rank;
    };
    void GetCapturedPlayerInfo(PlayerInfo out[4], int& count);
}
extern bool g_probeEnabled;
```

### ScPresent API (sc_present.h)
```cpp
namespace ScPresent {
    bool Install();                    // Subclass game window, install WNDPROC
    void Shutdown();                   // Restore original WNDPROC
    bool IsReady();                    // Window subclass installed
    bool QueueSC(void* actObj);        // Post WM_SC_DISPATCH for SC activity
    bool QueueCall(void* fn, void* arg); // Post WM_GT_DISPATCH for generic call
    void SetCallback(void* fn);        // Set dispatch callback
}
```

### ScGuard API (sc_guard.h)
```cpp
namespace ScGuard {
    void Install(uintptr_t gameBase, size_t gameSize);  // Register VEH
    void RegisterOwnThread(DWORD tid);    // Exempt owned thread from absorption
    void UnregisterOwnThread(DWORD tid);
    void NotifyScApc(DWORD gameTid);     // Arm SC-specific guard
    bool ShouldBackoff();                // Too many crashes?
    void ResetBackoff();                 // Clear backoff state
    int  GetAbsorptionCount();           // Total crashes absorbed
}
```

### HttpMonitor API (http_monitor.h)
```cpp
namespace HttpMonitor {
    void Install(uintptr_t gameBase);     // Hook libcurl functions
    void Uninstall();                     // Remove hooks
    void InstallWinHttpHooks();           // Alternative: hook winhttp
    void ScanForActivityFunction();       // Locate activity function in game.dll
    void* GetRetStubAddr();
    void* GetFakeVtableAddr();
    void* GetFakeEntityAddr();
    void* GetFakeFixupAddr();
}

// Mission ID management
bool HasGoldenMissionId();
const char* GetGoldenMissionId();

// Call tracking
int  HttpMonitor_GetActTotal();
int  HttpMonitor_GetActRewarded();
int  HttpMonitor_GetActNoReward();
int  HttpMonitor_GetActSCEarned();
int  HttpMonitor_GetActBonus();
void HttpMonitor_ResetCounters();
void HttpMonitor_ClearCallResult();
void HttpMonitor_SetCallResult(int v);
int  HttpMonitor_GetCallResult();
void HttpMonitor_AddRetryRecovered();
void HttpMonitor_AddRetryFailed();
int  HttpMonitor_GetRetryRecovered();
int  HttpMonitor_GetRetryFailed();

// POST body manipulation
void ActivatePostSwap(const char* uuid);
void DeactivatePostSwap();

// Response callback
typedef void (*MissionEndRespCb)(int httpStatus, const char* bodySnippet);
void HttpMonitor_SetMissionEndCb(MissionEndRespCb cb);

// Captured data access
bool HttpMonitor_HasCapturedMissionEnd();
const char* HttpMonitor_GetCapturedMissionEndBody();
int  HttpMonitor_GetCapturedMissionEndBodyLen();

extern std::atomic<bool> g_scCallInFlight;
```

---

## Weapon Table (51 entries)

```cpp
struct WeaponEntry {
    int      index;        // 0-50
    uint32_t internalId;   // Game internal hash ID
    const char* name;      // Display name
};

constexpr WeaponEntry kWeaponTable[51] = {
    { 0,  2852344585u, "AR-23 Liberator" },
    { 1,  2584612689u, "AR-23P Liberator Penetrator" },
    { 2,  4042525201u, "AR-23C Liberator Concussive" },
    { 3,  4052470460u, "R-63 Diligence" },
    { 4,  1944231224u, "R-63CS Diligence Counter Sniper" },
    { 5,  1392065413u, "SMG-37 Defender" },
    { 6,  2681533880u, "MP-98 Knight" },
    { 7,  456945495u,  "SG-8 Punisher" },
    { 8,  3886356347u, "SG-8S Slugger" },
    { 9,  3450040247u, "SG-225 Breaker" },
    { 10, 3654533182u, "SG-225SP Breaker Spray&Pray" },
    { 11, 1796165750u, "SG-225IE Breaker Incendiary" },
    { 12, 3866352840u, "LAS-5 Scythe" },
    { 13, 2746251822u, "LAS-16 Sickle" },
    { 14, 925809350u,  "PLAS-1 Scorcher" },
    { 15, 3808114828u, "PLAS-101 Purifier" },
    { 16, 2136163121u, "ARC-12 Blitzer" },
    { 17, 610029066u,  "R-36 Eruptor" },
    { 18, 1663589294u, "CB-9 Exploding Crossbow" },
    { 19, 790644647u,  "JAR-5 Dominator" },
    { 20, 3122012393u, "P-2 Peacemaker" },
    { 21, 1822777433u, "P-19 Redeemer" },
    { 22, 188142069u,  "P-113 Verdict" },
    { 23, 3115390823u, "P-4 Senator" },
    { 24, 1270056193u, "LAS-7 Dagger" },
    { 25, 2856670298u, "GP-31 Grenade Pistol" },
    { 26, 1293181137u, "PLAS-15 Loyalist" },
    { 27, 4061102636u, "SG-22 Bushwhacker" },
    { 28, 3120995212u, "FLAM-66 Torcher" },
    { 29, 3585403884u, "FLAM-40 Flamethrower" },
    { 30, 3977104437u, "ARC-3 Arc Thrower" },
    { 31, 975520411u,  "LAS-98 Laser Cannon" },
    { 32, 2706975592u, "LAS-99 Quasar Cannon" },
    { 33, 2460486419u, "RS-422 Railgun" },
    { 34, 4130961272u, "GL-21 Grenade Launcher" },
    { 35, 1704002426u, "EAT-17 Expendable Anti-Tank" },
    { 36, 2750027659u, "GR-8 Recoilless Rifle" },
    { 37, 82856471u,   "FAF-14 Spear" },
    { 38, 2077663824u, "AC-8 Autocannon" },
    { 39, 2051465721u, "APW-1 Anti-Materiel Rifle" },
    { 40, 1500305061u, "MG-43 Machine Gun" },
    { 41, 69999893u,   "MG-206 Heavy Machine Gun" },
    { 42, 610366017u,  "M-105 Stalwart" },
    { 43, 1873419027u, "MG-101 Gatling Sentry" },
    { 44, 1021424552u, "AX/TX-13 \"Guard Dog\" Rover" },
    { 45, 2399353262u, "A/G-16 Gatling Sentry" },
    { 46, 767959545u,  "A/M-12 Mortar Sentry" },
    { 47, 1676894626u, "A/MLS-4X Rocket Sentry" },
    { 48, 394174918u,  "A/AC-8 Autocannon Sentry" },
    { 49, 2036335043u, "EXO-45 Patriot Exosuit" },
    { 50, 3894692685u, "EXO-49 Emancipator Exosuit" },
};
```
