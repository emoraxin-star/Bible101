# Game Data & Feature Modules — LIBERTEA.DLL Skill

You are a game internals and cheat feature specialist focused on **LIBERTEA.DLL**. Your expertise covers the 32+ cheat features, game data structures, weapon/armor/enemy catalogs, and how each feature modifies the game.

## Key References
- **Master Knowledgebase**: `.skills/00_MASTER_KNOWLEDGEBASE.md`
- **Data**: `resweep/resweep_supplement.txt` (full game data catalog)
- **Logs**: `logs/agentE_game_data.txt`, `logs/agentE_game_data_part2.txt`

## Feature Catalog (32+ features, 8 categories)

### Player Cheats
| Feature | Implementation |
|---------|---------------|
| **God Mode** | 3 CODE_PATCH hooks: damage receive → 0, death flag NOP, health check bypass |
| **No Ragdoll** | FUNCTION_RETURN: RET at ragdoll function entry |
| **No Recoil** | FUNCTION_RETURN: RET at recoil calculation |
| **Movement Speed** | CODE_PATCH: slider `##spd` (0.1f), multiplier `##smult` |
| **No Boundary** | CONDITIONAL_INVERT: JE→JMP (always in-bounds) |
| **Landing Speed** | NOP_PATCH: NOP landing speed calculation |
| **Longer Hover** | NOP_PATCH: NOP hover time limit check |

### Combat Cheats
| Feature | Pattern | Implementation |
|---------|---------|----------------|
| **Infinite Ammo** | — | NOP_PATCH on decrement |
| **No Reload** | — | CODE_PATCH: bypass reload |
| **Infinite Grenades** | `0F 5B DB F3 41 0F 59 4E ?? F3` | NOP_PATCH on conversion |
| **Infinite Stims** | — | NOP_PATCH on decrement |
| **Infinite Stratagems** | `42 83 2C 81 ?? 48` | COND_INVERT on count check |
| **Instant Stratagem** | — | CODE_PATCH: zero call-in timer |
| **Mass Strat Drop** | — | CODE_PATCH (BROKEN - [N/A]) |
| **No Turret Overheat** | `F3 0F 11 4C A8 ?? 49` | NOP_PATCH on heat |
| **Inf Turret Duration** | `F3 45 0F 11 5E ?? E9` | NOP_PATCH on timer |
| **Expire All Turrets** | — | NOP_PATCH: invert expire logic |
| **No Laser Overheat** | — | NOP_PATCH on heat |
| **Instant Charge** | — | NOP_PATCH on charge calc |
| **Grenade Fuse** | `F3 0F 11 44 C8 ?? 0F` | NOP_PATCH on fuse timer |
| **Kill Counter** | `39 46 ?? 75 ?? FF C5` | CODE_PATCH: hook increment |

### Farming / Economy
| Feature | Implementation |
|---------|---------------|
| **Reward Multiplier** | FUNCTION_RETURN: sliders `##fxp`, `##fmed`, `##fslips` |
| **Force Difficulty** | NOP_PATCH: NOP `cmp esi,7` check |
| **Add Samples** | Direct write to session+0x110-0x11C |
| **Samples Over Limit** | Bypass extraction cap check |
| **Instant Shuttle** | `##shut5`: skip extraction timer |
| **Instant Complete** | `##ic5`: skip mission objectives |
| **Freeze Timer** | Stop countdown timers |

### Super Credits / Medal Farming
(See `.skills/04_NETWORK_FARMING.md` for full protocol)
- Batch SC/Medal replay system
- 9 calls per batch, 500ms apart, 58s cooldown
- Hash table NOP bypasses duplicate detection
- VEH crash recovery

### Weapon XP Farming
- 51 total weapons tracked (IDs likely 0-50)
- **All Guns mode** (`##ag`): auto-rotate through all 51
- **Selected Guns** (`##sg`): checkbox list `##sglist`
- **Primary Override**: set one weapon for entire lobby
- Configurable replays per gun (`##repperwep`)
- Log: `"[AllGuns] Weapon: %s (%d/%d), cycle %d/%d"`

### Armory
| Feature | Implementation |
|---------|---------------|
| **Unlock All** | NOP_PATCH on unlock check |
| **Armor Passive Editor** | `##ap_scan`, `##ap_armor`, `##ap_pass` |
| **Weapon Editor** | Write to WeaponStats struct |

### Visual / Misc
| Feature | Implementation |
|---------|---------------|
| **FOV Editor** | `##fov` slider: modify camera FOV |
| **Dark Fluid Pack** | `##pk`, `##pk_rst`: fly speed, gravity, fuel, impulse, boost |
| **Infinite Horde** | `##erad_ih`: enemy spawner (Coming Soon) |
| **Replay System** | `##bl` burst loop, `##maxreplays`, `##BurstCount` |

## Difficulty System
| Tier | Label | Reward Mult | Cheat `cmp esi,7` NOP |
|------|-------|-------------|----------------------|
| 1 | Trivial | 0% (1.0x) | Bypassed |
| 2 | Easy | 0% (1.0x) | Bypassed |
| 3 | Medium | 25% (1.25x) | Bypassed |
| 4 | Challenging | 50% (1.5x) | Bypassed |
| 5 | Hard | 75% (1.75x) | Bypassed |
| 6 | Extreme | 100% (2.0x) | Bypassed |
| 7 | Super Helldive | 150% (2.5x) | Bypassed |
| 8 | (custom) | 200% (3.0x) | Bypassed |
| 9 | (custom) | 250% (3.5x) | Bypassed |
| 10 | (custom) | 300% (4.0x) | Bypassed |

## Weapon Catalog (51 weapons)
Full list in `resweep/resweep_supplement.txt` — key weapons:
- AR-23 Liberator, AR-23C Liberator Concussive, AR-23P Liberator Penetrator
- SG-225 Breaker, SG-225IE Breaker Incendiary, SG-8 Punisher
- LAS-5 Scythe, LAS-16 Sickle, LAS-17 Double-Edged Sickle
- PLAS-1 Scorcher, PLAS-101 Purifier, PLAS-39 Accelerator Rifle
- JAR-5 Dominator, R-36 Eruptor, R-63 Diligence
- SMG-37 Defender, SMG-32 Reprimand, MP-98 Knight
- ARC-12 Blitzer, CB-9 Exploding Crossbow
- FLAM-66 Torcher

## Armor Passives (21 found)
Acclimated, Ballistic Padding, Combat Medic, Explosive Finale, Fire Resistant, Gas Resistance, Peak Physique, Siege Breaker, Supplemental Stamina, Concussive Hazmat, Concussive Grenadier, Reinforced Epaulettes, Acclimated, Battle Hardened, Fire Support, Desert Stormer, Scout Strider, etc.

## Enemy Types (28 found)
Bile Titan, Charger (Behemoth), Factory Strider, Harvester, Hulk (Bruiser/Scorcher), Devastator (Heavy/Rocket), Berserker, Stalker, Brood Commander, Hunter, Warrior, Scavenger, Nursing Spewer, Bile Spewer, Impaler, Gunship, Trooper, Overseer, Tank, Scout Strider, Shrieker

## WeaponStats Structure (Editor Target)
```
+0x30: damage (float)       → "Damage##we"
+0x34: penetration (float)  → "Struct. Penetration##we"
+0x38: fire rate (float)    → "FireRate (Trident)##we"
```

## PlayerSession Structure (Key Offsets)
```
+0x28: Primary activity ring buffer (278 code refs!)
+0x60: missionData pointer
+0x70: missionId[0x40] (UUID string)
+0xF0: SC consumed hash table (NOP'd by cheat)
+0xF8: Medal consumed hash table (NOP'd by cheat)
+0x100: Sample consumed hash table (NOP'd by cheat)
+0x110-0x11C: Sample counters (common/rare/super)
+0x128: Secondary activity ring buffer
+0x130: ServerInfo pointer
```

## ImGui UI Widget IDs (162+ found)
Key prefixes: `##sc_`, `##f`, `##spd`, `##smult`, `##rp`, `##ap_`, `##shut5`, `##ic5`, `##ag`, `##sg`, `##sglist`, `##sgsearch`, `##we`, `##fov`, `##pk`, `##ua`, `##diff`, `##difflvl`, `##fsamp_c`, `##fsamp_r`, `##fsamp_s`, `##sr`, `##lock_screen`, `##bl`, `##maxreplays`, `##BurstCount`, `##repperwep`, `##erad_ih`, `##isc`, `##msd`, `##msc`

## Web Research Elevations

### Helldivers 2 Engine & Architecture
- **Engine**: Autodesk Stingray (Bitsquid lineage) — heavily modified in-house fork
- **Asset ID**: `MurmurHash64A` — 64-bit hash of asset path string, used for all resource lookups
- **Data archives**: `exploded_dat` format — community tools (`Stingray-Explorer`, `filediver`, `hd2re`) can extract
- **Game executable**: `helldivers2.exe` (64-bit)
- **Rendering**: OpenGL 4.x (with D3D12/Vulkan abstraction layer in Stingray)

### Game Version History & Patch Impact on Features
| Version | Release | Key Changes | Feature Impact |
|---------|---------|-------------|----------------|
| v6.2.0 | Early 2026 | Standard update | — |
| v6.2.1 | Mar 2026 | Balance changes | Minimal |
| **v6.2.2** | **Apr 2026** | **SC pickup patched** | **SC farming via pickup → broken. Replay attack → may still work** |
| v6.2.3 | Apr 2026 | Bug fixes | Minimal |
| v6.2.4 | May 2026 | Anti-exploit hardening | Unknown impact |
| **v6.2.5** | **May 2026** | **Further AC updates** | **GameGuard AOB scanning added** |

### SC Farming Feature Status (Post-v414)
The cheat's primary monetization feature (SC/Medal farming) faces increasing mitigation:
- **Hash table NOP bypass**: GameGuard may now AOB-scan for the NOP sled pattern `90 90 90 90` in game.dll
- **Server-side validation**: HD2 devs may have added mission replay detection (same mission data, multiple submissions)
- **VEH recovery**: Still functional unless GameGuard monitors exception handler chains
- **HWID binding**: Server-side, not affected by game patches

### Graphics Updates (Post v414)
- FSR 3.1.5 (AMD upscaling)
- DLSS 4.5 (NVIDIA, transformer model)
- XeSS 3.0 (Intel upscaling)
- NVIDIA Reflex (latency reduction)
- AMD Anti-Lag 2 (latency reduction)

### Weapon Catalog Updates
Post-v414 may have added new weapons. The 51-weapon catalog in `resweep_supplement.txt` should be verified against current game version. Community API (`api.helldivers2.dev`) provides weapon stats without reverse engineering.

### Community Resources
| Resource | URL | Use Case |
|----------|-----|----------|
| HD2 Community API | `api.helldivers2.dev` | Weapon stats, war state, reward tables |
| filediver | GitHub | `.exploded_dat` extraction |
| Stingray-Explorer | GitHub | Stingray engine resource exploration |
| hd2re | GitHub | Helldivers 2 specific reversing tools |

### Memory Structure Stability
The key GameSession/PlayerSession structures are likely stable across patches because:
1. Stingray engine uses fixed-size ring buffers for activity tracking
2. Hash table pointers at PlayerSession+0xF0/0xF8/0x100 are core engine constructs
3. UUID-based mission IDs are standardized format

**But**: GameGuard's kernel-mode component can now scan for known pattern signatures in process memory, putting all NOP_PATCH hooks at risk.

## Config Persistence
- Likely JSON-based config save/load
- Potential path: `%APPDATA%/LiberTea/config.json`
- Auto-save on toggle/change (not confirmed)
- No explicit save/load profile UI identified
