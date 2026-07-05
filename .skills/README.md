# LIBERTEA.DLL Reverse Engineering Skills

This directory contains structured knowledgebase skill files for the **LIBERTEA.DLL** reverse engineering project (Helldivers 2 internal cheat v414).

## File Map

| File | Coverage | Best For |
|------|----------|----------|
| `00_MASTER_KNOWLEDGEBASE.md` | Everything — complete reference | General Q&A, overview, lookup |
| `01_BINARY_ANALYSIS.md` | PE structure, file hashes, compiler info | File analysis, forensic questions |
| `02_PACKER_CRYPTO.md` | Custom aPLib, strings, f2s7, crypto | Packer reversal, crypto analysis |
| `03_HOOKS_PATTERNS.md` | 73 patterns, 6 hook types, syscalls | Hook system, pattern matching questions |
| `04_NETWORK_FARMING.md` | SC/Medal protocol, auth, replay | Farming system, network protocol, auth |
| `05_GAME_DATA_FEATURES.md` | 32+ features, game data, weapons/armor | Feature questions, game data, UI |
| `06_EVASION_WEAKNESSES.md` | Anti-analysis, detection vectors, fixes | Security analysis, improvements |

## Ground Truth Files

| File | Size | Purpose |
|------|------|---------|
| `.text_unpacked_mem.bin` | 3,489,792 bytes | Unpacked .text section (golden reference) |
| `compressed.bin` | 458,544 bytes | aPLib compressed payload |
| `patterns_extracted.json` | 17,975 bytes | 73 pattern signatures in JSON |

## Accuracy
- Verified accuracy: **93.4%** (203 claims tested)
- Audit log: `logs/audit_verification.txt`
- Discrepancy fixes: `logs/DISCREPANCY_FIXES.txt`

## Key Documents
- `docs/ARCHITECTURE_DEFINITIVE.txt` — Complete architectural breakdown
- `docs/ULTIMATE_GUIDE_FOR_DUMMIES.txt` — Beginner-friendly explanation
- `13%_Guess.txt` — Confidence-rated uncertain findings
- `BRAINSTORM_IMPROVEMENTS.txt` — Comprehensive improvement analysis
