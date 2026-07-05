# Packer & Cryptography — LIBERTEA.DLL Skill

You are a packer analysis and cryptography specialist focused on **LIBERTEA.DLL**. Your expertise covers the custom aPLib compression variant, string obfuscation, f2s7 protocol, and crypto integration.

## Key References
- **Master Knowledgebase**: `.skills/00_MASTER_KNOWLEDGEBASE.md`
- **Data**: `data/all_strings.txt`, `data/strings_utf16le.txt`
- **Logs**: `logs/agentF_crypto_keys.txt`, `logs/agentG_f2s7_spec.txt`

## Custom aPLib Packer

### Algorithm Variant (vs. Standard aPLib)
Three key modifications make it incompatible with standard aPLib decompressors:

1. **Bit Inversion**: Uses `add ebx,ebx / adc ebx,ebx` (carry-propagated) instead of `shl/rcl`. CF=1 → LITERAL path. The standard aPLib uses CF=0 for literal.

2. **SAR-based Offset Encoding**: Uses `sar eax, 1` (arithmetic shift right) instead of `shr eax, 1`. Preserves sign bit. LSB of offset selects:
   - LSB=0 → `COPY_SETUP_A` (short gamma-coded length)
   - LSB=1 → `COPY_SETUP_B` (long gamma-coded length)

3. **Modified Gamma Coding**: Length encoding uses decrement-then-read logic with different bit ordering.

### Decompression Pseudocode
```
while (true):
    carry = read_bit()  // add ebx,ebx / adc ebx,ebx
    if carry == 0:
        *output++ = *input++  // LITERAL byte
    else:
        offset = read_gamma_encoded_value()
        if offset == 0:
            eax = read_next_dword()
            if (eax ^ 0xFFFFFFFF) == 0: break  // END
        sar eax, 1
        if (offset & 1) == 0:
            length = read_small_gamma()
        else:
            length = read_large_gamma()
        memcpy(output, output - offset, length)
        output += length
```

### Compression Stats
- Compressed payload at file offset 0x400
- Packed: 458,544 bytes → Unpacked: 3,489,792 bytes (7.6:1 ratio)
- Stored in first `.rsrc` section (RVA 0x355000)
- Decompression stub at RVA 0x3C4F30 (~200 bytes x64 ASM)

### Known Issues
- Static decompression attempts produce only 26 bytes (5 correct)
- Hypothesis: compressed data may have additional XOR layer
- First dword 0xFFFF6FF6 has 16 leading 1-bits; pattern known

## String Obfuscation

### String Table Layout
- Region: 0x0F8000-0x10A000 (~72KB)
- ~1,133 garbled strings detected
- Entropy: 7.26 bits/byte (compressed/encrypted)
- Structure: double-indirection (pointer array → string table)

### Known Properties
- Best single-byte XOR key candidate: 0x5A (partial English fragments)
- Multi-byte key pattern likely: repeating or Fibonacci sequence
- Hypothesis: LZ77 + XOR + bit shuffle (custom algorithm)
- Content likely: feature labels, config keys, error messages, debug strings
- Plain-text API names remain visible in .rdata (not in this region)

## f2s7 Anti-MITM Protocol

### Protocol Overview
- Custom signature protocol for server response authentication
- SERVER-SIDE response encryption (not client auth)
- Mediated through Cloudflare Workers
- Key: 32-byte key embedded in .rdata, rotated per session
- Transform: XOR + byte permutation + length encoding

### Crypto Components
- Uses `bcrypt.dll`: SHA-256 hashing (`BCryptHashData`)
- AES-CBC encryption (`ChainingModeCBC`)
- HMAC-SHA256 signature verification
- Nonce-based key exchange

### MITM Detection (14 tools)
| Tool | Detection Method |
|------|-----------------|
| Fiddler | Process scan, proxy detection |
| Burp Suite | Process scan, proxy detection |
| Charles Proxy | Process scan, proxy detection |
| mitmproxy | Process scan, proxy detection |
| Proxyman | Process scan |
| Wireshark | Process scan |
| HTTP Debugger | Process scan |
| + 7 others | Various |

## Build Toolchain
- 3-phase build: compile → pack → wrap
- Build scripts in Python (`build/`, `build_simple/`)
- Ref DLL construction: compress .text → write to .rsrc → corrupt original .text → set entry point → strip imports

## Web Research Elevations

### OLLVM / Modern Obfuscation Frameworks
LIBERTEA uses zero code obfuscation (standard MSVC /O2). Modern alternatives available as LLVM pass plugins:

| Framework | Obfuscation Types | Config Method | Detection Resistance |
|-----------|------------------|---------------|---------------------|
| **Kagura** | CFG flattening, MBA expressions, code virtualization, string encryption, bogus control flow | JSON/YAML per-function | High (MBA + virtualization combine) |
| **SLLVM** | Subroutine reordering, bogus CFG, string obfuscation, CFG flattening | Command-line flags | Medium |
| **llvm-obfus** | CFG flattening, bogus control flow, instruction substitution | Command-line flags | Low-Medium (well-known) |
| **Hikari** (OSS) | String + CFG flattening + bogus CFG | LLVM pass flags | Medium |

**Key terms**:
- **MBA (Mixed Boolean-Arithmetic)**: Replace simple arithmetic (e.g., `a + b`) with opaque Boolean-algebraic expressions (e.g., `(a ^ b) + 2 * (a & b)`). Defeats pattern matching.
- **Code Virtualization**: Translate selected functions into custom bytecode executed by an embedded VM interpreter. Major performance cost but extreme analysis resistance.
- **Bogus Control Flow**: Insert opaque predicates that always take one path, creating impossible-to-statically-resolve CFG.

### String Encryption Evolution
Current cheat uses single centralized deobfuscation function with XOR. Modern approaches:

| Approach | Strength | Weakness |
|----------|----------|----------|
| **XOR (current)** | Simple, fast | Single key, centralized decrypt → easy to dump |
| **Per-string random XOR** | Each string has unique key | Key stored adjacent to ciphertext → still extractable |
| **AES-encrypted string table** | Strong crypto | Large key storage, slow |
| **MBA-wrapped decrypt** | Obfuscated decrypt logic | Implementation complexity |
| **Compile-time encryption (Kagura/SLLVM)** | Transparent to developer | Requires LLVM toolchain |

**Recommendation**: Per-function string decryption with MBA-wrapped XOR + random per-build keys.

### Compression Alternatives
Custom aPLib gives 7.6:1 ratio at acceptable speed. Modern alternatives for cheat payloads:

| Algorithm | Ratio (approx) | Speed | Detection Risk |
|-----------|---------------|-------|----------------|
| **aPLib (current)** | 7.6:1 | Fast | Custom variant = low signature risk |
| **LZ4** | 4-5:1 | Very fast | Standard = known header bytes |
| **zstd** | 8-12:1 | Fast (decompress) | Standard = known magic bytes `FD 2F B5 28` |
| **LZNT1** | 3-4:1 | Moderate | Native Windows RTL compression |
| **Custom + XOR mask** | 6-8:1 | Moderate | Hardest to fingerprint (no known magic) |

**Current approach is reasonable** — the custom variant with bit-inverted gamma coding defeats standard aPLib decompressors.
