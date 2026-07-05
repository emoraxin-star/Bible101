# BYOVD Kernel Component — LIBERTEA v414 Research

## Concept

BYOVD (Bring Your Own Vulnerable Driver) exploits the Windows driver signing
requirement by loading a legitimate, Microsoft-signed driver that contains a
known vulnerability. Since the driver is properly signed, Windows Loader
(session manager/CI.dll) loads it without complaint. The vulnerability then
provides arbitrary kernel-mode access from user-mode via IOCTLs.

## Applicable Vulnerable Drivers

| Driver | Vendor | Vulnerability | IOCTL Interface | Notes |
|--------|--------|---------------|-----------------|-------|
| RTCore64.sys | MSI Afterburner | CVE-2019-16098 — Arbitrary MSR r/w | `\\.\RTCore64`, codes 0x80002040/0x80002044 | Most widely used; MSR access enables PG disable, VMX root escape |
| GLCKIO2.sys | ASUS | Arbitrary physical memory r/w | `\\.\GLCKIO2` | Direct physical memory; ideal for EPROCESS manipulation |
| gdrv.sys | Gigabyte | Arbitrary virtual memory r/w | Various IOCTLs | Can read/write any process memory from Ring 0 |
| DBUtil_2_3.sys | Dell | Arbitrary physical memory | `\\.\DBUtil_2_3` | Less detected but less capable |
| asmmap.sys | ASUS | Physical memory map | `\\.\AsusACPI` | Rare but functional |

## Detection Risk Assessment

| Vector | Risk | Mitigation |
|--------|------|------------|
| Driver load event (ETW TI) | HIGH (if monitored) | Load early, before GameGuard; use syscall to bypass ETW |
| Service creation audit (4688) | MEDIUM | Named after legitimate service; clean up after use |
| Signature scanning by AV | MEDIUM | Known signatures exist for RTCore64.sys; use less common driver |
| IOCTL pattern analysis | LOW | IOCTLs indistinguishable from legitimate software |
| Physical memory scanning | LOW | Only possible from Ring 0 which GameGuard can do |

## Operational Security

1. Delete driver .sys file from disk after load
2. Use random service name if possible
3. Remove service entry after unload
4. Prefer GLCKIO2 over RTCore64 (less signature coverage)
5. Unload driver on exit — leaving driver loaded persists detection vector

## Legal & Ethical Notes

- This is a research project analyzing cheat anti-detection techniques.
- BYOVD is a documented technique used by both security researchers and
  threat actors. The code here is for educational/analysis purposes.
- Vulnerable drivers should be responsibly disclosed, not weaponized.
- GameGuard's PPL protection is Microsoft's recommended anti-cheat
  mechanism; bypassing it defeats the OS security model.
