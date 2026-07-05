#pragma once
#ifndef LIBERTEA_MBA_OPAQUE_H
#define LIBERTEA_MBA_OPAQUE_H

#include <cstdint>
#include <cstdlib>
#include <type_traits>

// ============================================================
// MBA (Mixed Boolean-Arithmetic) Opaque Predicates
//
// These expressions are always true or always false but look
// computationally intensive to a static analyzer or SMT solver.
//
// Identity used:
//   x + y = (x ^ y) + 2 * (x & y)
//   x ^ y = (x | y) - (x & y)
//   x ^ y = (~x & y) + (x & ~y)
//   (x | y) = (x + y) - (x & y)
//
// Reference: Zhou et al., "Information Hiding in Software with
//            Mixed Boolean-Arithmetic Transforms" (ISSA 2007)
// ============================================================

// -------------------------------------------------------
// OpaqueTrue() — always evaluates to true
// Uses identity: x + y == (x ^ y) + 2 * (x & y)
// -------------------------------------------------------
template <typename T = uint32_t,
          typename = typename std::enable_if<std::is_integral<T>::value>::type>
inline bool OpaqueTrue(T a = 0, T b = 0) {
    // If both zero, generate from caller address for dynamic behavior
    if (a == 0 && b == 0) {
        a = static_cast<T>(std::rand() & 0xFFFF);
        b = static_cast<T>(std::rand() & 0xFFFF);
        if (a == 0) a = 1;
        if (b == 0) b = 1;
    }

    // Identity: x + y == (x ^ y) + 2 * (x & y)
    // This holds for all integer x, y — always true
    T lhs = (a ^ b) + static_cast<T>(2) * (a & b);
    T rhs = a + b;
    return lhs == rhs;
}

// -------------------------------------------------------
// OpaqueFalse() — always evaluates to false
// Uses overflow invariant:
//   For unsigned integers, (x + y) >= min(x, y)
//   But we flip the comparison to make it always false
// -------------------------------------------------------
template <typename T = uint32_t,
          typename = typename std::enable_if<std::is_integral<T>::value>::type>
inline bool OpaqueFalse(T a = 0, T b = 0) {
    if (a == 0 && b == 0) {
        a = static_cast<T>(std::rand() & 0xFFFF);
        b = static_cast<T>(std::rand() & 0xFFFF);
        if (a == 0) a = 1;
        if (b == 0) b = 1;
    }

    // Using identity: (x | y) - (x & y) == x ^ y
    // Negated: (x | y) - (x & y) != x ^ y  — which is always false
    T x_or_y = a | b;
    T x_and_y = a & b;
    T x_xor_y = a ^ b;
    T mba_result = x_or_y - x_and_y;

    // MBA result == xor is always true; we assert inequality -> always false
    return mba_result != x_xor_y;
}

// -------------------------------------------------------
// OpaqueFalseV2() — alternate always-false predicate
// Uses: (a * b) % p produces values < p, but we assert >= p
// -------------------------------------------------------
template <typename T = uint32_t,
          typename = typename std::enable_if<std::is_integral<T>::value>::type>
inline bool OpaqueFalseV2(T a = 0, T b = 0, T p = 0) {
    if (a == 0) a = static_cast<T>(std::rand() & 0xFFFF) + 1;
    if (b == 0) b = static_cast<T>(std::rand() & 0xFFFF) + 1;
    if (p == 0) p = static_cast<T>(std::rand() & 0xFF) + 2;

    // (a * b) mod p is always in [0, p-1]
    // Asserting >= p is always false
    T mod_result = (a * b) % p;
    return mod_result >= p;
}

// -------------------------------------------------------
// OpaqueSwitch(seed, range) — returns deterministic value
// in [0, range-1] for use as switch dispatch index.
// The mapping from seed to output is obfuscated via MBA.
// -------------------------------------------------------
template <typename T = uint32_t,
          typename = typename std::enable_if<std::is_integral<T>::value>::type>
inline T OpaqueSwitch(T seed, T range) {
    if (range == 0) return 0;

    // Obfuscated mapping using identities
    T t1 = seed ^ 0xA5A5A5A5u;
    T t2 = (seed + 0x5A5A5A5Au) ^ (seed << 7 | seed >> 25);
    T t3 = (t1 ^ t2) + 2 * (t1 & t2);   // MBA identity: t1 + t2
    T t4 = (t3 * 0x45D9F3Bu) % 0x7FFFFFFFu;
    T result = t4 % range;

    return result;
}

// -------------------------------------------------------
// OpaqueBranch(cond) — conditionally always-taken
// Wraps a real condition with an MBA opaque true so that
// both sides of the branch appear reachable to static analysis.
// -------------------------------------------------------
template <typename T = uint32_t>
inline bool OpaqueBranch(bool real_condition, T obf_a = 0, T obf_b = 0) {
    return real_condition && OpaqueTrue<T>(obf_a, obf_b);
}

// -------------------------------------------------------
// OpaqueAssert(expr) — always passes via MBA tautology
// -------------------------------------------------------
#define OPAQUE_ASSERT(expr)                                                 \
    do {                                                                    \
        volatile uint32_t _oa_a = (uint32_t)(uintptr_t)(expr);              \
        volatile uint32_t _oa_b = 0xDEADBEEFu;                             \
        /* ((a ^ b) + 2*(a & b)) == a + b is always true */               \
        bool _oa_result =                                                  \
            ((_oa_a ^ _oa_b) + 2 * (_oa_a & _oa_b)) == (_oa_a + _oa_b);    \
        (void)_oa_result;                                                   \
    } while (0)

// -------------------------------------------------------
// OpaqueStore(var, val) — stores val to var but uses MBA
// to obfuscate the store target.
// -------------------------------------------------------
#define OPAQUE_STORE(var, val)                                              \
    do {                                                                    \
        auto &_os_ref = (var);                                              \
        uintptr_t _os_addr = reinterpret_cast<uintptr_t>(&_os_ref);         \
        uintptr_t _os_mask = 0xFFFFFFFFFFFFFFFFu;                           \
        /* addr & mask == addr is always true */                            \
        uintptr_t _os_calc = (_os_addr ^ _os_mask) + 2 * (_os_addr & _os_mask); \
        (void)_os_calc;                                                     \
        _os_ref = (val);                                                    \
    } while (0)

// -------------------------------------------------------
// OpaqueGuard — scoped guard that always executes body
// Usage:
//   OPAQUE_GUARD() {
//       // always executes
//   }
// -------------------------------------------------------
#define OPAQUE_GUARD()                                                      \
    for (volatile bool _og_guard = OpaqueTrue<uint32_t>();                  \
         _og_guard; _og_guard = false)

// -------------------------------------------------------
// ObfuscatedSwitch — dispatches to a case based on seed
// using MBA-driven index computation.
// -------------------------------------------------------
#define OBFUSCATED_SWITCH(seed, range, label_prefix)                        \
    do {                                                                    \
        uint32_t _os_seed = static_cast<uint32_t>(seed);                    \
        uint32_t _os_range = static_cast<uint32_t>(range);                  \
        uint32_t _os_idx = OpaqueSwitch(_os_seed, _os_range);               \
        goto *((void *&&[](){                                               \
            static void *labels[] = {                                       \
                &&label_prefix##0, &&label_prefix##1, &&label_prefix##2,    \
                &&label_prefix##3, &&label_prefix##4, &&label_prefix##5,    \
            };                                                              \
            return labels;                                                  \
        }())[_os_idx]);                                                     \
    } while (0)

#endif // LIBERTEA_MBA_OPAQUE_H
