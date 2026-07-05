#pragma once

#include <string>
#include <cstring>

template<size_t N>
struct XStrN {
    char enc[N];

    constexpr XStrN(const char (&s)[N]) : enc{} {
        for (size_t i = 0; i < N; i++)
            enc[i] = s[i] ^ static_cast<char>(0x5A ^ (i * 0x37));
    }

    std::string d() const {
        std::string r(N - 1, '\0');
        for (size_t i = 0; i < N - 1; i++)
            r[i] = enc[i] ^ static_cast<char>(0x5A ^ (i * 0x37));
        return r;
    }

    void d(char* buf, size_t bufLen) const {
        size_t len = (N - 1 < bufLen - 1) ? N - 1 : bufLen - 1;
        for (size_t i = 0; i < len; i++)
            buf[i] = enc[i] ^ static_cast<char>(0x5A ^ (i * 0x37));
        buf[len] = '\0';
    }
};

template<size_t N>
struct XStrW {
    wchar_t enc[N];

    constexpr XStrW(const wchar_t (&s)[N]) : enc{} {
        for (size_t i = 0; i < N; i++)
            enc[i] = s[i] ^ static_cast<wchar_t>(0x5A ^ (i * 0x37));
    }

    std::wstring d() const {
        std::wstring r(N - 1, L'\0');
        for (size_t i = 0; i < N - 1; i++)
            r[i] = enc[i] ^ static_cast<wchar_t>(0x5A ^ (i * 0x37));
        return r;
    }

    void d(wchar_t* buf, size_t bufLen) const {
        size_t len = (N - 1 < bufLen - 1) ? N - 1 : bufLen - 1;
        for (size_t i = 0; i < len; i++)
            buf[i] = enc[i] ^ static_cast<wchar_t>(0x5A ^ (i * 0x37));
        buf[len] = L'\0';
    }
};

#define XSTR(s)  ([]{ static constexpr XStrN x(s); return x; }())
#define XWSTR(s) ([]{ static constexpr XStrW x(s); return x; }())
