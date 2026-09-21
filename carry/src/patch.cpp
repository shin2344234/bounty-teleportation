#include "patch.h"

#include <Windows.h>
#include <cstdio>
#include <cstring>

#include "core/log.h"
#include "game/mem.h"

namespace bp::patch
{
    namespace
    {
        constexpr int kMax = 16;
        constexpr unsigned kWidth = 8;

        struct Entry
        {
            char      name[48];
            uintptr_t at;
            uint8_t   orig[kWidth];
            uint8_t   repl[kWidth];
            unsigned  len;
            bool      on;
        };
        Entry g_patches[kMax];
        int   g_n = 0;

        void HexLine(const uint8_t* b, unsigned n, char* out, size_t cap)
        {
            size_t used = 0;
            out[0] = 0;
            for (unsigned i = 0; i < n && used + 4 < cap; ++i)
                used += snprintf(out + used, cap - used, i ? " %02X" : "%02X", b[i]);
        }

        bool Write(uintptr_t at, const uint8_t* b, unsigned n)
        {
            DWORD old = 0;
            if (!VirtualProtect(reinterpret_cast<void*>(at), n, PAGE_EXECUTE_READWRITE, &old)) return false;
            // One store for the whole instruction, so no thread running the
            // game can read half of the old one and half of the new. Three of
            // the four patches only change their opcode byte (74 to EB, same
            // displacement), which is a single-byte store wherever it sits;
            // one of those is at an odd address, where a two-byte interlocked
            // store is not allowed. The watchdog's patch changes both bytes
            // and sits on an eight-byte boundary.
            const uint8_t* cur = reinterpret_cast<const uint8_t*>(at);
            if (n == 2 && cur[1] == b[1])
                InterlockedExchange8(reinterpret_cast<volatile char*>(at), static_cast<char>(b[0]));
            else if (n == 2 && (at & 1) == 0)
                InterlockedExchange16(reinterpret_cast<volatile SHORT*>(at),
                                      static_cast<SHORT>(b[0] | (b[1] << 8)));
            else
                memcpy(reinterpret_cast<void*>(at), b, n);
            VirtualProtect(reinterpret_cast<void*>(at), n, old, &old);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(at), n);
            return true;
        }
    }

    int Register(const char* name, uintptr_t rva, const uint8_t* orig, const uint8_t* repl, unsigned n)
    {
        if (g_n >= kMax || n > kWidth)
        {
            LOG_ERR("[patch] %s: no room", name);
            return -1;
        }
        const uintptr_t at = bp::mem::Game().base + rva;
        uint8_t cur[kWidth] = {};
        if (!bp::mem::ReadBytes(at, cur, n))
        {
            LOG_ERR("[patch] %s: +0x%llX is not readable, so this is not the build the patch was made for; "
                    "nothing will be written", name, static_cast<unsigned long long>(rva));
            return -1;
        }
        if (memcmp(cur, orig, n) != 0)
        {
            char have[64];
            HexLine(cur, n, have, sizeof have);
            LOG_ERR("[patch] %s at +0x%llX reads %s, not the bytes this build should have there. Either the game "
                    "was updated or another mod changed the same place; nothing will be written", name,
                    static_cast<unsigned long long>(rva), have);
            return -1;
        }
        Entry& e = g_patches[g_n];
        memset(&e, 0, sizeof e);
        strncpy(e.name, name, sizeof e.name - 1);
        e.at = at;
        e.len = n;
        memcpy(e.orig, orig, n);
        memcpy(e.repl, repl, n);
        return g_n++;
    }

    bool Set(int index, bool on)
    {
        if (index < 0 || index >= g_n) return false;
        Entry& e = g_patches[index];
        if (e.on == on) return true;
        const uint8_t* want = on ? e.repl : e.orig;
        if (!Write(e.at, want, e.len))
        {
            LOG_ERR("[patch] %s: VirtualProtect refused the write", e.name);
            return false;
        }
        uint8_t cur[kWidth] = {};
        bp::mem::ReadBytes(e.at, cur, e.len);
        if (memcmp(cur, want, e.len) != 0)
        {
            char now[64];
            HexLine(cur, e.len, now, sizeof now);
            LOG_ERR("[patch] %s: wrote the bytes but read back %s", e.name, now);
            return false;
        }
        e.on = on;
        return true;
    }

    bool Apply(const char* name, uintptr_t rva, const uint8_t* orig, const uint8_t* repl, unsigned n)
    {
        const int i = Register(name, rva, orig, repl, n);
        if (i < 0) return false;
        if (!Set(i, true)) return false;
        LOG_OK("[patch] %s at +0x%llX written", name, static_cast<unsigned long long>(rva));
        return true;
    }

    void RestoreAll()
    {
        for (int i = g_n - 1; i >= 0; --i)
        {
            const Entry& e = g_patches[i];
            if (!e.on) continue;
            uint8_t cur[kWidth] = {};
            // Only put back what is still ours. Another mod may have written
            // over the same bytes since, and restoring then would undo its
            // patch rather than this one.
            if (bp::mem::ReadBytes(e.at, cur, e.len) && memcmp(cur, e.repl, e.len) == 0)
                Write(e.at, e.orig, e.len);
        }
        g_n = 0;
    }
}
