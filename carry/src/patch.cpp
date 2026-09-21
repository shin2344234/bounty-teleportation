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
            memcpy(reinterpret_cast<void*>(at), b, n);
            VirtualProtect(reinterpret_cast<void*>(at), n, old, &old);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(at), n);
            return true;
        }
    }

    bool Apply(const char* name, uintptr_t rva, const uint8_t* orig, const uint8_t* repl, unsigned n)
    {
        if (g_n >= kMax || n > kWidth)
        {
            LOG_ERR("[patch] %s: no room", name);
            return false;
        }
        const uintptr_t at = bp::mem::Game().base + rva;
        uint8_t cur[kWidth] = {};
        if (!bp::mem::ReadBytes(at, cur, n))
        {
            LOG_ERR("[patch] %s: +0x%llX is not readable, so this is not the build the patch was made for; "
                    "nothing written", name, static_cast<unsigned long long>(rva));
            return false;
        }
        char have[64], now[64];
        HexLine(cur, n, have, sizeof have);
        if (memcmp(cur, repl, n) == 0)
        {
            LOG("[patch] %s at +0x%llX already reads %s, nothing to do", name,
                static_cast<unsigned long long>(rva), have);
            return true;
        }
        if (memcmp(cur, orig, n) != 0)
        {
            LOG_ERR("[patch] %s at +0x%llX reads %s, not the bytes this build should have there. Either the game "
                    "was updated or another mod changed the same place; nothing written", name,
                    static_cast<unsigned long long>(rva), have);
            return false;
        }
        if (!Write(at, repl, n))
        {
            LOG_ERR("[patch] %s: VirtualProtect refused +0x%llX", name, static_cast<unsigned long long>(rva));
            return false;
        }
        bp::mem::ReadBytes(at, cur, n);
        HexLine(cur, n, now, sizeof now);
        if (memcmp(cur, repl, n) != 0)
        {
            LOG_ERR("[patch] %s at +0x%llX: wrote the bytes but read back %s", name,
                    static_cast<unsigned long long>(rva), now);
            return false;
        }
        Entry& e = g_patches[g_n++];
        memset(&e, 0, sizeof e);
        strncpy(e.name, name, sizeof e.name - 1);
        e.at = at;
        e.len = n;
        memcpy(e.orig, orig, n);
        memcpy(e.repl, repl, n);
        LOG_OK("[patch] %s at +0x%llX: was %s, now %s", name, static_cast<unsigned long long>(rva), have, now);
        return true;
    }

    void RestoreAll()
    {
        while (g_n > 0)
        {
            const Entry& e = g_patches[--g_n];
            uint8_t cur[kWidth] = {};
            // Only put back what is still ours. Another mod may have written
            // over the same bytes since, and restoring then would undo its
            // patch rather than this one.
            if (bp::mem::ReadBytes(e.at, cur, e.len) && memcmp(cur, e.repl, e.len) == 0)
                Write(e.at, e.orig, e.len);
        }
    }
}
