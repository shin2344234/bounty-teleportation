#include "game/errors.h"

#include <Windows.h>
#include <cstdlib>
#include <cstring>

#include "core/log.h"
#include "game/errors_table.h"
#include "game/mem.h"

namespace
{
    struct Resolved { uint32_t code; const char* name; };

    Resolved g_map[bp::errors_table::kCount];
    int  g_n = 0;
    int  g_zero = 0;
    int  g_unreadable = 0;
    int  g_dupes = 0;
    int  g_attempts = 0;
    bool g_loaded = false;
    bool g_stale = true;

    int Compare(const void* a, const void* b)
    {
        const uint32_t x = static_cast<const Resolved*>(a)->code;
        const uint32_t y = static_cast<const Resolved*>(b)->code;
        return x < y ? -1 : (x > y ? 1 : 0);
    }
}

namespace bp::errors
{
    int Load()
    {
        if (g_loaded) return g_n;

        const uintptr_t base = mem::Game().base;
        if (!base) { LOG_ERR("[errors] the game image is not resolved; no error names this session"); return 0; }

        ++g_attempts;
        g_n = g_zero = g_unreadable = g_dupes = 0;
        for (int i = 0; i < errors_table::kCount; ++i)
        {
            const errors_table::Entry& e = errors_table::kEntries[i];
            uint32_t v = 0;
            if (!mem::Read32(base + e.rva, &v)) { ++g_unreadable; continue; }
            if (v == 0) { ++g_zero; continue; }
            g_map[g_n].code = v;
            g_map[g_n].name = e.name;
            ++g_n;
        }
        qsort(g_map, static_cast<size_t>(g_n), sizeof(Resolved), Compare);
        for (int i = 1; i < g_n; ++i)
            if (g_map[i].code == g_map[i - 1].code) ++g_dupes;

        // A table from another build points at whatever now lives at those
        // addresses: mostly zero, and what is not zero collides. Both are
        // checked because either alone can look survivable.
        const int total = errors_table::kCount;
        g_stale = (g_n * 10 < total * 6) || (g_dupes * 20 > g_n);

        // Only a run that produced usable names is final. A run that did not
        // may simply have been early, and the worker calls again.
        if (!g_stale) g_loaded = true;

        LOG("[errors] attempt %d: %d of %d error globals answered, %d read zero, %d were unreadable, %d "
            "collide. Table built for %s.", g_attempts, g_n, total, g_zero, g_unreadable, g_dupes,
            errors_table::kBuild);
        if (g_stale)
        {
            // Which of the two it is matters. All zero and readable is an
            // uninitialised table and will fix itself; unreadable, or a
            // scatter of values that collide, is a table for another build.
            if (g_unreadable == 0 && g_n == 0)
                LOG("[errors] every global is readable and every one is zero, which is what this looks like "
                    "before the game's static initialisers have run. Trying again shortly.");
            else
                LOG_ERR("[errors] that is not the shape of a table waiting to be filled in. Run "
                        "research/gen_errors.py against this build and rebuild; until then every code is "
                        "logged as a number.");
            return g_n;
        }

        // The three the investigation turns on, written down so the log carries
        // its own proof that the table lines up with the running game.
        static const char* const kAnchors[] = {
            "eErrNoFieldMoveHolding",
            "eErrNoCantDoWhileCatchingOrCatched",
            "eErrNoInvalidField",
        };
        for (const char* a : kAnchors)
        {
            const uint32_t v = Value(a);
            if (v) LOG("[errors] %s = %lu (0x%08lX)", a, static_cast<unsigned long>(v), static_cast<unsigned long>(v));
            else   LOG_ERR("[errors] %s did not resolve, which it should have. Treat the names below with care.", a);
        }
        return g_n;
    }

    const char* Name(uint32_t code)
    {
        if (!g_loaded || g_stale || !code) return nullptr;
        int lo = 0, hi = g_n - 1;
        while (lo <= hi)
        {
            const int mid = lo + (hi - lo) / 2;
            if (g_map[mid].code == code) return g_map[mid].name;
            if (g_map[mid].code < code) lo = mid + 1; else hi = mid - 1;
        }
        return nullptr;
    }

    uint32_t Value(const char* name)
    {
        if (!g_loaded || !name) return 0;
        for (int i = 0; i < g_n; ++i)
            if (strcmp(g_map[i].name, name) == 0) return g_map[i].code;
        return 0;
    }

    bool Stale() { return g_stale; }
    bool Ready() { return g_loaded && !g_stale; }

    void DumpAll()
    {
        LOG("[errors] every resolved code, lowest first:");
        for (int i = 0; i < g_n; ++i)
            LOG("[errors]   %10lu  0x%08lX  %s", static_cast<unsigned long>(g_map[i].code),
                static_cast<unsigned long>(g_map[i].code), g_map[i].name);
    }
}
