#include "game/catchwatch.h"

#include <Windows.h>
#include <cstdint>
#include <cstring>

#include "core/log.h"
#include "game/mem.h"
#include "game/sites.h"

namespace bp::catchwatch
{
    namespace
    {
        // The catch component's own state lives in its first bytes: +0x28 is
        // the carrier handle KeepCarried reads, +0x38 is the field the
        // release tests first. 0x60 covers both with room around them.
        constexpr unsigned kBytes = 0x60;
        constexpr int      kSlots = 8;

        struct Slot
        {
            uintptr_t obj = 0;
            uint8_t   was[kBytes] = {};
            bool      seen = false;
        };
        Slot g_slots[kSlots];

        bool Wanted(uintptr_t obj, bool anyClass, const char** clsOut)
        {
            const char* cls = bp::mem::RttiShort(obj);
            *clsOut = cls ? cls : "?";
            if (anyClass) return true;
            return cls && strstr(cls, "Catch") != nullptr;
        }

        Slot* SlotFor(uintptr_t obj)
        {
            for (Slot& s : g_slots) if (s.seen && s.obj == obj) return &s;
            for (Slot& s : g_slots) if (!s.seen) { s.obj = obj; return &s; }
            return nullptr;
        }
    }

    void Tick(bool anyClass)
    {
        for (int i = 0; i < 32; ++i)
        {
            const uint64_t m = bp::sites::MarkAt(i);
            if (!m) break;
            const uintptr_t obj = static_cast<uintptr_t>(m);
            if (!bp::mem::Readable(obj, kBytes)) continue;

            const char* cls = nullptr;
            if (!Wanted(obj, anyClass, &cls)) continue;

            Slot* s = SlotFor(obj);
            if (!s) continue;

            uint8_t now[kBytes] = {};
            if (!bp::mem::ReadBytes(obj, now, kBytes)) continue;

            if (!s->seen)
            {
                s->seen = true;
                memcpy(s->was, now, kBytes);
                uint32_t carrier = 0, held = 0;
                memcpy(&carrier, now + 0x28, 4);
                memcpy(&held, now + 0x38, 4);
                LOG("[catchwatch] watching %s at 0x%llX: carrier handle +0x28 is 0x%08X, +0x38 is 0x%08X", cls,
                    static_cast<unsigned long long>(obj), carrier, held);
                continue;
            }
            if (memcmp(s->was, now, kBytes) == 0) continue;

            for (unsigned off = 0; off < kBytes; off += 4)
            {
                uint32_t a = 0, b = 0;
                memcpy(&a, s->was + off, 4);
                memcpy(&b, now + off, 4);
                if (a == b) continue;
                LOG("[catchwatch] %s at 0x%llX: +0x%02X was 0x%08X, now 0x%08X", cls,
                    static_cast<unsigned long long>(obj), off, a, b);
            }
            memcpy(s->was, now, kBytes);
        }
    }
}
