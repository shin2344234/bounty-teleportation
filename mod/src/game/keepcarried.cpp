#include "game/keepcarried.h"

#include <Windows.h>
#include <intrin.h>
#include <cstring>

#include "core/log.h"
#include "game/farhook.h"
#include "game/mem.h"

namespace bp::keepcarried
{
    namespace
    {
        using Fn = uint64_t(*)(uint64_t comp, uint64_t key);
        Fn   g_orig = nullptr;
        bool g_requireClass = true;
        Gate   g_gate = nullptr;
        OnKeep g_onKeep = nullptr;
        volatile LONG g_asked = 0, g_kept = 0;
        LONG g_reportedAsked = 0, g_reportedKept = 0;

        // The check's argument is the component at +0xb0 of the actor's
        // table, and its +8 is the actor. The actor's own catch component
        // sits at +0x70 of the same table; its +0x28 is the handle of
        // whoever is carrying it, 0xA0100001 on the outlaw in both
        // session-nine logs while he was on the player's back and zero once
        // released. Every read is guarded; anything unreadable is "not
        // carried" and the original answers.
        bool Carried(uint64_t comp, uintptr_t* actorOut, uintptr_t* catchOut, uint32_t* byOut)
        {
            uintptr_t actor = 0, table = 0, catchc = 0;
            if (!bp::mem::ReadPtr(static_cast<uintptr_t>(comp) + 8, &actor)) return false;
            if (!bp::mem::ReadPtr(actor + 0x68, &table)) return false;
            if (!bp::mem::ReadPtr(table + 0x70, &catchc)) return false;
            uint32_t by = 0;
            if (!bp::mem::Read32(catchc + 0x28, &by) || !by) return false;
            if (g_requireClass)
            {
                const char* cls = bp::mem::RttiShort(catchc);
                if (!cls || !strstr(cls, "CatchActorComponent")) return false;
            }
            *actorOut = actor;
            *catchOut = catchc;
            *byOut = by;
            return true;
        }

        uint64_t Detour(uint64_t comp, uint64_t key)
        {
            InterlockedIncrement(&g_asked);
            if (g_gate && !g_gate()) return g_orig(comp, key);
            uintptr_t actor = 0, catchc = 0;
            uint32_t by = 0;
            if (!Carried(comp, &actor, &catchc, &by)) return g_orig(comp, key);

            const LONG kept = InterlockedIncrement(&g_kept);
            if (g_onKeep) g_onKeep(actor, catchc);
            // The thunk at +0x1F53D10 jumps here, so the return address is
            // the thunk's caller: +0x2818165 when it is the sweep asking.
            const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
            uint64_t ownKey = 0;
            bp::mem::Read64(static_cast<uintptr_t>(comp) + 0x2e0, &ownKey);
            const char* acls = bp::mem::RttiShort(actor);
            const char* ccls = bp::mem::RttiShort(static_cast<uintptr_t>(comp));
            LOG("[keepcarried] kept %ld: %s@0x%llX is carried by handle 0x%08X, so \"does anyone else hold it\" is "
                "answered yes and it stays in the world. Asked from +0x%llX with key 0x%llX; the actor's own key is "
                "0x%llX; the component asked is a %s at 0x%llX, its catch component 0x%llX",
                kept, acls ? acls : "?", static_cast<unsigned long long>(actor), by,
                static_cast<unsigned long long>(bp::mem::Rva(caller)), static_cast<unsigned long long>(key),
                static_cast<unsigned long long>(ownKey), ccls ? ccls : "?", static_cast<unsigned long long>(comp),
                static_cast<unsigned long long>(catchc));
            return 1;
        }
    }

    bool Hook(uintptr_t target, bool requireClass)
    {
        g_requireClass = requireClass;
        char why[160] = "";
        if (!bp::farhook::Install("keepcarried", target, reinterpret_cast<void*>(&Detour),
                                  reinterpret_cast<void**>(&g_orig), why, sizeof why))
        {
            LOG_ERR("[keepcarried] could not hook the holder check at 0x%llX: %s",
                    static_cast<unsigned long long>(target), why);
            return false;
        }
        LOG_OK("[keepcarried] hooked the holder check at +0x%llX. An actor whose catch component says it is being "
               "carried is kept in the world by the departure sweep; every such answer is written with who asked",
               static_cast<unsigned long long>(bp::mem::Rva(target)));
        return true;
    }

    void SetGate(Gate gate) { g_gate = gate; }
    void SetOnKeep(OnKeep onKeep) { g_onKeep = onKeep; }

    void Summarise()
    {
        const LONG asked = InterlockedCompareExchange(&g_asked, 0, 0);
        const LONG kept = InterlockedCompareExchange(&g_kept, 0, 0);
        if (asked == g_reportedAsked && kept == g_reportedKept) return;
        LOG("[keepcarried] %ld asked, %ld kept (+%ld asked, +%ld kept since last)", asked, kept,
            asked - g_reportedAsked, kept - g_reportedKept);
        g_reportedAsked = asked;
        g_reportedKept = kept;
    }
}
