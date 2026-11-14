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
        Accept g_accept = nullptr;
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

        // Each place in the game that calls the check, written once the first
        // time it asks, so a log shows every caller went through the entry
        // below and came back.
        volatile LONG64 g_callers[32] = {};

        void NoteCaller(uintptr_t caller)
        {
            for (auto& slot : g_callers)
            {
                const LONG64 seen = InterlockedCompareExchange64(&slot, static_cast<LONG64>(caller), 0);
                if (seen == static_cast<LONG64>(caller)) return;
                if (seen == 0)
                {
                    LOG("[keepcarried] first call through the register-keeping entry from +0x%llX, and it came back "
                        "with that caller's registers as the game's own check leaves them",
                        static_cast<unsigned long long>(bp::mem::Rva(caller)));
                    return;
                }
            }
        }

        uint64_t Detour(uint64_t comp, uint64_t key, uintptr_t caller)
        {
            InterlockedIncrement(&g_asked);
            NoteCaller(caller);
            if (g_gate && !g_gate()) return g_orig(comp, key);
            uintptr_t actor = 0, catchc = 0;
            uint32_t by = 0;
            if (!Carried(comp, &actor, &catchc, &by)) return g_orig(comp, key);
            if (g_accept && !g_accept(actor, by)) return g_orig(comp, key);

            const LONG kept = InterlockedIncrement(&g_kept);
            if (g_onKeep) g_onKeep(actor, catchc);
            // The entry passes the game's return address, which is the
            // caller of the check, or of its thunk on builds that have one:
            // +0x2818165 when it is the sweep asking in 2.03.00.
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

        // The game's check writes only rax, r8, r9, r10 and the flags, and at
        // least one caller counts on that. On exe 1.0.0.3663 the function at
        // +0xE9787A0 keeps its own argument in r11, the component in rcx and
        // a zero in dl across the call, then reads [r11+0x88]. Detour is
        // ordinary compiled code and may change any volatile register. Its
        // two indirect calls go through the control flow guard dispatch, and
        // on a machine where that check is live it returns with r11 holding
        // a bitmap word, which is all ones for the trampoline's page. Justin's
        // crash dump from 13 November 2026 has r11 = -1 and a read of 0x87.
        //
        // So the hook enters through this, which saves rcx, rdx, r8 to r11
        // and xmm0 to xmm5, passes the game's return address as the third
        // argument, calls Detour and puts all of it back. To the caller the
        // hooked check writes rax and the flags and nothing else.
        void* BuildEntry()
        {
            static const unsigned char kHead[] = {
                0x51,                                     // push rcx
                0x52,                                     // push rdx
                0x41, 0x50,                               // push r8
                0x41, 0x51,                               // push r9
                0x41, 0x52,                               // push r10
                0x41, 0x53,                               // push r11
                0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, // sub rsp, 0x88: rsp is 16-aligned at the call
                0xF3, 0x0F, 0x7F, 0x44, 0x24, 0x20,       // movdqu [rsp+0x20], xmm0
                0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x30,       // movdqu [rsp+0x30], xmm1
                0xF3, 0x0F, 0x7F, 0x54, 0x24, 0x40,       // movdqu [rsp+0x40], xmm2
                0xF3, 0x0F, 0x7F, 0x5C, 0x24, 0x50,       // movdqu [rsp+0x50], xmm3
                0xF3, 0x0F, 0x7F, 0x64, 0x24, 0x60,       // movdqu [rsp+0x60], xmm4
                0xF3, 0x0F, 0x7F, 0x6C, 0x24, 0x70,       // movdqu [rsp+0x70], xmm5
                0x4C, 0x8B, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00, // mov r8, [rsp+0xB8]: the game's return address
                0x48, 0xB8,                               // mov rax, imm64 (Detour, written below)
            };
            static const unsigned char kTail[] = {
                0xFF, 0xD0,                               // call rax
                0xF3, 0x0F, 0x6F, 0x44, 0x24, 0x20,       // movdqu xmm0, [rsp+0x20]
                0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x30,       // movdqu xmm1, [rsp+0x30]
                0xF3, 0x0F, 0x6F, 0x54, 0x24, 0x40,       // movdqu xmm2, [rsp+0x40]
                0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x50,       // movdqu xmm3, [rsp+0x50]
                0xF3, 0x0F, 0x6F, 0x64, 0x24, 0x60,       // movdqu xmm4, [rsp+0x60]
                0xF3, 0x0F, 0x6F, 0x6C, 0x24, 0x70,       // movdqu xmm5, [rsp+0x70]
                0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00, // add rsp, 0x88
                0x41, 0x5B,                               // pop r11
                0x41, 0x5A,                               // pop r10
                0x41, 0x59,                               // pop r9
                0x41, 0x58,                               // pop r8
                0x5A,                                     // pop rdx
                0x59,                                     // pop rcx
                0xC3,                                     // ret
            };
            unsigned char* p = static_cast<unsigned char*>(
                VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (!p) return nullptr;
            const uintptr_t detour = reinterpret_cast<uintptr_t>(&Detour);
            memcpy(p, kHead, sizeof kHead);
            memcpy(p + sizeof kHead, &detour, sizeof detour);
            memcpy(p + sizeof kHead + sizeof detour, kTail, sizeof kTail);
            DWORD old = 0;
            if (!VirtualProtect(p, 4096, PAGE_EXECUTE_READ, &old))
            {
                VirtualFree(p, 0, MEM_RELEASE);
                return nullptr;
            }
            FlushInstructionCache(GetCurrentProcess(), p, 4096);
            return p;
        }
    }

    bool Hook(uintptr_t target, bool requireClass)
    {
        g_requireClass = requireClass;
        char why[160] = "";
        void* entry = BuildEntry();
        if (!entry)
        {
            LOG_ERR("[keepcarried] could not hook the holder check at 0x%llX: the page for its register-keeping "
                    "entry could not be made", static_cast<unsigned long long>(target));
            return false;
        }
        if (!bp::farhook::Install("keepcarried", target, entry,
                                  reinterpret_cast<void**>(&g_orig), why, sizeof why))
        {
            LOG_ERR("[keepcarried] could not hook the holder check at 0x%llX: %s",
                    static_cast<unsigned long long>(target), why);
            return false;
        }
        LOG_OK("[keepcarried] the holder check is entered through a stub that keeps rcx, rdx, r8 to r11 and xmm0 to "
               "xmm5 for its caller, as the game's own check does");
        LOG_OK("[keepcarried] hooked the holder check at +0x%llX. An actor whose catch component says it is being "
               "carried is kept in the world by the departure sweep; every such answer is written with who asked",
               static_cast<unsigned long long>(bp::mem::Rva(target)));
        return true;
    }

    void SetGate(Gate gate) { g_gate = gate; }
    void SetOnKeep(OnKeep onKeep) { g_onKeep = onKeep; }
    void SetAccept(Accept accept) { g_accept = accept; }

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
