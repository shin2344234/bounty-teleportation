#include "mod.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <intrin.h>

#include "core/log.h"
#include "core/paths.h"
#include "game/farhook.h"
#include "game/keepcarried.h"
#include "game/mem.h"
#include "ini_default.h"
#include "patch.h"
#include "version.h"

// Bounty Teleportation: the four patches and the one hook that let the player take a
// caught bounty target through a map teleport, and nothing else.
//
// All of it was found by Bounty Probe, which is the research plugin next door
// and writes half a gigabyte a minute doing it. This one writes about twenty
// lines a session. The probe's FEASIBILITY.md has the working; what follows
// is only what each address is.
namespace
{
    std::atomic<bool> g_stop{false};
    HANDLE g_thread = nullptr;

    struct Settings
    {
        bool keepCatch = true;
        bool keepCarried = true;
    };

    // ---- the catch release, in its four places ----------------------------
    //
    // A catch is the game's word for carrying an actor. The component holding
    // one lives at [[actor+0x68]+0x70], with the carrier's handle at +0x28 and
    // the held actor's at +0x38, and catch_update is what ends it. Three
    // callers end it as part of a teleport and one ends it on a timer; each
    // sits behind a short jump that already skips it in the ordinary case, so
    // each patch is two bytes that make that jump unconditional.
    //
    // Every address below belongs to one game build. The 21 September 2026
    // patch from 1.0.0.2944 to 1.0.0.2949 moved most of them by 0x10 and the
    // client's and the sweep's much further, which turned 1.0.0 and 1.0.1 into
    // plugins that check, find the wrong bytes and do nothing. The 23
    // September patch to 1.0.0.2976 moved them again, the client release by
    // 0x18280. The DLC on 29 October, 1.0.0.3392, moved all of them, put the
    // character control release in vtable slot 0x1F8 where it had been in
    // 0x200, and rewrote the teleport handler's prologue, so the slot and the
    // prologue are per build too. The 30 October hotfix, 1.0.0.3424, moved
    // them all again and changed nothing else this plugin reads. 1.0.0.3446
    // moved them once more and dropped the thunk in front of the holder
    // check, so the sweep calls it directly there. The 31 October patch,
    // 1.0.0.3460, moved them all again and changed none of that code. The
    // 1 November patch, 1.0.0.3462, moved the server and client releases, the
    // sweep and the teleport handler and left the rest where 3460 had it, again
    // with the same code. 1.0.0.3479, later the same day, moved the client
    // release by 0x8FC80 and nearly everything else back by 0x50, and changed
    // none of that code either. Every build is listed, and the one whose
    // addresses all check out is the one used. research\derive_2949.py is how the later sets were
    // found: every one of them from a byte pattern or from a reference to
    // something already found, never from an offset against the old build.

    struct Release
    {
        const char* label;
        uintptr_t   at;          // the two bytes that decide whether it runs
        uint8_t     orig[2];
        uint8_t     repl[2];
        uintptr_t   call;        // the catch_update call it skips
        uintptr_t   guard;       // the test in front of it
        const uint8_t* shape;    // what that test must read
        unsigned    shapeLen;
        uintptr_t   vtable;      // 0 when the function is in no vtable
        uintptr_t   slotTarget;  // what the build's release slot of it must hold
        uintptr_t   thunkTo;     // 0 unless that slot points at a jmp
    };

    // cmp [rcx+0x38],0 / je / mov bl,1 / jmp / cmp [rcx+0x28],0 / setne.
    // The three teleport copies are the same function compiled three times
    // and all three read this.
    const uint8_t kTeleportGuard[16] = { 0x83, 0x79, 0x38, 0x00, 0x74, 0x04, 0xB3, 0x01,
                                         0xEB, 0x07, 0x83, 0x79, 0x28, 0x00, 0x0F, 0x95 };

    // The watchdog reads both handles into registers first:
    // test edi,edi / jne / test ebx,ebx / je.
    const uint8_t kWatchdogGuard[8] = { 0x85, 0xFF, 0x75, 0x04, 0x85, 0xDB, 0x74, 0x3E };

    constexpr int kReleaseCount = 4;

    // A catch_update call the plugin does not patch, named only so the log
    // can say which one ran. Nothing is written at these.
    struct OtherRelease
    {
        const char* label;
        uintptr_t   call;
    };

    struct Build
    {
        const char* name;          // the exe version it was read off
        uintptr_t   catchUpdate;   // where every release below must call
        Release     releases[kReleaseCount];
        uintptr_t   holderCheck;   // the departure sweep's "does anyone hold it"
        uintptr_t   holderThunk;   // the jmp that reaches it, 0 where the sweep calls it directly
        uintptr_t   sweepCall;     // the sweep's call to that thunk, or to the check itself
        uintptr_t   teleport;      // the map teleport handler
        uintptr_t   teleportCall1; // its two callers, both in the message handler
        uintptr_t   teleportCall2;
        OtherRelease others[2];    // zero where they were never derived
        uintptr_t   catchTick;     // the catch component's tick, the watchdog's own function
        uintptr_t   releaseSlot;   // the vtable slot the character control release is in
        const uint8_t* teleportHead; // the teleport handler's first 15 bytes
    };

    // mov rax,rsp / mov [rax+10],rbx / mov [rax+18],rsi / mov [rax+20],rdi,
    // the teleport handler's up to 1.0.0.2976.
    const uint8_t kTeleportHead[15] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48,
                                        0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20 };
    // mov [rsp+10],rbx / mov [rsp+18],r8 / mov [rsp+8],rcx, its prologue on
    // 1.0.0.3392, which keeps the moved actor in its home slot instead of r13.
    const uint8_t kTeleportHead3392[15] = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x4C, 0x89, 0x44,
                                            0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08 };

    // The releases, in order: the release slot (0x200, or 0x1F8 from
    // 1.0.0.3392) of the server and common CharacterControl components,
    // called by the teleport handler once the player has been moved; the
    // client's own copy of that function, reached through a thunk, whose
    // absence is what made the outlaw arrive lying on the ground when only
    // the server's was patched; a client state
    // transition that is in no vtable and fires a second after the confirm;
    // and the watchdog on the catch component itself, which runs about six
    // times a second on every catch in the world and drops one the carry
    // animation no longer backs. The watchdog's patch goes over the first
    // test rather than the `je` below it: with something actually held, the
    // `jne` in between jumps past that `je` and never reads it.
    const Build kBuilds[] = {
        {
            "1.0.0.3479", 0x226AE10,
            {
                { "keepcatch", 0x2515C54, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2515C73, 0x2515C34,
                  kTeleportGuard, 16, 0x5EE6718, 0x2515C00, 0 },
                { "keepcatch_client", 0x96487D4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x96487F3, 0x96487B4,
                  kTeleportGuard, 16, 0x593D8E0, 0x945540, 0x9648780 },
                { "keepcatch_state", 0x17886DD, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x17886FA, 0x17886BB,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226C038, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226C079, 0x226C038,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213BC30, 0, 0x2A5895C,
            0x2E67C30, 0x2E689DA, 0x2E68FAC,
            { { "the release in +0x1788A80", 0x1788F43 }, { "the release in +0x227F500", 0x227F6B6 } },
            0x226BFB0, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3462", 0x226AE60,
            {
                { "keepcatch", 0x2515CA4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2515CC3, 0x2515C84,
                  kTeleportGuard, 16, 0x5EE6718, 0x2515C50, 0 },
                { "keepcatch_client", 0x95B8B54, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x95B8B73, 0x95B8B34,
                  kTeleportGuard, 16, 0x593D8E0, 0x945570, 0x95B8B00 },
                { "keepcatch_state", 0x178872D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178874A, 0x178870B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226C088, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226C0C9, 0x226C088,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213BC80, 0, 0x2A589AC,
            0x2E67C80, 0x2E68A2A, 0x2E68FFC,
            { { "the release in +0x1788AD0", 0x1788F93 }, { "the release in +0x227F550", 0x227F706 } },
            0x226C000, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3460", 0x226AE60,
            {
                { "keepcatch", 0x2515994, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x25159B3, 0x2515974,
                  kTeleportGuard, 16, 0x5EE57C8, 0x2515940, 0 },
                { "keepcatch_client", 0x94CE5A4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x94CE5C3, 0x94CE584,
                  kTeleportGuard, 16, 0x593C8E0, 0x945570, 0x94CE550 },
                { "keepcatch_state", 0x178872D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178874A, 0x178870B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226C088, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226C0C9, 0x226C088,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213BC80, 0, 0x2A5867C,
            0x2E67940, 0x2E686EA, 0x2E68CBC,
            { { "the release in +0x1788AD0", 0x1788F93 }, { "the release in +0x227F550", 0x227F706 } },
            0x226C000, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3446", 0x2267AA0,
            {
                { "keepcatch", 0x2512214, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2512233, 0x25121F4,
                  kTeleportGuard, 16, 0x5EE15C8, 0x25121C0, 0 },
                { "keepcatch_client", 0x9536C44, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x9536C63, 0x9536C24,
                  kTeleportGuard, 16, 0x59388D0, 0x944A30, 0x9536BF0 },
                { "keepcatch_state", 0x178561D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178563A, 0x17855FB,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x2268CC8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x2268D09, 0x2268CC8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x21388B0, 0, 0x2A5505C,
            0x2E63DF0, 0x2E64B9A, 0x2E6516C,
            { { "the release in +0x17859C0", 0x1785E83 }, { "the release in +0x227C190", 0x227C346 } },
            0x2268C40, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3424", 0x22668F0,
            {
                { "keepcatch", 0x2511064, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2511083, 0x2511044,
                  kTeleportGuard, 16, 0x5EDF4C8, 0x2511010, 0 },
                { "keepcatch_client", 0x97BF134, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x97BF153, 0x97BF114,
                  kTeleportGuard, 16, 0x5936838, 0x944A00, 0x97BF0E0 },
                { "keepcatch_state", 0x1784A6D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x1784A8A, 0x1784A4B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x2267B18, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x2267B59, 0x2267B18,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xC9F4A10, 0x2137880, 0x2A539DC,
            0x2E624A0, 0x2E6324A, 0x2E6381C,
            { { "the release in +0x1784E10", 0x17852D3 }, { "the release in +0x227AFE0", 0x227B196 } },
            0x2267A90, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3392", 0x22656B0,
            {
                { "keepcatch", 0x250FDD4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x250FDF3, 0x250FDB4,
                  kTeleportGuard, 16, 0x5EDD4B8, 0x250FD80, 0 },
                { "keepcatch_client", 0x967143F, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x967145E, 0x967141F,
                  kTeleportGuard, 16, 0x5934850, 0x9441D0, 0x96713E0 },
                { "keepcatch_state", 0x178393D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178395A, 0x178391B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x22668D8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x2266919, 0x22668D8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xC91E0F0, 0x2136620, 0x2A5274C,
            0x2E60CA0, 0x2E61A4A, 0x2E6201C,
            { { "the release in +0x1783CE0", 0x17841A3 }, { "the release in +0x2279DA0", 0x2279F56 } },
            0x2266850, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.2976", 0x20AD400,
            {
                { "keepcatch", 0x2329184, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x23291A3, 0x2329164,
                  kTeleportGuard, 16, 0x5B25468, 0x2329130, 0 },
                { "keepcatch_client", 0x9857044, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x9857063, 0x9857024,
                  kTeleportGuard, 16, 0x55B5460, 0x860FF0, 0x9856FF0 },
                { "keepcatch_state", 0x156F1CD, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x156F1EA, 0x156F1AB,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x20AE628, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x20AE669, 0x20AE628,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xDD9D1E0, 0x1F53D50, 0x28181E0,
            0x2BC96C0, 0x2BCA5DD, 0x2BCAB80,
            { { "the release in +0x156F550", 0x156F9F5 }, { "the release in +0x20C0610", 0x20C07C6 } },
            0x20AE5A0, 0x200, kTeleportHead,
        },
        {
            "1.0.0.2949", 0x20AD3B0,
            {
                { "keepcatch", 0x2329134, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2329153, 0x2329114,
                  kTeleportGuard, 16, 0x5B25260, 0x23290E0, 0 },
                { "keepcatch_client", 0x983EDC4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x983EDE3, 0x983EDA4,
                  kTeleportGuard, 16, 0x55B53C8, 0x860F90, 0x983ED70 },
                { "keepcatch_state", 0x156F25D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x156F27A, 0x156F23B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x20AE5D8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x20AE619, 0x20AE5D8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xDD526C0, 0x1F53D20, 0x2818170,
            0x2BC9650, 0x2BCA56D, 0x2BCAB10,
            {}, 0x20AE550, 0x200, kTeleportHead,
        },
        {
            "1.0.0.2944", 0x20AD3A0,
            {
                { "keepcatch", 0x2329124, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2329143, 0x2329104,
                  kTeleportGuard, 16, 0x5B25260, 0x23290D0, 0 },
                { "keepcatch_client", 0x99B6D0F, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x99B6D2E, 0x99B6CEF,
                  kTeleportGuard, 16, 0x55B53C8, 0x860F90, 0x99B6CB0 },
                { "keepcatch_state", 0x156F24D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x156F26A, 0x156F22B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x20AE5C8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x20AE609, 0x20AE5C8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xE1478D0, 0x1F53D10, 0x2818160,
            0x2BC9640, 0x2BCA55D, 0x2BCAB00,
            {}, 0x20AE540, 0x200, kTeleportHead,
        },
    };

    // Filled in once a build is recognised.
    const Build* g_build = nullptr;

    uintptr_t BranchTarget(uintptr_t at, uint8_t op)
    {
        uint8_t b[5] = {};
        if (!bp::mem::ReadBytes(bp::mem::Game().base + at, b, 5) || b[0] != op) return 0;
        int32_t rel = 0;
        memcpy(&rel, b + 1, 4);
        return at + 5 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
    }

    int g_releaseIdx[kReleaseCount] = { -1, -1, -1, -1 };

    // True when every address of one release is where that build says. `loud`
    // is off while builds are being tried, so a build that is simply not the
    // one installed does not fill the log with its misses.
    bool ReleaseChecks(const Release& r, uintptr_t catchUpdate, uintptr_t slotOff, bool loud)
    {
        const uintptr_t base = bp::mem::Game().base;
        const uintptr_t target = BranchTarget(r.call, 0xE8);
        if (target != catchUpdate)
        {
            if (loud)
                LOG_ERR("[%s] the call at +0x%llX goes to +0x%llX and not to catch_update at +0x%llX, so this is "
                        "not the release; nothing written", r.label, static_cast<unsigned long long>(r.call),
                        static_cast<unsigned long long>(target), static_cast<unsigned long long>(catchUpdate));
            return false;
        }
        uint8_t guard[16] = {};
        if (!bp::mem::ReadBytes(base + r.guard, guard, r.shapeLen) || memcmp(guard, r.shape, r.shapeLen) != 0)
        {
            if (loud)
                LOG_ERR("[%s] the test at +0x%llX is not the catch check this build should have; nothing written",
                        r.label, static_cast<unsigned long long>(r.guard));
            return false;
        }
        uint8_t at[2] = {};
        if (!bp::mem::ReadBytes(base + r.at, at, 2) || memcmp(at, r.orig, 2) != 0)
        {
            if (loud)
                LOG_ERR("[%s] the jump at +0x%llX is not the one this build should have; nothing written",
                        r.label, static_cast<unsigned long long>(r.at));
            return false;
        }
        if (r.vtable)
        {
            uint64_t slot = 0;
            if (!bp::mem::Read64(base + r.vtable + slotOff, &slot) || slot != base + r.slotTarget)
            {
                if (loud)
                    LOG_ERR("[%s] slot 0x%llX of the vtable at +0x%llX is 0x%llX and not +0x%llX; nothing written",
                            r.label, static_cast<unsigned long long>(slotOff),
                            static_cast<unsigned long long>(r.vtable),
                            static_cast<unsigned long long>(slot), static_cast<unsigned long long>(r.slotTarget));
                return false;
            }
            if (r.thunkTo && BranchTarget(r.slotTarget, 0xE9) != r.thunkTo)
            {
                if (loud)
                    LOG_ERR("[%s] the thunk at +0x%llX does not jump to +0x%llX; nothing written", r.label,
                            static_cast<unsigned long long>(r.slotTarget),
                            static_cast<unsigned long long>(r.thunkTo));
                return false;
            }
        }
        return true;
    }

    // mov [rsp+8],rbx / mov eax,[rcx+0x1c], the holder check's first bytes.
    const uint8_t kHolderHead[9] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x44, 0x8B, 0x41, 0x1C };

    bool BuildChecks(const Build& bld, bool loud)
    {
        const uintptr_t base = bp::mem::Game().base;
        for (const Release& r : bld.releases)
            if (!ReleaseChecks(r, bld.catchUpdate, bld.releaseSlot, loud)) return false;

        uint8_t head[15] = {};
        if (!bp::mem::ReadBytes(base + bld.holderCheck, head, 9) || memcmp(head, kHolderHead, 9) != 0)
        {
            if (loud)
                LOG_ERR("[keepcarried] +0x%llX does not start the way the holder check does",
                        static_cast<unsigned long long>(bld.holderCheck));
            return false;
        }
        const uintptr_t sweepTo = bld.holderThunk ? bld.holderThunk : bld.holderCheck;
        if ((bld.holderThunk && BranchTarget(bld.holderThunk, 0xE9) != bld.holderCheck) ||
            BranchTarget(bld.sweepCall, 0xE8) != sweepTo)
        {
            if (loud)
                LOG_ERR(bld.holderThunk ? "[keepcarried] the sweep no longer reaches the holder check through its thunk"
                                        : "[keepcarried] the sweep no longer calls the holder check");
            return false;
        }
        if (!bp::mem::ReadBytes(base + bld.teleport, head, 15) || memcmp(head, bld.teleportHead, 15) != 0)
        {
            if (loud)
                LOG_ERR("[teleport] +0x%llX does not start the way the map teleport handler does",
                        static_cast<unsigned long long>(bld.teleport));
            return false;
        }
        if (BranchTarget(bld.teleportCall1, 0xE8) != bld.teleport ||
            BranchTarget(bld.teleportCall2, 0xE8) != bld.teleport)
        {
            if (loud) LOG_ERR("[teleport] the teleport's message handler no longer calls it from where it did");
            return false;
        }
        return true;
    }

    // Picks the build whose every address checks out. Nothing is written here.
    const Build* SelectBuild()
    {
        for (const Build& bld : kBuilds)
            if (BuildChecks(bld, false))
            {
                LOG_OK("[mod] this game is %s, and every address for it checks out", bld.name);
                return &bld;
            }
        LOG_ERR("[mod] this game matches none of the %zu builds this plugin knows, the newest being %s. Nothing is "
                "written and nothing is hooked, which is what a game patch looks like from in here. The reasons "
                "for the newest one follow.", _countof(kBuilds), kBuilds[0].name);
        BuildChecks(kBuilds[0], true);
        return nullptr;
    }

    // The addresses are already checked by then, so this only remembers the
    // patches. Registering can still refuse if two of them overlap, which
    // would be a mistake in the table rather than in the game.
    bool RegisterKeepCatch()
    {
        int done = 0;
        for (int i = 0; i < kReleaseCount; ++i)
        {
            const Release& r = g_build->releases[i];
            g_releaseIdx[i] = bp::patch::Register(r.label, r.at, r.orig, r.repl, 2);
            if (g_releaseIdx[i] >= 0) ++done;
        }
        if (done == kReleaseCount)
        {
            LOG_OK("[keepcatch] all %d releases are ready. None is written until a map teleport starts with "
                   "something held, and each comes out again when that carry ends.", kReleaseCount);
            return true;
        }
        LOG_ERR("[keepcatch] only %d of %d releases could be registered, so none will be used: skipping some and "
                "not others leaves the two sides disagreeing about what is carried.", done, kReleaseCount);
        for (int& i : g_releaseIdx) i = -1;
        return false;
    }

    // ---- when the releases are skipped ------------------------------------
    //
    // 1.0.0 skipped all four releases for the whole session. They are not
    // only the teleport's: petting an animal, putting a note away and a grab
    // interrupted by a hit all end through the same catch_update, and the
    // watchdog in particular is how the game clears a catch whose animation
    // has gone. Three bug reports on 21 September 2026 were players left
    // frozen over a dog, holding a note they had stored, or with a bounty
    // stuck to their back, none of them anywhere near a teleport.
    //
    // So they are armed. The map teleport handler runs once per confirm,
    // reached only from the teleport's own message handler, and it moves the
    // player and then calls the first release. If the player is holding
    // something when it starts, the four releases are written there, before
    // any of them can run. They stay written while that carry lasts and come
    // out when it ends: the sweep kept nobody within five seconds, or the
    // outlaw it kept is no longer carried, or the player is no longer holding
    // anything.
    constexpr ULONGLONG kNoKeepMs       = 5000;
    constexpr int       kEndPolls       = 3;     // 300 ms of "not carried" before believing it

    SRWLOCK             g_armLock = SRWLOCK_INIT;
    std::atomic<bool>   g_armed{false};
    // Written under g_armLock in Arm and Disarm, read without it in CheckCarry
    // (the mod thread) and, for g_playerCatch, in the catch_update hook on
    // game threads, so each is atomic: a plain field read there would be a
    // data race even though an aligned word never tears on x64.
    std::atomic<ULONGLONG> g_armedAt{0};
    std::atomic<uintptr_t> g_playerCatch{0};
    std::atomic<uintptr_t> g_keptCatch{0};
    std::atomic<int>       g_endStrikes{0};
    long                   g_arms = 0;

    // Whose carry it is. An actor's own handle is the dword at +0x60, just
    // before its component table at +0x68: Bounty Probe's object dumps of 20
    // September 2026 have 0xA0100001 there on the player's actor 1,782 times
    // and each NPC's own 0xB01xxxxx on theirs. 0xA0100001 is the
    // player-tagged actor, the id Master Looter and Private Storage Master
    // key on too. A component's actor is at its +8, which is how the game's
    // own getter at +0x20ABA70 reaches it from a catch component.
    //
    // 1.0.5 and 1.0.6 never asked. gamniac's crash dump of 30 September 2026
    // is a stack overflow on the game's main thread, 347,922 frames of
    // +0x141A900, a function that numbers a graph by depth and never ends if
    // the graph has a loop, with no frame of this plugin on the stack. Five
    // players reported crashes on 1.0.6, four of them in quest cutscenes, and
    // every one who tried turning the mod off says the crash went with it. In
    // a cutscene an NPC lets go of someone through the same three releases,
    // and 1.0.6 took that as the start of a teleport: it skipped the release,
    // wrote all four for every catch in the game, and let the sweep keep any
    // carried actor. A catch the scene meant to end stayed on. That is the
    // likeliest way into the loop, though the dump cannot say which catch.
    //
    // The four byte patches had the same reach. Written, they skip a release
    // for every catch in the game, NPCs' included, for as long as the carry
    // lasts. Each patch jumps from its guard to the instruction after the
    // catch_update call, and every block it jumps over only loads that call's
    // arguments, so returning from the catch_update hook without calling
    // through does the same thing for one catch and leaves every other catch
    // alone. With the hook in, an armed carry skips a release only for the
    // player's catch and for a catch whose carrier is the player. The patches
    // are written only if the hook could not go in. The client keeps its own
    // catch components, apart from the server's the handler arms on, and a
    // client catch holding the same outlaw counts as the player's even if its
    // actor's +0x60 should read differently from the server's.
    //
    // Playing as Damiane or Oongka changes the answer. Master Looter's notes
    // (docs/investigations/DAMIANE.md there) split the player into the
    // 0xA0100001 identity and the body on screen. As Kliff they are one actor.
    // As Damiane or Oongka the body is a separate 0xB0 actor, 0xB0100002 in
    // Master Looter's LuxDragon log, and the catch belongs to the body: the
    // outlaw in both of kuodo20's 1.0.3 logs of 24 September 2026 is "carried
    // by handle 0xB0100002", where every Kliff log says 0xA0100001. 1.0.7
    // compared the owner with 0xA0100001 alone, so for those players the early
    // arm stopped firing, and a trimmed teleport left the bounty behind again.
    //
    // The map teleport handler is given the actor being moved, and the catch
    // it arms on is that actor's, so it is the played body whichever character
    // that is. Its handle is learned there on every teleport, carrying or not,
    // and replaces the last one. A
    // release counts as the player's if its owner is 0xA0100001 or that
    // handle. An NPC in a cutscene is neither, so the 1.0.6 crash is not
    // reopened. The first teleport of a session as Damiane or Oongka, if it
    // is a trimmed one that carries, has nothing learned yet.
    constexpr uint32_t  kPlayerHandle = 0xA0100001;
    constexpr ULONGLONG kEarlyMs      = 500;
    std::atomic<uint32_t> g_bodyHandle{0};      // the played body when it is not kPlayerHandle, else 0
    std::atomic<uintptr_t> g_bodyActor{0};      // the actor object the teleport moved under that handle

    // The handle alone is not enough: after a reload, or once Kliff is played
    // again, another actor can carry the same handle or Damiane's body can stand
    // in a scene as an NPC. So the release must also come from the very actor
    // object the last map teleport moved.
    bool IsPlayed(uint32_t owner, uintptr_t actor)
    {
        if (owner == kPlayerHandle) return true;
        return owner && owner == g_bodyHandle.load() && actor && actor == g_bodyActor.load();
    }

    void ForgetBody(const char* why);
    std::atomic<uint32_t> g_carrier{0};         // the handle a kept actor's carrier must be
    std::atomic<uint32_t> g_held{0};            // the handle of whoever the player is carrying
    std::atomic<bool>     g_earlyPending{false};
    std::atomic<bool>     g_hookSkips{false};   // catch_update is hooked, so no patch is written
    std::atomic<bool>     g_patched{false};     // this carry wrote the four patches instead
    std::atomic<bool>     g_earlyOk{false};     // the catch tick is hooked, so an early arm can be undone

    uint32_t OwnerHandle(uintptr_t comp)
    {
        uintptr_t actor = 0;
        uint32_t handle = 0;
        if (!bp::mem::ReadPtr(comp + 8, &actor) || !bp::mem::Read32(actor + 0x60, &handle)) return 0;
        return handle;
    }

    // The class of the actor a catch component belongs to, for the log only.
    const char* OwnerClass(uintptr_t comp)
    {
        uintptr_t actor = 0;
        if (!bp::mem::ReadPtr(comp + 8, &actor)) return "?";
        const char* cls = bp::mem::RttiShort(actor);
        return cls ? cls : "?";
    }

    // ---- which release let go ---------------------------------------------
    //
    // Two players on 24 September 2026 found that the KLIFF TELEPORT patch of
    // Even Faster Vanilla Animations Trimmer leaves the bounty behind, untied,
    // and no log could say why: a teleport that starts with nothing held
    // wrote nothing, and a disarm said only that the carry had ended. So every
    // catch_update on a catch that is live when it is called is remembered
    // with where it was called from, and the recent ones go into the log at
    // two moments. A map teleport that starts with nothing held lists the last
    // fifteen seconds, which names whatever let go before the teleport
    // handler ran. A disarm lists everything since the teleport armed, which
    // names a release that ran while the four were written. The hook only
    // reads; nothing in the game is changed by it.
    //
    // catch_update takes the component in rcx, an out pointer in rdx, a force
    // byte in r8b, a float in xmm3 and the reason as a byte on the stack: 9
    // from the teleport releases, 1 from the watchdog, 0xC from the one in
    // +0x20C0610. The fourth parameter is declared float so xmm3 reaches the
    // original intact, and three more stack slots are passed through as the
    // teleport detour does.
    struct Seen
    {
        ULONGLONG first, last;
        uintptr_t comp;
        uintptr_t from;       // return address, as an rva
        uint32_t  held, carrier;
        uint32_t  owner;      // the handle of the actor the component belongs to
        uint8_t   reason;
        bool      skipped;
        uint32_t  repeats;
    };
    constexpr int       kSeen       = 32;
    constexpr ULONGLONG kLookBackMs = 15000;
    Seen    g_seen[kSeen] = {};
    int     g_seenNext = 0;
    SRWLOCK g_seenLock = SRWLOCK_INIT;

    using CatchUpdateFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, float, uint64_t, uint64_t, uint64_t, uint64_t);
    CatchUpdateFn g_catchUpdateOrig = nullptr;

    void Remember(uintptr_t comp, uintptr_t from, uint32_t held, uint32_t carrier, uint32_t owner, uint8_t reason,
                  bool skipped)
    {
        const ULONGLONG now = GetTickCount64();
        AcquireSRWLockExclusive(&g_seenLock);
        Seen& prev = g_seen[(g_seenNext + kSeen - 1) % kSeen];
        if (prev.first && prev.comp == comp && prev.from == from && prev.held == held && prev.carrier == carrier &&
            prev.skipped == skipped)
        {
            prev.last = now;
            ++prev.repeats;
        }
        else
        {
            g_seen[g_seenNext] = { now, now, comp, from, held, carrier, owner, reason, skipped, 0 };
            g_seenNext = (g_seenNext + 1) % kSeen;
        }
        ReleaseSRWLockExclusive(&g_seenLock);
    }

    bool Arm(uintptr_t playerCatch, uint32_t held, uint32_t owner, const char* early);

    // ---- putting back what an early arm skipped ---------------------------
    //
    // An early arm is a guess that a teleport is on its way, and a quest
    // cutscene makes the same guess come out wrong. wanjia1234566 reported on
    // 10 October 2026 that on 1.0.7 a sheep carried to the child who lost it,
    // and the man carried out of the burning house, stay stuck to Kliff once
    // the scene starts. The scene ends the player's catch through the same
    // client releases a shortened teleport does, 1.0.7 armed and skipped
    // them, and when no teleport came it disarmed without ever ending the
    // catch the scene had asked to end.
    //
    // So every call skipped while an early arm waits for its teleport is kept
    // here, and if the arm runs out it is made again, on the catch it was
    // meant for. catch_update reads a thread-local flag to pick between the
    // server's actors and the client's, so it cannot be called from the mod
    // thread; the replay waits for that catch component's own tick at
    // catchTick (slot 0x140 of the client's catch vtable, and the first call
    // in the server's), which runs on the right thread several times a
    // second and is the function the watchdog release sits in. The call takes
    // nothing from its caller but the component, the force byte, the float
    // and the reason; its out pointer only ever receives a dword.
    struct Skipped
    {
        uintptr_t comp;
        uint32_t  held, carrier;   // what it held when skipped; a replay needs the same
        uint64_t  force, reason;
        float     f;
        const char* label;
    };
    constexpr int       kSkipped  = 8;
    constexpr ULONGLONG kReplayMs = 5000;  // a catch whose tick never comes in that time is left alone
    Skipped               g_skipped[kSkipped] = {};
    int                   g_skippedCount = 0;
    SRWLOCK               g_skippedLock = SRWLOCK_INIT;
    std::atomic<bool>     g_replayDue{false};
    std::atomic<ULONGLONG> g_replayUntil{0};

    void KeepSkipped(uintptr_t comp, uint32_t held, uint32_t carrier, uint64_t force, float f, uint64_t reason,
                     const char* label)
    {
        AcquireSRWLockExclusive(&g_skippedLock);
        bool dup = false;
        for (int k = 0; k < g_skippedCount; ++k)
            if (g_skipped[k].comp == comp) { dup = true; break; }
        if (!dup && g_skippedCount < kSkipped)
            g_skipped[g_skippedCount++] = { comp, held, carrier, force, reason, f, label };
        ReleaseSRWLockExclusive(&g_skippedLock);
    }

    // A teleport did follow, so the skips were the ones it needed, or a new
    // early arm is starting its own list.
    void ForgetSkipped()
    {
        AcquireSRWLockExclusive(&g_skippedLock);
        g_skippedCount = 0;
        g_replayDue.store(false);
        ReleaseSRWLockExclusive(&g_skippedLock);
    }

    // The early arm ran out. Called from Disarm with g_armLock held, so an
    // early arm on a game thread cannot start its own list in between, and
    // it returns how many are due for Disarm to log after the lock.
    int ReplaySkipped()
    {
        AcquireSRWLockExclusive(&g_skippedLock);
        const int n = g_skippedCount;
        if (n)
        {
            g_replayUntil.store(GetTickCount64() + kReplayMs);
            g_replayDue.store(true);
        }
        ReleaseSRWLockExclusive(&g_skippedLock);
        return n;
    }

    // The mod thread's side: give up on a catch whose tick never came.
    void ExpireSkipped()
    {
        if (!g_replayDue.load() || GetTickCount64() < g_replayUntil.load()) return;
        AcquireSRWLockExclusive(&g_skippedLock);
        if (!g_replayDue.load() || GetTickCount64() < g_replayUntil.load())
        {
            ReleaseSRWLockExclusive(&g_skippedLock);
            return;
        }
        Skipped left[kSkipped];
        const int n = g_skippedCount;
        memcpy(left, g_skipped, sizeof left);
        g_skippedCount = 0;
        g_replayDue.store(false);
        ReleaseSRWLockExclusive(&g_skippedLock);
        for (int k = 0; k < n; ++k)
            LOG_ERR("[release] the catch at 0x%llX holding 0x%08X had no tick within %llu seconds, so the release %s "
                    "skipped was not made again", static_cast<unsigned long long>(left[k].comp), left[k].held,
                    static_cast<unsigned long long>(kReplayMs / 1000), left[k].label);
    }

    // Runs on every catch component's tick, on the game's threads, so the
    // common case is one atomic load.
    void ReplayOn(uintptr_t comp)
    {
        if (!g_replayDue.load(std::memory_order_relaxed)) return;
        Skipped s = {};
        bool found = false;
        AcquireSRWLockExclusive(&g_skippedLock);
        for (int k = 0; k < g_skippedCount; ++k)
            if (g_skipped[k].comp == comp)
            {
                s = g_skipped[k];
                g_skipped[k] = g_skipped[--g_skippedCount];
                found = true;
                break;
            }
        if (!g_skippedCount) g_replayDue.store(false);
        ReleaseSRWLockExclusive(&g_skippedLock);
        if (!found) return;

        // The same address holding someone else is a different catch by
        // now, and a release made on it would drop the wrong actor.
        uint32_t held = 0, carrier = 0;
        bp::mem::Read32(comp + 0x38, &held);
        bp::mem::Read32(comp + 0x28, &carrier);
        if (held != s.held || carrier != s.carrier)
        {
            LOG("[release] not made again: the catch at 0x%llX holds 0x%08X carried by 0x%08X now, not 0x%08X "
                "carried by 0x%08X as when %s was skipped", static_cast<unsigned long long>(comp), held, carrier,
                s.held, s.carrier, s.label);
            return;
        }
        uint64_t out = 0;
        g_catchUpdateOrig(comp, reinterpret_cast<uint64_t>(&out), s.force, s.f, s.reason, 0, 0, 0);
        LOG("[release] made %s again on the catch at 0x%llX holding 0x%08X carried by 0x%08X, which no teleport "
            "needed kept", s.label, static_cast<unsigned long long>(comp), s.held, s.carrier);
    }

    // The first three releases are the teleport's own, reason 9, and in the
    // ordinary teleport each runs after the teleport handler, when the four
    // are already written and its patched jump skips the call. A shortened
    // teleport can run one of them first. The KLIFF TELEPORT patch of Even
    // Faster Vanilla Animations Trimmer cuts the start of Kliff's teleport
    // sequence to one time piece, and zx3691's log on 26 September 2026 has
    // the client state transition letting go of the client's catch 62 ms
    // before the handler, the watchdog letting go of the server's 15 ms after
    // that, and the handler finding nothing held. thatswedishdad's log on 27
    // September has the client's character control doing the same 78 ms
    // before it. So a call from either client release on a catch that is
    // holding someone arms the four right there and is skipped, which is what
    // the written jump would have done. The code after each call overwrites
    // or clears the register and never reads what catch_update returns. The
    // server's character control is left out: the teleport handler is what
    // calls it, after arming, so it cannot come first in a teleport, and
    // before one it is the game ending a carry for some other reason. 1.0.6
    // and 1.0.7 armed on it too. The watchdog is left out because it runs on
    // every catch several times a second, and an unarmed call from it is the
    // game ending a carry as usual.
    //
    // Only the player's own catch counts. The releases also end an NPC's
    // catch in a cutscene, and 1.0.6 armed on those too (see kPlayerHandle).
    // A call on any other actor's catch goes through to the game and is
    // written to the log. If no teleport handler follows an early arm within
    // half a second, the carry check disarms, and every call skipped in
    // between is made again (see Skipped).
    uint64_t CatchUpdateDetour(uint64_t comp, uint64_t out, uint64_t force, float f,
                               uint64_t reason, uint64_t g, uint64_t h, uint64_t i)
    {
        const uintptr_t c = static_cast<uintptr_t>(comp);
        uint32_t held = 0, carrier = 0;
        bp::mem::Read32(c + 0x38, &held);
        bp::mem::Read32(c + 0x28, &carrier);
        if (held || carrier)
        {
            const uintptr_t from = bp::mem::Rva(reinterpret_cast<uintptr_t>(_ReturnAddress()));
            const uint32_t owner = OwnerHandle(c);
            uintptr_t ownerActor = 0;
            bp::mem::ReadPtr(c + 8, &ownerActor);
            // The Kliff identity holding someone means Kliff is the body being
            // played, so a body learned while playing Damiane or Oongka is stale.
            if (owner == kPlayerHandle && held && g_bodyHandle.load())
                ForgetBody("0xA0100001 is holding someone, so Kliff is being played again");
            int rel = -1;
            if (g_build)
                for (int r = 0; r < kReleaseCount; ++r)
                    if (from == g_build->releases[r].call + 5) { rel = r; break; }

            if (rel >= 0 && g_armed.load() && !g_patched.load())
            {
                const uint32_t want = g_carrier.load();
                const uint32_t mine = g_held.load();
                const bool ours = c == g_playerCatch.load() || (want && (owner == want || carrier == want)) ||
                                  (mine && held == mine);
                Remember(c, from, held, carrier, owner, static_cast<uint8_t>(reason), ours);
                if (!ours) return g_catchUpdateOrig(comp, out, force, f, reason, g, h, i);
                if (g_earlyPending.load())
                    KeepSkipped(c, held, carrier, force, f, reason, g_build->releases[rel].label);
                return 0;
            }

            bool skip = false;
            if (rel >= 1 && rel < 3 && held && !g_armed.load() && g_earlyOk.load())
            {
                if (!IsPlayed(owner, ownerActor))
                    LOG("[release] %s let go of 0x%08X for 0x%08X (a %s), which is neither 0x%08X nor the body the "
                        "last map teleport moved (0x%08X), so the game ends that catch as it always has",
                        g_build->releases[rel].label, held, owner, OwnerClass(c), kPlayerHandle,
                        g_bodyHandle.load());
                else
                    skip = Arm(c, held, owner, g_build->releases[rel].label);
            }
            Remember(c, from, held, carrier, owner, static_cast<uint8_t>(reason), skip);
            if (skip)
            {
                KeepSkipped(c, held, carrier, force, f, reason, g_build->releases[rel].label);
                return 0;
            }
        }
        return g_catchUpdateOrig(comp, out, force, f, reason, g, h, i);
    }

    const char* ReleaseName(uintptr_t from)
    {
        if (!g_build) return nullptr;
        for (const Release& r : g_build->releases)
            if (r.call + 5 == from) return r.label;
        for (const OtherRelease& o : g_build->others)
            if (o.call && o.call + 5 == from) return o.label;
        return nullptr;
    }

    // Copies the ring under the lock and logs outside it, so a catch_update
    // on a game thread never waits behind the log.
    void ListReleases(ULONGLONG since, const char* span)
    {
        Seen copy[kSeen];
        AcquireSRWLockShared(&g_seenLock);
        memcpy(copy, g_seen, sizeof copy);
        const int next = g_seenNext;
        ReleaseSRWLockShared(&g_seenLock);

        const ULONGLONG now = GetTickCount64();
        int listed = 0;
        for (int k = 0; k < kSeen; ++k)
        {
            const Seen& e = copy[(next + k) % kSeen];
            if (!e.first || e.last < since) continue;
            ++listed;
            const char* cls = bp::mem::RttiShort(e.comp);
            const char* name = ReleaseName(e.from);
            LOG("[release] %llu ms ago: catch_update on %s 0x%llX of 0x%08X, holding 0x%08X, carried by 0x%08X, "
                "reason %u, returning to +0x%llX%s%s%s%s", static_cast<unsigned long long>(now - e.first),
                cls ? cls : "?", static_cast<unsigned long long>(e.comp), e.owner, e.held, e.carrier, e.reason,
                static_cast<unsigned long long>(e.from), name ? " (" : "", name ? name : "", name ? ")" : "",
                e.skipped ? ", skipped by this mod" : "");
            if (e.repeats)
                LOG("[release]   and %u more times from there, the last %llu ms ago", e.repeats,
                    static_cast<unsigned long long>(now - e.last));
        }
        if (!listed) LOG("[release] no catch that was holding or carried anything went through catch_update %s", span);
        else LOG("[release] that is every live catch that went through catch_update %s", span);
    }

    bool HookCatchUpdate()
    {
        const uintptr_t target = bp::mem::Game().base + g_build->catchUpdate;
        char why[160] = "";
        if (!bp::farhook::Install("catch_update", target, reinterpret_cast<void*>(&CatchUpdateDetour),
                                  reinterpret_cast<void**>(&g_catchUpdateOrig), why, sizeof why))
        {
            LOG_ERR("[release] could not hook catch_update at +0x%llX: %s. The carry still works; the log just "
                    "cannot say which release let go", static_cast<unsigned long long>(g_build->catchUpdate), why);
            return false;
        }
        LOG_OK("[release] hooked catch_update at +0x%llX to note which release lets go of a carry",
               static_cast<unsigned long long>(g_build->catchUpdate));
        return true;
    }

    // The catch component's tick takes the component in rcx and a pointer
    // to a byte in rdx, and reads nothing else of its caller's.
    using CatchTickFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t);
    CatchTickFn g_catchTickOrig = nullptr;

    uint64_t CatchTickDetour(uint64_t comp, uint64_t b, uint64_t c, uint64_t d)
    {
        ReplayOn(static_cast<uintptr_t>(comp));
        return g_catchTickOrig(comp, b, c, d);
    }

    // mov [rsp+8],rbx / mov [rsp+0x18],rbp / mov [rsp+0x20],rsi / push rdi /
    // push r14 / push r15 / sub rsp,0x40 / mov rsi,rcx / cmp byte [rdx],0.
    const uint8_t kTickHead[27] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24,
                                    0x20, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xF1 };

    // Without it an early arm that runs out cannot put back what it skipped,
    // so early arming is off too and only the handler arms.
    bool HookCatchTick()
    {
        const uintptr_t target = bp::mem::Game().base + g_build->catchTick;
        uint8_t head[sizeof kTickHead] = {};
        if (!bp::mem::ReadBytes(target, head, sizeof head) || memcmp(head, kTickHead, sizeof head) != 0)
        {
            LOG_ERR("[release] +0x%llX does not start the way the catch tick does, so it is not hooked",
                    static_cast<unsigned long long>(g_build->catchTick));
            return false;
        }
        char why[160] = "";
        if (!bp::farhook::Install("catch_tick", target, reinterpret_cast<void*>(&CatchTickDetour),
                                  reinterpret_cast<void**>(&g_catchTickOrig), why, sizeof why))
        {
            LOG_ERR("[release] could not hook the catch tick at +0x%llX: %s",
                    static_cast<unsigned long long>(g_build->catchTick), why);
            return false;
        }
        LOG_OK("[release] hooked the catch tick at +0x%llX, where a release an early arm skipped is made again if no "
               "teleport follows", static_cast<unsigned long long>(g_build->catchTick));
        return true;
    }

    bool CatchComponent(uintptr_t actor, uintptr_t* out)
    {
        uintptr_t table = 0, catchc = 0;
        if (!bp::mem::ReadPtr(actor + 0x68, &table)) return false;
        if (!bp::mem::ReadPtr(table + 0x70, &catchc)) return false;
        const char* cls = bp::mem::RttiShort(catchc);
        if (!cls || !strstr(cls, "CatchActorComponent")) return false;
        *out = catchc;
        return true;
    }

    bool StillCatch(uintptr_t catchc)
    {
        if (!catchc || !bp::mem::Readable(catchc, 0x40)) return false;
        const char* cls = bp::mem::RttiShort(catchc);
        return cls && strstr(cls, "CatchActorComponent");
    }

    // Writes or removes all four together. Called with the lock held.
    bool SetReleases(bool on)
    {
        bool ok = true;
        for (int i : g_releaseIdx) if (i >= 0) ok = bp::patch::Set(i, on) && ok;
        return ok;
    }

    // `early` names the release that armed ahead of the handler, or is null
    // when the handler itself arms; see CatchUpdateDetour.
    bool                g_lastEarly = false;

    // `owner` is the handle of the actor whose catch it is, and the sweep
    // keeps only an actor that names it as carrier.
    bool Arm(uintptr_t playerCatch, uint32_t held, uint32_t owner, const char* early)
    {
        AcquireSRWLockExclusive(&g_armLock);
        const bool was = g_armed.load();
        const bool wasEarly = g_lastEarly;
        // The hook skips per catch once it knows whose carry it is. Without
        // the hook, or without the carrier's handle, the patches go in for
        // every catch as they did up to 1.0.6.
        const bool patch = !g_hookSkips.load() || !owner;
        const bool ok = patch ? SetReleases(true) : true;
        if (ok && patch) g_patched.store(true);
        // Some of the four may be written when a later one is refused. Nothing
        // would take them out again, since a carry that did not arm never
        // disarms, so they come out here.
        if (!ok && patch) SetReleases(false);
        g_armed.store(ok);
        g_armedAt.store(GetTickCount64());
        g_playerCatch.store(playerCatch);
        g_endStrikes.store(0);
        g_lastEarly = early != nullptr;
        g_earlyPending.store(early != nullptr);
        g_carrier.store(owner);
        g_held.store(held);
        if (!was) g_keptCatch.store(0);
        ++g_arms;
        // An early arm starts its own list, and the handler arming means a
        // teleport came and wanted whatever was skipped.
        ForgetSkipped();
        const long n = g_arms;
        ReleaseSRWLockExclusive(&g_armLock);
        if (early)
        {
            if (ok)
                LOG("[teleport] %ld: %s went to let go of 0x%08X before any teleport handler ran, which a "
                    "shortened teleport sequence does, so the player's carry is kept from here and that release is "
                    "skipped", n, early, held);
            else
                LOG_ERR("[teleport] %ld: %s went to let go of 0x%08X early, but the releases could not all be "
                        "written; the game will release him as it always has", n, early, held);
        }
        else if (ok)
            LOG("[teleport] %ld: a map teleport started with 0x%08X holding 0x%08X, so %s until that carry "
                "ends%s", n, owner, held,
                patch ? "the four releases are written for every catch" : "the four releases skip that carry alone",
                !was ? "" : wasEarly ? " (armed a moment ago, when the client let go early)"
                                     : " (it was already armed from the last one)");
        else
            LOG_ERR("[teleport] %ld: a map teleport started with the player holding 0x%08X, but the releases "
                    "could not all be written; the game will release him as it always has", n, held);
        if (ok && !owner)
            LOG_ERR("[teleport] %ld: the handle of the actor doing the carrying could not be read, so the releases "
                    "are written for every catch and the sweep keeps any carried actor, as 1.0.6 did", n);
        return ok;
    }

    // `replay` is set only when an early arm ran out with no teleport; every
    // other end of a carry forgets the skips, since a teleport wanted them.
    void Disarm(const char* why, bool replay = false)
    {
        AcquireSRWLockExclusive(&g_armLock);
        if (!g_armed.load()) { ReleaseSRWLockExclusive(&g_armLock); return; }
        const bool restored = !g_patched.load() || SetReleases(false);
        g_patched.store(false);
        g_armed.store(false);
        g_keptCatch.store(0);
        g_earlyPending.store(false);
        g_carrier.store(0);
        g_held.store(0);
        g_playerCatch.store(0);
        g_endStrikes.store(0);
        const ULONGLONG armedAt = g_armedAt.load();
        const ULONGLONG held = GetTickCount64() - armedAt;
        int due = 0;
        if (replay) due = ReplaySkipped();
        else ForgetSkipped();
        ReleaseSRWLockExclusive(&g_armLock);
        LOG("[teleport] the releases are back to the game's own after %llu seconds: %s",
            static_cast<unsigned long long>(held / 1000), why);
        if (!restored)
            LOG_ERR("[teleport] the four releases could not all be written back to the game's own bytes, so some "
                    "stay skipped for every catch; restart the game");
        ListReleases(armedAt, "since the teleport armed");
        if (due)
            LOG("[release] %d skipped release%s will be made again at the next tick of %s catch, since no teleport "
                "needed %s", due, due == 1 ? "" : "s", due == 1 ? "its" : "their", due == 1 ? "it" : "them");
    }

    // The mod thread's side, ten times a second while armed.
    void CheckCarry()
    {
        ExpireSkipped();
        if (!g_armed.load()) return;
        if (g_earlyPending.load() && GetTickCount64() - g_armedAt.load() > kEarlyMs)
        {
            Disarm("a release let go of the player's catch early, but no map teleport followed within half a second",
                   true);
            return;
        }
        const uintptr_t kept = g_keptCatch.load();
        if (!kept)
        {
            if (GetTickCount64() - g_armedAt.load() > kNoKeepMs)
                Disarm("the sweep kept nobody, so nothing came through the teleport with the player");
            return;
        }
        uint32_t carriedBy = 0, held = 0;
        const bool outlaw = StillCatch(kept) && bp::mem::Read32(kept + 0x28, &carriedBy) && carriedBy;
        const uintptr_t mine = g_playerCatch.load();
        const bool player = StillCatch(mine) && bp::mem::Read32(mine + 0x38, &held) && held;
        if (outlaw && player) { g_endStrikes.store(0); return; }
        if (++g_endStrikes < kEndPolls) return;
        Disarm(!outlaw ? "the outlaw is no longer carried" : "the player is no longer holding anything");
    }

    // Remembers which actor the map teleport moves, which is the body being
    // played (see kPlayerHandle). The Kliff identity clears it, so a body
    // learned for Damiane is not trusted after the player switches back. The
    // log says so when it changes, with the class, which is what a log from a
    // Damiane or Oongka player is needed for.
    void ForgetBody(const char* why)
    {
        g_bodyActor.store(0);
        const uint32_t was = g_bodyHandle.exchange(0);
        if (was) LOG("[teleport] no longer treating 0x%08X as the played body: %s", was, why);
    }

    void NotePlayed(uintptr_t actor, uint32_t owner)
    {
        if (!owner) return;
        const uint32_t now = owner == kPlayerHandle ? 0 : owner;
        g_bodyActor.store(now ? actor : 0);
        if (g_bodyHandle.exchange(now) == now) return;
        const char* cls = bp::mem::RttiShort(actor);
        if (now)
            LOG("[teleport] the map teleport moved 0x%08X (a %s), not 0xA0100001, so the character being played has "
                "its own body, and a release that lets go of its catch just before a teleport counts as the "
                "player's from here", now, cls ? cls : "?");
        else
            LOG("[teleport] the map teleport moved 0xA0100001 (a %s), so the played body is the player-tagged actor "
                "again", cls ? cls : "?");
    }

    using TeleportFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    TeleportFn g_teleportOrig = nullptr;

    // Takes eight arguments and passes eight on. The handler reads at least
    // six (its fifth and sixth come off the stack, at [rbp+0x130] and
    // [rbp+0x138] up to 1.0.0.2976, and the fifth at [rbp+0xE0] on
    // 1.0.0.3392), and a detour that declared four would hand the original
    // whatever happened to be in its own frame for the rest. The extra two
    // are read from the caller's frame and passed back unchanged.
    uint64_t TeleportDetour(uint64_t a, uint64_t b, uint64_t actor, uint64_t d,
                            uint64_t e, uint64_t f, uint64_t g, uint64_t h)
    {
        uintptr_t catchc = 0;
        uint32_t held = 0;
        const bool found = CatchComponent(static_cast<uintptr_t>(actor), &catchc);
        uint32_t owner = 0;
        if (!bp::mem::Read32(static_cast<uintptr_t>(actor) + 0x60, &owner)) owner = 0;
        NotePlayed(static_cast<uintptr_t>(actor), owner);
        if (found && bp::mem::Read32(catchc + 0x38, &held) && held)
            Arm(catchc, held, owner, nullptr);
        else
        {
            LOG("[teleport] a map teleport started with the player holding nothing%s, so nothing is armed",
                found ? "" : " (no catch component on the actor it was given)");
            ListReleases(GetTickCount64() - kLookBackMs, "in the 15 seconds before it");
        }
        return g_teleportOrig(a, b, actor, d, e, f, g, h);
    }

    // The handler's bytes and both its callers were checked when the build
    // was chosen, so this only installs the hook.
    bool HookTeleport()
    {
        const uintptr_t target = bp::mem::Game().base + g_build->teleport;
        char why[160] = "";
        if (!bp::farhook::Install("teleport", target, reinterpret_cast<void*>(&TeleportDetour),
                                  reinterpret_cast<void**>(&g_teleportOrig), why, sizeof why))
        {
            LOG_ERR("[teleport] could not hook +0x%llX: %s",
                    static_cast<unsigned long long>(g_build->teleport), why);
            return false;
        }
        LOG_OK("[teleport] hooked the map teleport at +0x%llX, which is where the releases get armed",
               static_cast<unsigned long long>(g_build->teleport));
        return true;
    }

    bool KeepGate() { return g_armed.load(); }

    // The sweep runs every five seconds and at every map confirm, over every
    // actor a quest stage spawned. While armed, 1.0.6 kept any of them that
    // anyone was carrying. Now the carrier has to be the actor that armed.
    bool KeepAccept(uintptr_t actor, uint32_t carriedBy)
    {
        const uint32_t want = g_carrier.load();
        if (!want || carriedBy == want) return true;
        const char* cls = bp::mem::RttiShort(actor);
        LOG("[keepcarried] not kept: %s@0x%llX is carried by 0x%08X, not by 0x%08X whose carry this is, so the game "
            "answers for it", cls ? cls : "?", static_cast<unsigned long long>(actor), carriedBy, want);
        return false;
    }

    void OnKeep(uintptr_t actor, uintptr_t catchc)
    {
        g_keptCatch.store(catchc);
        LOG("[teleport] the sweep was told to keep 0x%llX, which stays armed while he is carried",
            static_cast<unsigned long long>(actor));
    }

    // ---- the departure sweep ----------------------------------------------
    //
    // Leaving a field tears down every actor the player's session spawned in
    // it, and a caught outlaw is one of those. The sweep spares an actor
    // somebody else still holds, and up to 1.0.0.3424 the question is asked
    // through a thunk.
    // KeepCarried answers yes for an actor whose catch component names a
    // carrier. The addresses were checked when the build was chosen.
    void InstallKeepCarried()
    {
        const uintptr_t target = bp::mem::Game().base + g_build->holderCheck;
        if (!bp::keepcarried::Hook(target))
            LOG_ERR("[keepcarried] the holder check at +0x%llX could not be hooked. If Bounty Probe is in this "
                    "folder too, that is why: it hooks the same function, and only one of the two plugins should "
                    "be loaded.", static_cast<unsigned long long>(g_build->holderCheck));
    }

    // ---- settings ----------------------------------------------------------

    // Writes the documented ini beside the plugin when there is none. The
    // bytes are BountyTeleportation.ini's own, embedded at build time, so the file
    // that ships in the archive and the file a first run writes are the same
    // text.
    void WriteDefaultIni()
    {
        const std::wstring path = bp::Paths::File(BT_INI);
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return;
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
        DWORD written = 0;
        WriteFile(h, kDefaultIni, kDefaultIniSize, &written, nullptr);
        CloseHandle(h);
    }

    Settings ReadSettings()
    {
        const std::wstring path = bp::Paths::File(BT_INI);
        Settings s;
        s.keepCatch = GetPrivateProfileIntW(L"settings", L"KeepCatch", 1, path.c_str()) != 0;
        s.keepCarried = GetPrivateProfileIntW(L"settings", L"KeepCarried", 1, path.c_str()) != 0;
        return s;
    }

    DWORD WINAPI Worker(LPVOID)
    {
        WriteDefaultIni();
        const Settings s = ReadSettings();

        LOG("[mod] %s %s. Settings: KeepCatch=%d KeepCarried=%d", BT_NAME, BT_VERSION,
            s.keepCatch ? 1 : 0, s.keepCarried ? 1 : 0);
        LOG("[mod] game image at 0x%p, %zu bytes.",
            reinterpret_cast<void*>(bp::mem::Game().base), bp::mem::Game().size);

        // Which game this is. Nothing is written or hooked if it is none of
        // the builds the addresses were read off.
        g_build = SelectBuild();
        if (!g_build)
        {
            while (!g_stop.load()) { Sleep(250); bp::Log::Flush(); }
            return 0;
        }

        // Nothing is armed unless KeepCatch is on, the four releases register
        // and the teleport hook goes in. Without the hook there is no way to
        // know a teleport has started, and writing the releases for the whole
        // session is what 1.0.0 did and what broke petting.
        bool armable = false;
        if (s.keepCatch)
        {
            armable = RegisterKeepCatch() && HookTeleport();
            // Skips the releases for the player's carry alone. Without it
            // the carry still works, with the releases written for every
            // catch as up to 1.0.6.
            if (armable)
            {
                g_hookSkips.store(HookCatchUpdate());
                if (g_hookSkips.load()) g_earlyOk.store(HookCatchTick());
                if (!g_earlyOk.load())
                    LOG_ERR("[keepcatch] a release that lets go just before the teleport handler runs is not caught, "
                            "so a shortened teleport sequence leaves the bounty behind");
                if (g_hookSkips.load())
                    LOG_OK("[keepcatch] an armed carry skips the four releases only for the player's catch and for "
                           "whoever the player carries. Every other catch in the game is let go as usual.");
                else
                    LOG_ERR("[keepcatch] without the catch_update hook, an armed carry writes the four releases for "
                            "every catch in the game, as 1.0.6 did");
            }
        }
        else LOG("[keepcatch] KeepCatch is 0, so a teleport releases the catch as it always has");

        if (s.keepCarried)
        {
            if (!armable)
                LOG("[keepcarried] KeepCarried does nothing without KeepCatch armed: the release runs before the "
                    "sweep and clears the flag this reads");
            // The sweep hook answers only while a teleport carry is armed, and
            // tells the carry check which outlaw it kept.
            bp::keepcarried::SetGate(&KeepGate);
            bp::keepcarried::SetOnKeep(&OnKeep);
            bp::keepcarried::SetAccept(&KeepAccept);
            InstallKeepCarried();
        }
        else LOG("[keepcarried] KeepCarried is 0, so the departure sweep removes the carried actor as it always has");

        // Ten times a second: end an armed carry when it is over, and put the
        // log lines on the disk. A flush from inside a hook would make the
        // game wait on the disk on its own thread.
        while (!g_stop.load())
        {
            Sleep(100);
            CheckCarry();
            bp::Log::Flush();
        }
        return 0;
    }
}

namespace bp::Mod
{
    // crashpad_handler.exe loads .asi plugins too. That process gets its own
    // one-line log and touches nothing.
    constexpr size_t kMinGameImage = 64ull * 1024 * 1024;

    void Initialize(HMODULE module)
    {
        bp::Paths::Init(module);
        const size_t size = bp::mem::Game().size;
        if (!bp::mem::Game().base || size < kMinGameImage)
        {
            wchar_t name[96];
            _snwprintf_s(name, _countof(name), _TRUNCATE, L"%s.other", BT_FILEBASE);
            bp::Log::ClaimSingle(name);
            LOG("[mod] this process has a %zu byte image, which is not the game, so nothing is hooked here", size);
            bp::Log::Shutdown();
            return;
        }
        bp::Log::Claim(BT_FILEBASE);
        g_thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    }

    void Shutdown(bool processExiting)
    {
        g_stop.store(true);
        if (processExiting)
        {
            bp::Log::Shutdown();
            return;
        }
        if (g_thread)
        {
            WaitForSingleObject(g_thread, 3000);
            CloseHandle(g_thread);
            g_thread = nullptr;
        }
        // Unloading by hand is a modder's thing to do, and leaving a hooked
        // game behind after it is not.
        bp::farhook::RemoveAll();
        bp::patch::RestoreAll();
        bp::Log::Shutdown();
    }
}
