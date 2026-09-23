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
    // 0x18280. Every build is listed, and the one whose addresses all check
    // out is the one used. research\derive_2949.py is how the later sets were
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
        uintptr_t   slotTarget;  // what slot 0x200 of it must hold
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

    struct Build
    {
        const char* name;          // the exe version it was read off
        uintptr_t   catchUpdate;   // where every release below must call
        Release     releases[kReleaseCount];
        uintptr_t   holderCheck;   // the departure sweep's "does anyone hold it"
        uintptr_t   holderThunk;   // the jmp that reaches it
        uintptr_t   sweepCall;     // the sweep's call to that thunk
        uintptr_t   teleport;      // the map teleport handler
        uintptr_t   teleportCall1; // its two callers, both in the message handler
        uintptr_t   teleportCall2;
    };

    // The releases, in order: slot 0x200 of the server and common
    // CharacterControl components, called by the teleport handler once the
    // player has been moved; the client's own copy of that function, reached
    // through a thunk, whose absence is what made the outlaw arrive lying on
    // the ground when only the server's was patched; a client state
    // transition that is in no vtable and fires a second after the confirm;
    // and the watchdog on the catch component itself, which runs about six
    // times a second on every catch in the world and drops one the carry
    // animation no longer backs. The watchdog's patch goes over the first
    // test rather than the `je` below it: with something actually held, the
    // `jne` in between jumps past that `je` and never reads it.
    const Build kBuilds[] = {
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
    bool ReleaseChecks(const Release& r, uintptr_t catchUpdate, bool loud)
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
            if (!bp::mem::Read64(base + r.vtable + 0x200, &slot) || slot != base + r.slotTarget)
            {
                if (loud)
                    LOG_ERR("[%s] slot 0x200 of the vtable at +0x%llX is 0x%llX and not +0x%llX; nothing written",
                            r.label, static_cast<unsigned long long>(r.vtable),
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
    // mov rax,rsp / mov [rax+10],rbx / mov [rax+18],rsi / mov [rax+20],rdi,
    // the teleport handler's.
    const uint8_t kTeleportHead[15] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48,
                                        0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20 };

    bool BuildChecks(const Build& bld, bool loud)
    {
        const uintptr_t base = bp::mem::Game().base;
        for (const Release& r : bld.releases)
            if (!ReleaseChecks(r, bld.catchUpdate, loud)) return false;

        uint8_t head[15] = {};
        if (!bp::mem::ReadBytes(base + bld.holderCheck, head, 9) || memcmp(head, kHolderHead, 9) != 0)
        {
            if (loud)
                LOG_ERR("[keepcarried] +0x%llX does not start the way the holder check does",
                        static_cast<unsigned long long>(bld.holderCheck));
            return false;
        }
        if (BranchTarget(bld.holderThunk, 0xE9) != bld.holderCheck ||
            BranchTarget(bld.sweepCall, 0xE8) != bld.holderThunk)
        {
            if (loud) LOG_ERR("[keepcarried] the sweep no longer reaches the holder check through its thunk");
            return false;
        }
        if (!bp::mem::ReadBytes(base + bld.teleport, head, 15) || memcmp(head, kTeleportHead, 15) != 0)
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
    ULONGLONG           g_armedAt = 0;
    uintptr_t           g_playerCatch = 0;
    std::atomic<uintptr_t> g_keptCatch{0};
    int                 g_endStrikes = 0;
    long                g_arms = 0;

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

    void Arm(uintptr_t playerCatch, uint32_t held)
    {
        AcquireSRWLockExclusive(&g_armLock);
        const bool was = g_armed.load();
        const bool ok = SetReleases(true);
        g_armed.store(ok);
        g_armedAt = GetTickCount64();
        g_playerCatch = playerCatch;
        g_endStrikes = 0;
        if (!was) g_keptCatch.store(0);
        ++g_arms;
        const long n = g_arms;
        ReleaseSRWLockExclusive(&g_armLock);
        if (ok)
            LOG("[teleport] %ld: a map teleport started with the player holding 0x%08X, so the four releases are "
                "written until that carry ends%s", n, held, was ? " (it was already armed from the last one)" : "");
        else
            LOG_ERR("[teleport] %ld: a map teleport started with the player holding 0x%08X, but the releases "
                    "could not all be written; the game will release him as it always has", n, held);
    }

    void Disarm(const char* why)
    {
        AcquireSRWLockExclusive(&g_armLock);
        if (!g_armed.load()) { ReleaseSRWLockExclusive(&g_armLock); return; }
        SetReleases(false);
        g_armed.store(false);
        g_keptCatch.store(0);
        g_playerCatch = 0;
        g_endStrikes = 0;
        const ULONGLONG held = GetTickCount64() - g_armedAt;
        ReleaseSRWLockExclusive(&g_armLock);
        LOG("[teleport] the releases are back to the game's own after %llu seconds: %s",
            static_cast<unsigned long long>(held / 1000), why);
    }

    // The mod thread's side, ten times a second while armed.
    void CheckCarry()
    {
        if (!g_armed.load()) return;
        const uintptr_t kept = g_keptCatch.load();
        if (!kept)
        {
            if (GetTickCount64() - g_armedAt > kNoKeepMs)
                Disarm("the sweep kept nobody, so nothing came through the teleport with the player");
            return;
        }
        uint32_t carriedBy = 0, held = 0;
        const bool outlaw = StillCatch(kept) && bp::mem::Read32(kept + 0x28, &carriedBy) && carriedBy;
        const bool player = StillCatch(g_playerCatch) && bp::mem::Read32(g_playerCatch + 0x38, &held) && held;
        if (outlaw && player) { g_endStrikes = 0; return; }
        if (++g_endStrikes < kEndPolls) return;
        Disarm(!outlaw ? "the outlaw is no longer carried" : "the player is no longer holding anything");
    }

    using TeleportFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    TeleportFn g_teleportOrig = nullptr;

    // Takes eight arguments and passes eight on. The handler reads at least
    // six (its fifth and sixth come off the stack at [rbp+0x130] and
    // [rbp+0x138]), and a detour that declared four would hand the original
    // whatever happened to be in its own frame for the rest. The extra two
    // are read from the caller's frame and passed back unchanged.
    uint64_t TeleportDetour(uint64_t a, uint64_t b, uint64_t actor, uint64_t d,
                            uint64_t e, uint64_t f, uint64_t g, uint64_t h)
    {
        uintptr_t catchc = 0;
        uint32_t held = 0;
        if (CatchComponent(static_cast<uintptr_t>(actor), &catchc) && bp::mem::Read32(catchc + 0x38, &held) && held)
            Arm(catchc, held);
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
    // somebody else still holds, and the question is asked through a thunk.
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
        if (s.keepCatch) armable = RegisterKeepCatch() && HookTeleport();
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
