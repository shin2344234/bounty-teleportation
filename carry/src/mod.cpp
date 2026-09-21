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
    // the held actor's at +0x38, and catch_update at +0x20AD3A0 is what ends
    // it. Three callers end it as part of a teleport and one ends it on a
    // timer; each sits behind a short jump that already skips it in the
    // ordinary case, so each patch is two bytes that make that jump
    // unconditional.
    constexpr uintptr_t kCatchUpdate = 0x20AD3A0;

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

    const Release kReleases[] = {
        // Slot 0x200 of the server and common CharacterControl components,
        // called by the teleport handler once the player has been moved.
        { "keepcatch", 0x2329124, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2329143, 0x2329104,
          kTeleportGuard, 16, 0x5B25260, 0x23290D0, 0 },
        // The client's own copy of that function, reached through a thunk.
        // Patching only the server's is what made the outlaw arrive lying on
        // the ground: the server went on carrying him and the client had let
        // go.
        { "keepcatch_client", 0x99B6D0F, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x99B6D2E, 0x99B6CEF,
          kTeleportGuard, 16, 0x55B53C8, 0x860F90, 0x99B6CB0 },
        // A client state transition, in no vtable, reached from +0x9F19F7 and
        // +0x1F58C26. It fired once per teleport, a second after the confirm.
        { "keepcatch_state", 0x156F24D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x156F26A, 0x156F22B,
          kTeleportGuard, 16, 0, 0, 0 },
        // +0x20AE540, on the catch component itself, about six times a second
        // on every catch in the world. It drops one the carry animation no
        // longer backs, and a teleport resets those flags, so it cleared both
        // sides a second after every arrival. The patch goes over the first
        // test and not the `je` below it: with something actually held, the
        // `jne` in between jumps past that `je` and never reads it.
        { "keepcatch_watchdog", 0x20AE5C8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x20AE609, 0x20AE5C8,
          kWatchdogGuard, 8, 0, 0, 0 },
    };

    uintptr_t BranchTarget(uintptr_t at, uint8_t op)
    {
        uint8_t b[5] = {};
        if (!bp::mem::ReadBytes(bp::mem::Game().base + at, b, 5) || b[0] != op) return 0;
        int32_t rel = 0;
        memcpy(&rel, b + 1, 4);
        return at + 5 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
    }

    constexpr int kReleaseCount = static_cast<int>(sizeof kReleases / sizeof kReleases[0]);
    int g_releaseIdx[kReleaseCount] = { -1, -1, -1, -1 };

    // Checks one release against the executable and registers its patch
    // without writing it. Returns the patch index, or -1.
    int RegisterRelease(const Release& r)
    {
        const uintptr_t base = bp::mem::Game().base;
        const uintptr_t target = BranchTarget(r.call, 0xE8);
        if (target != kCatchUpdate)
        {
            LOG_ERR("[%s] the call at +0x%llX goes to +0x%llX and not to catch_update at +0x%llX, so this is not "
                    "the release; nothing written", r.label, static_cast<unsigned long long>(r.call),
                    static_cast<unsigned long long>(target), static_cast<unsigned long long>(kCatchUpdate));
            return -1;
        }
        uint8_t guard[16] = {};
        if (!bp::mem::ReadBytes(base + r.guard, guard, r.shapeLen) || memcmp(guard, r.shape, r.shapeLen) != 0)
        {
            LOG_ERR("[%s] the test at +0x%llX is not the catch check this build should have; nothing written",
                    r.label, static_cast<unsigned long long>(r.guard));
            return -1;
        }
        if (r.vtable)
        {
            uint64_t slot = 0;
            if (!bp::mem::Read64(base + r.vtable + 0x200, &slot) || slot != base + r.slotTarget)
            {
                LOG_ERR("[%s] slot 0x200 of the vtable at +0x%llX is 0x%llX and not +0x%llX; nothing written",
                        r.label, static_cast<unsigned long long>(r.vtable), static_cast<unsigned long long>(slot),
                        static_cast<unsigned long long>(r.slotTarget));
                return -1;
            }
            if (r.thunkTo && BranchTarget(r.slotTarget, 0xE9) != r.thunkTo)
            {
                LOG_ERR("[%s] the thunk at +0x%llX does not jump to +0x%llX; nothing written", r.label,
                        static_cast<unsigned long long>(r.slotTarget),
                        static_cast<unsigned long long>(r.thunkTo));
                return -1;
            }
        }
        return bp::patch::Register(r.label, r.at, r.orig, r.repl, 2);
    }

    bool RegisterKeepCatch()
    {
        int done = 0;
        for (int i = 0; i < kReleaseCount; ++i)
        {
            g_releaseIdx[i] = RegisterRelease(kReleases[i]);
            if (g_releaseIdx[i] >= 0) ++done;
        }
        if (done == kReleaseCount)
        {
            LOG_OK("[keepcatch] all %d releases check out and are ready. None is written until a map teleport "
                   "starts with something held, and each comes out again when that carry ends.", kReleaseCount);
            return true;
        }
        LOG_ERR("[keepcatch] only %d of %d releases check out, so none will be used: skipping some and not "
                "others leaves the two sides disagreeing about what is carried.", done, kReleaseCount);
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
    // So they are armed. A map teleport runs +0x2BC9640 once per confirm,
    // reached only from the teleport's message handler (+0x2BCA55D and
    // +0x2BCAB00), and it moves the player and then calls the first release
    // at +0x2BC9928. If the player is holding something when it starts, the
    // four releases are written there, before any of them can run. They stay
    // written while that carry lasts and come out when it ends: the sweep
    // kept nobody within five seconds, or the outlaw it kept is no longer
    // carried, or the player is no longer holding anything.
    constexpr uintptr_t kTeleport       = 0x2BC9640;
    constexpr uintptr_t kTeleportCall1  = 0x2BCA55D;
    constexpr uintptr_t kTeleportCall2  = 0x2BCAB00;
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

    bool HookTeleport()
    {
        const uintptr_t base = bp::mem::Game().base;
        // mov rax,rsp / mov [rax+10],rbx / mov [rax+18],rsi / mov [rax+20],rdi
        static const uint8_t kHead[15] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48,
                                           0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20 };
        uint8_t head[15] = {};
        if (!bp::mem::ReadBytes(base + kTeleport, head, 15) || memcmp(head, kHead, 15) != 0)
        {
            LOG_ERR("[teleport] +0x%llX does not start the way the teleport handler does on this build, so nothing "
                    "is hooked and the releases are never written", static_cast<unsigned long long>(kTeleport));
            return false;
        }
        if (BranchTarget(kTeleportCall1, 0xE8) != kTeleport || BranchTarget(kTeleportCall2, 0xE8) != kTeleport)
        {
            LOG_ERR("[teleport] the teleport's message handler no longer calls +0x%llX from where it did; nothing "
                    "is hooked", static_cast<unsigned long long>(kTeleport));
            return false;
        }
        char why[160] = "";
        if (!bp::farhook::Install("teleport", base + kTeleport, reinterpret_cast<void*>(&TeleportDetour),
                                  reinterpret_cast<void**>(&g_teleportOrig), why, sizeof why))
        {
            LOG_ERR("[teleport] could not hook +0x%llX: %s", static_cast<unsigned long long>(kTeleport), why);
            return false;
        }
        LOG_OK("[teleport] hooked the map teleport at +0x%llX, which is where the releases get armed",
               static_cast<unsigned long long>(kTeleport));
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
    // somebody else still holds, and the question is asked through a thunk at
    // +0x1F53D10 into +0xE1478D0. KeepCarried answers yes for an actor whose
    // catch component names a carrier.
    constexpr uintptr_t kHolderCheck = 0xE1478D0;
    constexpr uintptr_t kHolderThunk = 0x1F53D10;
    constexpr uintptr_t kSweepCall   = 0x2818160;

    void InstallKeepCarried()
    {
        const uintptr_t base = bp::mem::Game().base;
        // mov [rsp+8],rbx / mov eax,[rcx+0x1c]
        static const uint8_t kHead[9] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x44, 0x8B, 0x41, 0x1C };
        uint8_t head[9] = {};
        if (!bp::mem::ReadBytes(base + kHolderCheck, head, 9) || memcmp(head, kHead, 9) != 0)
        {
            LOG_ERR("[keepcarried] +0x%llX does not start the way the holder check does on this build, so it is "
                    "not hooked and the sweep will take the carried actor as it always has. If Bounty Probe is "
                    "in this folder too, that is why: it hooks the same function, and only one of the two "
                    "plugins should be loaded.", static_cast<unsigned long long>(kHolderCheck));
            return;
        }
        if (BranchTarget(kHolderThunk, 0xE9) != kHolderCheck)
        {
            LOG_ERR("[keepcarried] the thunk at +0x%llX does not jump to the holder check; nothing is hooked",
                    static_cast<unsigned long long>(kHolderThunk));
            return;
        }
        if (BranchTarget(kSweepCall, 0xE8) != kHolderThunk)
        {
            LOG_ERR("[keepcarried] the sweep's call at +0x%llX does not reach the thunk; nothing is hooked",
                    static_cast<unsigned long long>(kSweepCall));
            return;
        }
        bp::keepcarried::Hook(base + kHolderCheck);
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
        LOG("[mod] game image at 0x%p, %zu bytes. The addresses below were read off 2.03.00, exe 1.0.0.2944.",
            reinterpret_cast<void*>(bp::mem::Game().base), bp::mem::Game().size);

        // Nothing is armed unless KeepCatch is on, the four releases all check
        // out and the teleport hook goes in. Without the hook there is no way
        // to know a teleport has started, and writing the releases for the
        // whole session is what 1.0.0 did and what broke petting.
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
