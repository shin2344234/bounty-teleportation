#include "core/mod.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>

#include "core/log.h"
#include "core/paths.h"
#include "game/errors.h"
#include "game/catchwatch.h"
#include "game/holdwatch.h"
#include "game/keepcarried.h"
#include "game/mem.h"
#include "game/resolve.h"
#include "game/signatures.h"
#include "game/sites.h"
#include "ini_default.h"
#include "version.h"

namespace
{
    std::atomic<bool> g_stop{false};
    HANDLE g_thread = nullptr;

    float ReadSetting(const wchar_t* key, const wchar_t* fallback)
    {
        const std::wstring ini = bp::Paths::File(BP_INI);
        wchar_t buf[64] = {};
        GetPrivateProfileStringW(L"settings", key, fallback, buf, 64, ini.c_str());
        return static_cast<float>(_wtof(buf));
    }

    void ReadSettingText(const wchar_t* key, const wchar_t* fallback, char* out, unsigned cap)
    {
        const std::wstring ini = bp::Paths::File(BP_INI);
        wchar_t buf[64] = {};
        GetPrivateProfileStringW(L"settings", key, fallback, buf, 64, ini.c_str());
        unsigned i = 0;
        for (; i + 1 < cap && buf[i]; ++i) out[i] = buf[i] < 0x80 ? static_cast<char>(buf[i]) : '?';
        out[i] = 0;
    }

    // The ini is the whole interface of a probe: which hooks run, how much each
    // logs. Write the documented one out when there is none beside the plugin,
    // and never touch an existing file, however old.
    void WriteDefaultIni()
    {
        const std::wstring path = bp::Paths::File(BP_INI);
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return;
        FILE* f = nullptr;
        const errno_t e = _wfopen_s(&f, path.c_str(), L"wb");
        if (e != 0 || !f)
        {
            LOG("[ini] %ls is not there and could not be written (errno %d). The built-in hooks still run; "
                "there is just no file to change one in.", BP_INI, e);
            return;
        }
        const bool ok = fwrite(kDefaultIni, 1, kDefaultIniSize, f) == kDefaultIniSize;
        fclose(f);
        LOG(ok ? "[ini] no %ls beside the plugin, so one was written with every setting at its default and "
                 "a note on each. Edit it and restart the game."
               : "[ini] %ls was created but not written in full. Delete it and it will be written again.",
            BP_INI);
    }

    struct Settings
    {
        bool     autoSites;   // hook the handlers the resolver finds
        bool     hookCallers; // and what calls them
        bool     hookHoldCheck; // and the call each branch follows
        bool     holdWatch;   // sample what the hold acquirer decides on, on change
        unsigned holdLines;   // cap on lost-hold pairs; 0 is no cap
        bool     unblock;     // turn the proven refusal's branch into a jump
        bool     unblockAll;  // and the two that have never been seen to refuse
        bool     keepCatch;   // skip the catch release the teleport handler makes after the move
        bool     keepCarried; // and keep the carried actor out of the departure sweep
        bool     dumpErrors;  // every resolved eErr name, once
        unsigned lines;       // per-call log budget for the resolved sites
        char     traceClass[48]; // holdwatch traces actors whose class name contains this
    };

    Settings ReadSettings()
    {
        Settings s;
        s.autoSites   = ReadSetting(L"AutoSites", L"1") != 0.0f;
        s.hookCallers = ReadSetting(L"HookCallers", L"1") != 0.0f;
        s.hookHoldCheck = ReadSetting(L"HookHoldCheck", L"0") != 0.0f;
        s.holdWatch   = ReadSetting(L"HoldWatch", L"1") != 0.0f;
        const float hl = ReadSetting(L"HoldLines", L"0");
        s.holdLines   = hl <= 0 ? 0u : (hl > 5000 ? 5000u : static_cast<unsigned>(hl));
        s.unblock     = ReadSetting(L"Unblock", L"0") != 0.0f;
        s.unblockAll  = ReadSetting(L"UnblockAll", L"0") != 0.0f;
        s.keepCatch   = ReadSetting(L"KeepCatch", L"0") != 0.0f;
        s.keepCarried = ReadSetting(L"KeepCarried", L"0") != 0.0f;
        s.dumpErrors  = ReadSetting(L"DumpErrors", L"0") != 0.0f;
        const float n = ReadSetting(L"Lines", L"0");
        s.lines = n <= 0 ? 0u : (n > 5000 ? 5000u : static_cast<unsigned>(n));
        ReadSettingText(L"TraceClass", L"ChildOnly", s.traceClass, sizeof s.traceClass);
        return s;
    }

    // One place the game raises eErrNoFieldMoveHolding. There are three of them
    // on this build and nothing in the file says which one refuses a map
    // teleport, so the probe watches all of them and lets a session decide.
    struct GateSite
    {
        uintptr_t   reader = 0;   // the instruction that loads the error code
        uintptr_t   func = 0;     // the function it is in
        uintptr_t   branch = 0;   // the short conditional that skips the refusal
        uint8_t     branchOp = 0; // 0x74 (je) or 0x75 (jne)
        uintptr_t   hold = 0;     // the last call before the refusal, when it is rare enough to hook
        int         holdCallers = 0;
        const char* section = "?";
    };

    constexpr int kMaxGateSites = 4;

    // Above this many call sites, a function is general plumbing rather than
    // this handler's predicate, and a detour on it costs a playable session.
    // The candidate on both .didata handlers is called from 4,679 places.
    constexpr int kHotCallerLimit = 64;

    struct Gate
    {
        uintptr_t global = 0;
        int       total = 0;                 // readers found, before the cap
        GateSite  site[kMaxGateSites];
        int       n = 0;
    };

    // The refusal is reached by falling through a short conditional jump, so
    // the two bytes before the error load are that jump. Both halves are
    // checked rather than assumed: the opcode has to be a short je or jne, and
    // it has to land past the load. The polarity differs between the three
    // sites, which is exactly why it is read rather than hardcoded.
    bool FindBranch(GateSite& g)
    {
        const uintptr_t at = g.reader - 2;
        uint8_t b[2] = {};
        if (!bp::mem::ReadBytes(bp::mem::Game().base + at, b, 2)) return false;
        if (b[0] != 0x74 && b[0] != 0x75)
        {
            char hex[64];
            bp::resolve::HexAt(at, 8, hex, sizeof hex);
            LOG_ERR("[gate]   the two bytes before the error load read %s, and a short je or jne is what "
                    "should be there. Unblock cannot touch this one.", hex);
            return false;
        }
        const uintptr_t dest = at + 2 + static_cast<uintptr_t>(static_cast<int8_t>(b[1]));
        if (dest <= g.reader)
        {
            LOG_ERR("[gate]   the jump at +0x%llX lands at +0x%llX, which is not past the error store at "
                    "+0x%llX, so it is not what skips the refusal.", static_cast<unsigned long long>(at),
                    static_cast<unsigned long long>(dest), static_cast<unsigned long long>(g.reader));
            return false;
        }
        g.branch = at;
        g.branchOp = b[0];
        // The bytes just before the jump are the comparison it reads, and that
        // is the real predicate. It is a compare rather than a call, so there
        // is nothing to hook; the log carries it raw for whoever reads it back.
        char before[64];
        bp::resolve::HexAt(at - 10, 10, before, sizeof before);
        LOG("[gate]   skipped by the %s at +0x%llX, which jumps %d bytes to +0x%llX. The ten bytes before "
            "it are %s, which is the comparison it branches on.",
            b[0] == 0x74 ? "je" : "jne", static_cast<unsigned long long>(at),
            static_cast<int>(static_cast<int8_t>(b[1])), static_cast<unsigned long long>(dest), before);
        return true;
    }

    Gate ResolveGate()
    {
        Gate g;
        int leas = 0;
        const DWORD t0 = GetTickCount();
        g.global = bp::resolve::ErrorGlobal(bp::sig::kGateError, &leas);
        if (!g.global)
        {
            LOG_ERR("[gate] %s did not resolve to a global, so nothing is hooked from it. Every address "
                    "below would have come from that one step.", bp::sig::kGateError);
            return g;
        }

        uintptr_t readers[kMaxGateSites] = {};
        const int found = bp::resolve::Readers(g.global, readers, kMaxGateSites, &g.total);
        LOG("[gate] %s: %d leas -> global +0x%llX (%s), read by %d instruction%s", bp::sig::kGateError, leas,
            static_cast<unsigned long long>(g.global), bp::resolve::SectionOf(g.global), g.total,
            g.total == 1 ? "" : "s");
        if (g.total > found)
            LOG("[gate] only the first %d are followed; raise kMaxGateSites to take the rest", found);
        if (!found)
        {
            LOG_ERR("[gate] nothing reads it, which cannot be right for an error the game shows. The scan "
                    "covers both executable sections, so this is a change in how the code loads it.");
            return g;
        }

        for (int i = 0; i < found; ++i)
        {
            GateSite s;
            s.reader = readers[i];
            s.section = bp::resolve::SectionOf(s.reader);
            s.func = bp::resolve::FunctionStart(s.reader);
            if (!s.func)
            {
                LOG_ERR("[gate] reader %d at +0x%llX (%s) has no unwind entry, so its function start is "
                        "unknown and it is skipped", i + 1, static_cast<unsigned long long>(s.reader), s.section);
                continue;
            }
            LOG("[gate] reader %d: +0x%llX in %s, inside +0x%llX, %llu bytes into it", i + 1,
                static_cast<unsigned long long>(s.reader), s.section,
                static_cast<unsigned long long>(s.func), static_cast<unsigned long long>(s.reader - s.func));
            FindBranch(s);
            const uintptr_t lastCall = bp::resolve::LastCallBefore(s.func, s.reader);
            if (!lastCall)
                LOG("[gate]   no call between the function's start and the error store, so nothing near the "
                    "branch is worth hooking separately");
            else
            {
                s.holdCallers = bp::resolve::Callers(lastCall, nullptr, 0);
                if (s.holdCallers <= kHotCallerLimit)
                {
                    s.hold = lastCall;
                    LOG("[gate]   the last call before it is +0x%llX (%s), called from %d places, so it is "
                        "hooked too", static_cast<unsigned long long>(lastCall),
                        bp::resolve::SectionOf(lastCall), s.holdCallers);
                }
                else
                    LOG("[gate]   the last call before it is +0x%llX (%s), called from %d places. That is "
                        "general plumbing rather than this handler's predicate, and a detour on it would "
                        "drown the log and the frame rate, so it is left alone.",
                        static_cast<unsigned long long>(lastCall), bp::resolve::SectionOf(lastCall),
                        s.holdCallers);
            }
            g.site[g.n++] = s;
        }

        // Against the notes. The resolver is the authority; this line exists so
        // a build that has moved says so in one place, instead of being noticed
        // later from a log that read plausibly.
        const bool same = g.global == bp::sig::kGateErrGlobal && g.total == bp::sig::kGateReaderCount &&
                          g.n > 0 && g.site[0].func == bp::sig::kGateFunction;
        if (same) LOG("[gate] the global, the reader count and the first handler all match the notes for %s",
                      bp::sig::kBuild);
        else LOG("[gate] this does not match the notes for %s, which record global +0x%llX, %d readers and "
                 "+0x%llX as the first handler. The resolver is what to trust; FEASIBILITY.md needs the new "
                 "numbers.", bp::sig::kBuild, static_cast<unsigned long long>(bp::sig::kGateErrGlobal),
                 bp::sig::kGateReaderCount, static_cast<unsigned long long>(bp::sig::kGateFunction));
        LOG("[gate] resolved in %lu ms", static_cast<unsigned long>(GetTickCount() - t0));
        return g;
    }

    void HookGate(const Gate& g, const Settings& s)
    {
        if (!s.autoSites || !g.n) return;
        const uintptr_t base = bp::mem::Game().base;
        char spec[192], name[48];
        int callersHooked = 0;

        // Two handlers can share a caller, and a bad reader can name the same
        // handler twice. Hooking one entry twice leaves each thunk stealing
        // bytes the other wrote, so every address goes in here first.
        uintptr_t hooked[16] = {};
        int nHooked = 0;
        auto claim = [&](uintptr_t a) {
            for (int k = 0; k < nHooked; ++k) if (hooked[k] == a) return false;
            if (nHooked < 16) hooked[nHooked++] = a;
            return true;
        };

        for (int i = 0; i < g.n; ++i)
        {
            const GateSite& site = g.site[i];

            // The handler. On the one in .code, rdx is the out pointer the
            // error is written to, which is what names a refusal at return.
            // The other two are read the same way and the log says if they are
            // not: a nonsense out value is visible as one.
            // onerr: these run tens of thousands of times a session, nearly
            // all of them about actors streaming in. Silent until one returns
            // an error, then everything about that call; and everything about
            // every call on a marked actor (onlymarked), which is how the
            // player's own move and the carried outlaw's are told apart from
            // the rest: the request in r8 carries the destination, and the
            // unwind says who asked.
            snprintf(name, sizeof name, "fieldmove%d", i + 1);
            // The dump of `this` stops at 0x400, short of the field-attach
            // sub-object at +0x4F0; holdwatch writes that one itself when
            // the handler's hold is refused.
            if (s.lines) snprintf(spec, sizeof spec, "out=2, args=4, onerr=1, onlymarked=1, marks=0x180, errlines=%u, obj=0x400", s.lines);
            else snprintf(spec, sizeof spec, "out=2, args=4, onerr=1, onlymarked=1, marks=0x180, obj=0x400");
            if (claim(base + site.func)) bp::sites::AddSite(name, base + site.func, spec);
            else LOG("[gate] +0x%llX is already hooked, so %s is not added",
                     static_cast<unsigned long long>(site.func), name);

            // The call the branch follows. Session three showed it hands back a
            // FieldAttacherForActor rather than an error, so out=2 reads a
            // pointer and calls every one of its half a million calls a
            // refusal. It is also not the predicate: that is the cmp between
            // the call and the jump, on a local. Off unless asked for.
            if (site.hold && s.hookHoldCheck)
            {
                snprintf(name, sizeof name, "holdcheck%d", i + 1);
                if (s.lines) snprintf(spec, sizeof spec, "args=2, lines=%u, retobj=0x40, obj=0x80", s.lines);
                else snprintf(spec, sizeof spec, "args=2, retobj=0x40, obj=0x80");
                if (claim(base + site.hold)) bp::sites::AddSite(name, base + site.hold, spec);
                else LOG("[gate] +0x%llX is already hooked, so %s is not added",
                         static_cast<unsigned long long>(site.hold), name);
            }

            if (!s.hookCallers) continue;
            uintptr_t calls[4] = {};
            const int nc = bp::resolve::Callers(site.func, calls, 4);
            const int shown = nc < 4 ? nc : 4;
            LOG("[gate] +0x%llX is called from %d place%s%s", static_cast<unsigned long long>(site.func), nc,
                nc == 1 ? "" : "s", nc > 4 ? ", of which the first four are followed" : "");
            for (int k = 0; k < shown && callersHooked < 4; ++k)
            {
                const uintptr_t fn = bp::resolve::FunctionStart(calls[k]);
                if (!fn) continue;
                LOG("[gate]   from +0x%llX, inside +0x%llX (%s)", static_cast<unsigned long long>(calls[k]),
                    static_cast<unsigned long long>(fn), bp::resolve::SectionOf(fn));
                if (!claim(base + fn)) continue;
                snprintf(name, sizeof name, "fm_caller%d", ++callersHooked);
                if (s.lines) snprintf(spec, sizeof spec, "args=4, onerr=1, onlymarked=1, marks=0x180, errlines=%u, obj=0x100", s.lines);
                else snprintf(spec, sizeof spec, "args=4, onerr=1, onlymarked=1, marks=0x180, obj=0x100");
                bp::sites::AddSite(name, base + fn, spec);
            }
        }
    }

    // Session nine's answer. The map teleport's server handler (+0x2BC9640)
    // moves the player through the field-move wrapper +0x2BCCE30, and that
    // wrapper's tail (+0x21A16F0 -> +0x2BCB960) moves whatever the player
    // is catching with the same request, so the outlaw arrives at the
    // destination on his own. Then the handler calls slot 0x200 of the
    // player's ServerCharacterControlActorComponent, +0x23290D0, which
    // releases the catch (catch_update, reason 9) whenever the catch
    // component holds one, and the outlaw is left standing there. The
    // release sits behind `test bl, bl; je +0x2329148`; making that jump
    // unconditional keeps the catch through the teleport. 2.03.00 bytes,
    // checked three ways before anything is written: the je's bytes, the
    // call it skips being catch_update, and the vtable slot being the
    // function.
    // One release, written twice. Slot 0x200 of the character-control
    // component is +0x23290D0 for the server and common classes, and for
    // ClientCharacterControlActorComponent it is a thunk at +0x860F90 to
    // +0x99B6CB0, which is the same code instruction for instruction: read
    // the catch component at [[actor+0x68]+0x70], test its +0x38 then its
    // +0x28, and on either call catch_update with reason 9. Session ten
    // patched the server's branch alone, so the server carried the outlaw
    // to the destination while the client put him down, and he arrived
    // lying on the ground. Both copies get the same branch now.
    //
    // Each one is checked three ways before a byte is written: the call it
    // skips must reach catch_update, the class's slot 0x200 must still hold
    // the function (through its thunk, where there is one), and the branch
    // itself must read 74 22.
    // One release, written out three times. Each copy reads the catch
    // component at [[actor+0x68]+0x70], tests its +0x38 and then its +0x28
    // into bl, and calls catch_update with reason 9 behind a short jump over
    // that call. Those seventeen bytes of test are identical in all three,
    // which is what `guard` checks.
    //
    //   +0x23290D0   slot 0x200 of Server and Common CharacterControl
    //   +0x99B6CB0   the same slot on the client class, through a thunk at
    //                +0x860F90
    //   +0x156EF40   a client state transition with no vtable entry, reached
    //                from +0x9F19F7 and +0x1F58C26
    //
    // Session ten found them one at a time, each after a trial that put the
    // outlaw on the ground: the first patch alone left the client letting go,
    // the first two left this one. It fired exactly once in the 18:05 run,
    // a second after the confirm.
    struct Release
    {
        const char* label;
        uintptr_t   at;          // the two bytes that decide whether it runs
        uint8_t     orig[2];     // what they read now
        uint8_t     repl[2];     // what they are replaced with
        uintptr_t   call;        // the catch_update call it skips
        uintptr_t   guard;       // the test that decides it
        uintptr_t   vtable;      // 0 when the function is not in a vtable
        uintptr_t   slotTarget;  // what slot 0x200 must hold
        uintptr_t   thunkTo;     // 0 unless that slot points at a jmp
        bool        watchdog;    // the periodic check rather than a teleport path
    };

    bool PatchRelease(const Release& r)
    {
        constexpr uintptr_t kCatchUpdate = 0x20AD3A0;
        // cmp [rcx+0x38],0 / je / mov bl,1 / jmp / cmp [rcx+0x28],0 / setne
        static const uint8_t kGuard[16] = { 0x83, 0x79, 0x38, 0x00, 0x74, 0x04, 0xB3, 0x01,
                                            0xEB, 0x07, 0x83, 0x79, 0x28, 0x00, 0x0F, 0x95 };
        // The watchdog reads the two handles into registers first:
        // test edi,edi / jne / test ebx,ebx / je
        static const uint8_t kWatchdog[8] = { 0x85, 0xFF, 0x75, 0x04, 0x85, 0xDB, 0x74, 0x3E };
        const uintptr_t base = bp::mem::Game().base;

        auto branch = [&](uintptr_t at, uint8_t op) -> uintptr_t
        {
            uint8_t b[5] = {};
            if (!bp::mem::ReadBytes(base + at, b, 5) || b[0] != op) return 0;
            int32_t rel = 0;
            memcpy(&rel, b + 1, 4);
            return at + 5 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
        };

        const uintptr_t target = branch(r.call, 0xE8);
        if (target != kCatchUpdate)
        {
            LOG_ERR("[%s] the call at +0x%llX goes to +0x%llX, not catch_update at +0x%llX, so the release is not "
                    "where the notes say and nothing is written", r.label, static_cast<unsigned long long>(r.call),
                    static_cast<unsigned long long>(target), static_cast<unsigned long long>(kCatchUpdate));
            return false;
        }
        uint8_t guard[16] = {};
        const uint8_t* want = r.watchdog ? kWatchdog : kGuard;
        const unsigned n = r.watchdog ? 8u : 16u;
        if (!bp::mem::ReadBytes(base + r.guard, guard, n) || memcmp(guard, want, n) != 0)
        {
            LOG_ERR("[%s] the test at +0x%llX is not the catch check this build should have, so nothing is written",
                    r.label, static_cast<unsigned long long>(r.guard));
            return false;
        }
        if (r.vtable)
        {
            uint64_t slot = 0;
            if (!bp::mem::Read64(base + r.vtable + 0x200, &slot) || slot != base + r.slotTarget)
            {
                LOG_ERR("[%s] slot 0x200 of the vtable at +0x%llX is 0x%llX, not +0x%llX; nothing written", r.label,
                        static_cast<unsigned long long>(r.vtable), static_cast<unsigned long long>(slot),
                        static_cast<unsigned long long>(r.slotTarget));
                return false;
            }
            if (r.thunkTo && branch(r.slotTarget, 0xE9) != r.thunkTo)
            {
                LOG_ERR("[%s] the thunk at +0x%llX does not jump to +0x%llX; nothing written", r.label,
                        static_cast<unsigned long long>(r.slotTarget), static_cast<unsigned long long>(r.thunkTo));
                return false;
            }
        }
        return bp::sites::ApplyPatch(r.label, r.at, r.orig, r.repl, 2);
    }

    void ApplyKeepCatch()
    {
        // The fourth is not on the teleport path. +0x20AE540 runs on the
        // catch component itself, reads the two handles, and calls
        // catch_update with reason 1 unless the state object behind
        // [[[actor+0x68]+0x40]+0x88]+0x10 says the carry is still backed by
        // its animation flags. A teleport resets those flags, so a second
        // after the confirm it decides the catch is stale and drops it on
        // both sides at once.
        //
        // Its entry is two branches, not one:
        //
        //     +0x20AE5C8  test edi,edi          ; the held handle
        //     +0x20AE5CA  jne  +0x20AE5D0       ; something held, so check it
        //     +0x20AE5CC  test ebx,ebx          ; the carrier handle
        //     +0x20AE5CE  je   +0x20AE60E       ; nothing held, nothing to do
        //
        // 0.9.4 made the second one unconditional, which does nothing
        // during a carry: the first branch has already jumped over it. The
        // 18:32 trial applied the patch, logged it, and still lost both
        // handles a second after arrival, from this same call. What skips
        // the release for a live catch is a jump at the top of the pair,
        // so 0.9.5 writes EB 44 over the first test and lands on the same
        // +0x20AE60E the guard's own branches use.
        static const Release kReleases[] = {
            { "keepcatch",          0x2329124, { 0x74, 0x22 }, { 0xEB, 0x22 },
              0x2329143, 0x2329104, 0x5B25260, 0x23290D0, 0,         false },
            { "keepcatch_client",   0x99B6D0F, { 0x74, 0x22 }, { 0xEB, 0x22 },
              0x99B6D2E, 0x99B6CEF, 0x55B53C8, 0x860F90,  0x99B6CB0, false },
            { "keepcatch_state",    0x156F24D, { 0x74, 0x20 }, { 0xEB, 0x20 },
              0x156F26A, 0x156F22B, 0,         0,         0,         false },
            { "keepcatch_watchdog", 0x20AE5C8, { 0x85, 0xFF }, { 0xEB, 0x44 },
              0x20AE609, 0x20AE5C8, 0,         0,         0,         true  },
        };
        int done = 0;
        for (const Release& r : kReleases) if (PatchRelease(r)) ++done;
        const int total = static_cast<int>(sizeof kReleases / sizeof kReleases[0]);
        if (done == total)
            LOG_OK("[keepcatch] all %d copies of the teleport's catch release are skipped, so the player keeps "
                   "what he is carrying through a map teleport and both sides still say he is carrying it", total);
        else
            LOG_ERR("[keepcatch] %d of %d copies of the release were patched. The rest still run, and the sides "
                    "will disagree about whether anything is being carried.", done, total);
    }

    // Session ten. KeepCatch alone was not enough (15:47 log): the outlaw
    // was moved with the player and kept caught, and a message handler that
    // runs at every map confirm (+0x10DC8D90) then tore down every actor the
    // player's session had spawned in the field, him included, through
    // +0x287DB30 -> +0x287D440 -> +0x2808D00 -> +0x107313E0 -> +0x2817E00 ->
    // +0xE44B050 -> the actor's virtual 0x110, which is where his catch was
    // cleaned up and his field went. The 15:33 log had the same sweep on
    // him; what looked like his re-placement was a new NPC at the same
    // address. +0x2817E00 spares an actor when +0x1F53D10 (a thunk to
    // +0xE1478D0) says someone else still holds it. keepcarried answers
    // that for a carried actor. Three things are checked before the hook
    // goes in: the check's first bytes, the thunk jumping to it, and the
    // sweep's call reaching the thunk.
    void InstallKeepCarried()
    {
        constexpr uintptr_t kCheck = 0xE1478D0, kThunk = 0x1F53D10, kCallInSweep = 0x2818160;
        static const uint8_t kHead[9] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x44, 0x8B, 0x41, 0x1C };
        const uintptr_t base = bp::mem::Game().base;
        uint8_t head[9] = {};
        if (!bp::mem::ReadBytes(base + kCheck, head, 9) || memcmp(head, kHead, 9) != 0)
        {
            LOG_ERR("[keepcarried] +0x%llX does not start the way the holder check does on 2.03.00, so it is not "
                    "hooked", static_cast<unsigned long long>(kCheck));
            return;
        }
        auto branchTarget = [&](uintptr_t at, uint8_t op) -> uintptr_t
        {
            uint8_t b[5] = {};
            if (!bp::mem::ReadBytes(base + at, b, 5) || b[0] != op) return 0;
            int32_t rel = 0;
            memcpy(&rel, b + 1, 4);
            return at + 5 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
        };
        const uintptr_t thunkTo = branchTarget(kThunk, 0xE9);
        if (thunkTo != kCheck)
        {
            LOG_ERR("[keepcarried] the thunk at +0x%llX goes to +0x%llX, not the holder check at +0x%llX; not hooked",
                    static_cast<unsigned long long>(kThunk), static_cast<unsigned long long>(thunkTo),
                    static_cast<unsigned long long>(kCheck));
            return;
        }
        const uintptr_t callTo = branchTarget(kCallInSweep, 0xE8);
        if (callTo != kThunk)
        {
            LOG_ERR("[keepcarried] the sweep's call at +0x%llX goes to +0x%llX, not the thunk at +0x%llX; not hooked",
                    static_cast<unsigned long long>(kCallInSweep), static_cast<unsigned long long>(callTo),
                    static_cast<unsigned long long>(kThunk));
            return;
        }
        bp::keepcarried::Hook(base + kCheck);
    }

    void ApplyUnblock(const Gate& g, bool all)
    {
        // Readers come back lowest address first, so site 0 is the one in
        // .code: the handler session three caught refusing twice. The other
        // two ran 1,984 and 6 times in that session and refused nothing, and
        // one of them is on a path the game takes constantly, so they are left
        // alone unless asked for.
        const int last = all ? g.n : (g.n ? 1 : 0);
        if (!all && g.n > 1)
            LOG("[unblock] patching the handler that has been seen to refuse and leaving the other %d alone. "
                "UnblockAll=1 takes all of them.", g.n - 1);
        int done = 0, skipped = 0;
        for (int i = 0; i < last; ++i)
        {
            const GateSite& site = g.site[i];
            if (!site.branch) { ++skipped; continue; }
            uint8_t cur[2] = {};
            if (!bp::mem::ReadBytes(bp::mem::Game().base + site.branch, cur, 2)) { ++skipped; continue; }
            const uint8_t orig[2] = { site.branchOp, cur[1] };
            const uint8_t repl[2] = { 0xEB, cur[1] };
            char label[32];
            snprintf(label, sizeof label, "Unblock%d", i + 1);
            if (bp::sites::ApplyPatch(label, site.branch, orig, repl, 2)) ++done;
        }
        LOG("[unblock] %d of %d refusal branches turned into unconditional jumps%s. Everything past each "
            "branch runs as it always did; whether a carried target survives what follows is the open "
            "question, and a save backup is the answer to getting that wrong.",
            done, last, skipped ? ", the rest left alone because they did not look the way they should" : "");
    }

    DWORD WINAPI Worker(LPVOID)
    {
        WriteDefaultIni();
        const Settings s = ReadSettings();

        LOG("[mod] %s %s. Settings: AutoSites=%d HookCallers=%d HookHoldCheck=%d HoldWatch=%d HoldLines=%u "
            "Unblock=%d KeepCatch=%d KeepCarried=%d DumpErrors=%d Lines=%u TraceClass=%s", BP_NAME, BP_VERSION,
            s.autoSites ? 1 : 0, s.hookCallers ? 1 : 0, s.hookHoldCheck ? 1 : 0, s.holdWatch ? 1 : 0, s.holdLines,
            s.unblock ? 1 : 0, s.keepCatch ? 1 : 0, s.keepCarried ? 1 : 0, s.dumpErrors ? 1 : 0, s.lines,
            s.traceClass);
        LOG("[mod] game image at 0x%p, %zu bytes. The notes were written against %s.",
            reinterpret_cast<void*>(bp::mem::Game().base), bp::mem::Game().size, bp::sig::kBuild);

        // The first call nearly always finds nothing: the ASI loader gets this
        // plugin in before the game has initialised its own statics. The
        // worker keeps asking. Hooking does not wait on it, because the names
        // are looked up when a line is written rather than when a hook goes in.
        bp::errors::Load();

        const Gate gate = ResolveGate();

        // The ini first, so a hand-written site wins a name collision with an
        // automatic one and the fixed catch hooks are in before the resolved
        // ones eat the site budget.
        bp::sites::Install(true);
        HookGate(gate, s);

        // The hold acquirer sits behind the first handler's predicate call.
        // Site 0 is the .code handler, the one that refuses; its `hold` is
        // the wrapper +0x2BC4200 and the acquirer is the one call inside it.
        if (s.holdWatch && gate.n && gate.site[0].hold)
            bp::holdwatch::Install(gate.site[0].hold, s.holdLines, gate.site[0].func,
                                   s.traceClass[0] ? s.traceClass : nullptr);
        else if (s.holdWatch)
            LOG("[hold] HoldWatch is on but the resolver found no predicate call before the first handler's "
                "refusal, so there is nothing to sample");

        if (s.unblock) ApplyUnblock(gate, s.unblockAll);
        else LOG("[unblock] Unblock is 0, so every refusal stands. Sessions one to nine found no refusal on "
                 "the player; the teleport goes and the catch is released, which is KeepCatch's business.");
        if (s.keepCatch) ApplyKeepCatch();
        else LOG("[keepcatch] KeepCatch is 0, so the teleport handler releases the catch as it always has");
        if (s.keepCarried)
        {
            if (!s.keepCatch)
                LOG("[keepcarried] KeepCarried without KeepCatch does nothing useful: the release runs before the "
                    "sweep and clears the carried flag this reads, so the sweep removes the actor as shipped");
            InstallKeepCarried();
        }
        else LOG("[keepcarried] KeepCarried is 0, so the departure sweep removes the carried actor as it always has");

        int tick = 0, errorTries = 0;
        bool dumped = false;
        while (!g_stop.load())
        {
            // A pass is two seconds, so this gives the game four minutes to
            // fill the error table in before giving up on naming codes.
            if (!bp::errors::Ready() && errorTries < 120)
            {
                if (bp::errors::Load() && bp::errors::Ready())
                    LOG_OK("[errors] the table filled in %d seconds after the plugin loaded", errorTries * 2);
                else if (++errorTries == 120)
                    LOG_ERR("[errors] the error globals were still empty after four minutes, so codes stay "
                            "numbers for the rest of this session.");
            }
            if (bp::errors::Ready() && s.dumpErrors && !dumped) { bp::errors::DumpAll(); dumped = true; }
            bp::sites::Tick();
            bp::sites::Summarise();
            bp::holdwatch::Summarise();
            bp::keepcarried::Summarise();
            if (++tick % 30 == 0) LOG("[mod] still running, %d minutes in", tick / 30);
            for (int i = 0; i < 20 && !g_stop.load(); ++i) { Sleep(100); bp::catchwatch::Tick(); bp::Log::Flush(); }
        }
        LOG("[mod] worker stopped");
        return 0;
    }
}

namespace bp::Mod
{
    // crashpad_handler.exe loads this plugin too, with a 671,744-byte image on
    // this build. That instance names its own log, says why it is doing
    // nothing, and touches nothing. Flight Freedom learned this the expensive
    // way: a log file named after something that changes every run is a leak,
    // and one folder had 78 of them.
    static constexpr size_t kMinGameImage = 64ull * 1024 * 1024;

    void Initialize(HMODULE module)
    {
        Paths::Init(module);
        const size_t size = mem::Game().size;
        if (!mem::Game().base || size < kMinGameImage)
        {
            wchar_t name[96];
            _snwprintf_s(name, _countof(name), _TRUNCATE, L"%s.other", BP_FILEBASE);
            Log::ClaimSingle(name);

            wchar_t exe[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, exe, MAX_PATH);
            const wchar_t* leaf = wcsrchr(exe, L'\\');
            LOG("[mod] %ls (pid %lu) has a %zu byte image, which is not the game, so nothing is hooked here. "
                "The game's own log is %ls.log.", leaf ? leaf + 1 : exe, GetCurrentProcessId(), size, BP_FILEBASE);
            Log::Shutdown();
            return;
        }
        Log::Claim(BP_FILEBASE);
        Log::RemovePerProcessLogs(BP_FILEBASE);
        g_thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    }

    void Shutdown(bool processExiting)
    {
        g_stop.store(true);
        if (processExiting)
        {
            Log::Shutdown();
            return;
        }
        if (g_thread)
        {
            WaitForSingleObject(g_thread, 3000);
            CloseHandle(g_thread);
            g_thread = nullptr;
        }
        sites::Remove();
        Log::Shutdown();
    }
}
