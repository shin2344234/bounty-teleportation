#include "game/holdwatch.h"

#include <Windows.h>
#include <intrin.h>
#include <cstdio>
#include <cstring>

#include "core/log.h"
#include "game/dump.h"
#include "game/farhook.h"
#include "game/unwind.h"
#include "game/mem.h"
#include "game/resolve.h"
#include "game/sites.h"

namespace bp::holdwatch
{
    namespace
    {
        using Fn = uint64_t(*)(uint64_t sub, uint64_t out);
        Fn  g_orig = nullptr;

        // The acquirer runs for every actor with a transform component, not
        // just the player, so "last sample" has to be per sub-object or every
        // call would read as a change. 256 slots, oldest evicted.
        constexpr int kSubs = 256;
        struct Slot { Sample last; LONG64 seen; bool lost; };
        Slot   g_slots[kSubs];
        int    g_nSlots = 0;
        LONG64 g_tick = 0;
        CRITICAL_SECTION g_lock;

        // Where the wrapper returns to inside itself, and how far above our
        // own return address the wrapper's return address sits: it does
        // `push rbx; sub rsp, 0x30` after being called, so 8 + 0x30 + 8.
        uint64_t  g_wrapperRet = 0;
        constexpr unsigned kWrapperFrame = 0x40;
        uintptr_t g_gateLo = 0, g_gateHi = 0;
        char      g_traceClass[48] = "";
        volatile LONG g_tracedCalls = 0;

        // Marked by a site (the outlaw, the player's catch component and its
        // owner), or of the traced class (the player's own).
        bool Traced(const Sample& s)
        {
            if (bp::sites::Interesting(s.actor) || (s.owner && bp::sites::Interesting(s.owner))) return true;
            if (!g_traceClass[0] || !s.actor) return false;
            const char* cls = bp::mem::RttiShort(s.actor);
            return cls && strstr(cls, g_traceClass) != nullptr;
        }

        volatile LONG g_calls = 0, g_refused = 0, g_changes = 0, g_requests = 0, g_requestsRefused = 0, g_losses = 0;
        // No budgets: everything is written. The counters and the refill
        // stay so a cap can be set again from Install() if a session ever
        // needs a quiet log, and the tests exercise that path.
        constexpr LONG kUnlimited = 0x7FFF0000;
        volatile LONG g_lossLines = kUnlimited, g_changeLines = kUnlimited, g_firstLines = kUnlimited,
                      g_requestLines = kUnlimited, g_dumpsLeft = kUnlimited;
        volatile LONG g_refusedDumpsLeft = kUnlimited;
        LONG g_lossCap = kUnlimited, g_changeCap = kUnlimited, g_firstCap = kUnlimited, g_requestCap = kUnlimited,
             g_dumpCap = kUnlimited, g_refusedDumpCap = kUnlimited;
        constexpr LONG kRefill = 4;   // per Summarise() tick, which is every two seconds

        void Refill(volatile LONG* left, LONG cap)
        {
            for (;;)
            {
                const LONG cur = InterlockedCompareExchange(left, 0, 0);
                if (cur >= cap) return;
                const LONG next = cur + kRefill > cap ? cap : cur + kRefill;
                if (InterlockedCompareExchange(left, next, cur) == cur) return;
            }
        }
        LONG g_reportedCalls = 0, g_reportedRefused = 0;

        void Name(uintptr_t p, char* out, unsigned cap)
        {
            if (!p) { snprintf(out, cap, "null"); return; }
            const char* n = bp::mem::RttiShort(p);
            if (n) snprintf(out, cap, "<%s>", n);
            else snprintf(out, cap, "0x%llX", static_cast<unsigned long long>(p));
        }

        void Where(uintptr_t p, char* out, unsigned cap)
        {
            if (bp::mem::InImage(p)) snprintf(out, cap, "+0x%llX", static_cast<unsigned long long>(bp::mem::Rva(p)));
            else snprintf(out, cap, "0x%llX (not in the image)", static_cast<unsigned long long>(p));
        }

        Slot* Find(uintptr_t sub)
        {
            for (int i = 0; i < g_nSlots; ++i) if (g_slots[i].last.sub == sub) return &g_slots[i];
            return nullptr;
        }

        Slot* Insert(const Sample& s)
        {
            Slot* victim = nullptr;
            if (g_nSlots < kSubs) victim = &g_slots[g_nSlots++];
            else
            {
                victim = &g_slots[0];
                for (int i = 1; i < kSubs; ++i) if (g_slots[i].seen < victim->seen) victim = &g_slots[i];
            }
            victim->last = s;
            return victim;
        }

        void Dumps(const Sample& s)
        {
            if (InterlockedCompareExchange(&g_dumpsLeft, 0, 0) <= 0) return;
            InterlockedDecrement(&g_dumpsLeft);
            if (bp::mem::Plausible(s.sub)) bp::dump::Object("hold sub", s.sub, 0x80);
            if (bp::mem::Plausible(s.actor)) bp::dump::Object("hold actor", s.actor, 0x100);
            if (bp::mem::Plausible(s.c1a0)) bp::dump::Object("hold chain+0x1a0", s.c1a0, 0x580);
        }

        uint64_t Detour(uint64_t sub, uint64_t out)
        {
            // Our return address is inside the wrapper; the wrapper's own is
            // a known distance above it. Anything else calling the acquirer
            // directly is named by its own return address instead.
            uint64_t* ra = static_cast<uint64_t*>(_AddressOfReturnAddress());
            const bool viaWrapper = g_wrapperRet && *ra == g_wrapperRet;
            const uint64_t caller = viaWrapper ? *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(ra) + kWrapperFrame)
                                               : *ra;

            const uint64_t r = g_orig(sub, out);
            const LONG call = InterlockedIncrement(&g_calls);
            Sample s;
            Read(static_cast<uintptr_t>(sub), s);
            uint8_t ok = 0;
            bp::mem::Read8(static_cast<uintptr_t>(out) + 0x10, &ok);
            s.ok = ok != 0;
            s.caller = static_cast<uintptr_t>(caller);
            s.resultType = bp::mem::RttiShort(static_cast<uintptr_t>(out));
            if (!s.ok) InterlockedIncrement(&g_refused);

            // The field-move handler asks on every one of its calls, 27,359
            // in session seven, so only its refusals are written: that is
            // the sample the refusal was decided on, next to the refusal.
            const bool request = g_gateLo && bp::mem::InImage(caller) &&
                                 bp::mem::Rva(caller) >= g_gateLo && bp::mem::Rva(caller) < g_gateHi;
            if (request)
            {
                InterlockedIncrement(&g_requests);
                if (!s.ok)
                {
                    InterlockedIncrement(&g_requestsRefused);
                    if (InterlockedCompareExchange(&g_requestLines, 0, 0) > 0)
                    {
                        InterlockedDecrement(&g_requestLines);
                        char text[640];
                        Describe(s, text, sizeof text);
                        LOG("[hold] the field-move handler was refused at call %ld: %s", call, text);
                        Dumps(s);
                        // Who asked for this actor's move, and what the actor
                        // is to the player, are the two questions a refusal
                        // here leaves open. The stack answers the first; the
                        // owning component, past the dump clamp, the second.
                        if (InterlockedCompareExchange(&g_refusedDumpsLeft, 0, 0) > 0)
                        {
                            InterlockedDecrement(&g_refusedDumpsLeft);
                            if (bp::mem::Plausible(s.owner)) bp::dump::Object("hold owner component", s.owner, 0x600);
                            bp::unwind::Here("field-move hold refused", 40);
                        }
                    }
                }
            }

            // A traced actor is written on every call, with its caller: what
            // asks about its field attachment, and in what order, around a
            // teleport. From inside the handler it also gets the dumps; the
            // handler's own site carries the unwind.
            const bool traced = Traced(s);
            if (traced)
            {
                InterlockedIncrement(&g_tracedCalls);
                char text[640];
                Describe(s, text, sizeof text);
                LOG("[hold] traced actor at call %ld%s: %s", call,
                    request ? " (asked by the field-move handler)" : "", text);
                if (request) Dumps(s);
            }

            EnterCriticalSection(&g_lock);
            ++g_tick;
            Slot* slot = Find(static_cast<uintptr_t>(sub));
            Sample before;
            int kind = 0;   // 0 nothing, 1 first sight, 2 change, 3 lost the hold, 4 got it back
            if (!slot) { slot = Insert(s); slot->lost = false; kind = 1; }
            else if (Differs(slot->last, s))
            {
                before = slot->last;
                if (before.ok && !s.ok) { kind = 3; slot->lost = true; }
                else if (!before.ok && s.ok && slot->lost) { kind = 4; slot->lost = false; }
                else kind = 2;
                slot->last = s;
            }
            slot->seen = g_tick;
            LeaveCriticalSection(&g_lock);
            if (!kind) return r;

            // A sub-object that had the hold and lost it is the carry, or
            // whatever else takes it away, and the sample it had before is
            // the other half of the diff. Those get their own budget; the
            // world load spends the plain one in fifteen seconds.
            volatile LONG* budget = kind == 1 ? &g_firstLines : (kind == 2 ? &g_changeLines : &g_lossLines);
            LONG n = 0;
            if (kind == 2) n = InterlockedIncrement(&g_changes);
            if (kind == 3) n = InterlockedIncrement(&g_losses);
            if (InterlockedCompareExchange(budget, 0, 0) <= 0) return r;
            InterlockedDecrement(budget);
            char text[640];
            Describe(s, text, sizeof text);
            if (kind == 1) LOG("[hold] first sight at call %ld: %s", call, text);
            else if (kind == 2) LOG("[hold] change %ld at call %ld: %s", n, call, text);
            else
            {
                char was[640];
                Describe(before, was, sizeof was);
                LOG("[hold] %s at call %ld. was: %s", kind == 3 ? "lost the hold" : "got the hold back", call, was);
                LOG("[hold] %s at call %ld. now: %s", kind == 3 ? "lost the hold" : "got the hold back", call, text);
                Dumps(s);
                if (traced) bp::unwind::Here(kind == 3 ? "traced actor lost the hold" : "traced actor got the hold back", 40);
            }
            return r;
        }
    }

    bool Read(uintptr_t sub, Sample& s)
    {
        s = Sample{};
        s.sub = sub;
        if (!bp::mem::Read8(sub + 0x58, &s.blocked)) return false;
        bp::mem::Read16(sub + 0x5a, &s.holds);
        if (bp::mem::ReadPtr(sub + 0x10, &s.p10)) bp::mem::Read8(s.p10 + 0x4a, &s.p10Alive);
        bp::mem::ReadPtr(sub + 0x50, &s.p50);
        if (bp::mem::ReadPtr(sub, &s.owner) && bp::mem::ReadPtr(s.owner + 8, &s.actor))
        {
            bp::mem::Read8(s.actor + 0xC2, &s.actorFlag);
            if (bp::mem::ReadPtr(s.actor + 0x68, &s.c68) && bp::mem::ReadPtr(s.c68 + 0x1a0, &s.c1a0))
                bp::mem::ReadPtr(s.c1a0 + 0x540, &s.c540);
        }
        return true;
    }

    bool Differs(const Sample& a, const Sample& b)
    {
        return a.ok != b.ok || a.blocked != b.blocked || (a.p10 == 0) != (b.p10 == 0) ||
               a.p10Alive != b.p10Alive || a.actorFlag != b.actorFlag ||
               a.p50 != b.p50 || a.actor != b.actor || a.c540 != b.c540;
    }

    void Why(const Sample& s, char* out, unsigned cap)
    {
        if (s.ok) { snprintf(out, cap, "ok"); return; }
        char buf[128] = "";
        unsigned n = 0;
        auto add = [&](const char* what) {
            n += static_cast<unsigned>(snprintf(buf + n, sizeof buf - n, "%s%s", n ? ", " : "", what));
        };
        if (s.blocked) add("blocked");
        if (!s.p10) add("no field held");
        else if (!s.p10Alive) add("held field dead");
        if (!s.actorFlag) add("actor flag 0");
        if (!n) add("refused for none of the four");
        snprintf(out, cap, "%s", buf);
    }

    void Describe(const Sample& s, char* out, unsigned cap)
    {
        char p10[80], p50[80], actor[80], c68[80], c1a0[80], c540[80], why[128], from[64];
        Name(s.p10, p10, sizeof p10);
        Name(s.p50, p50, sizeof p50);
        Name(s.actor, actor, sizeof actor);
        Name(s.c68, c68, sizeof c68);
        Name(s.c1a0, c1a0, sizeof c1a0);
        Name(s.c540, c540, sizeof c540);
        Why(s, why, sizeof why);
        Where(s.caller, from, sizeof from);
        snprintf(out, cap,
                 "ok=%d (%s) blocked=%u holds=%u field=%s alive=%u p50=%s actor=%s@0x%llX flag=%u "
                 "chain +0x68=%s +0x1a0=%s +0x540=%s sub=0x%llX result=<%s> from %s",
                 s.ok ? 1 : 0, why, s.blocked, s.holds, p10, s.p10Alive, p50, actor,
                 static_cast<unsigned long long>(s.actor), s.actorFlag, c68, c1a0, c540,
                 static_cast<unsigned long long>(s.sub), s.resultType ? s.resultType : "?", from);
    }

    uintptr_t CallTargetIn(uintptr_t rva, unsigned span, uintptr_t* retAt)
    {
        uint8_t b[128];
        if (span > sizeof b) span = sizeof b;
        if (!bp::mem::ReadBytes(bp::mem::Game().base + rva, b, span)) return 0;
        for (unsigned i = 0; i + 5 <= span; ++i)
        {
            if (b[i] != 0xE8) continue;
            int32_t rel = 0;
            memcpy(&rel, b + i + 1, 4);
            const uintptr_t t = rva + i + 5 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
            if (t < bp::mem::Game().size)
            {
                if (retAt) *retAt = rva + i + 5;
                return t;
            }
        }
        return 0;
    }

    bool Install(uintptr_t wrapperRva, unsigned lines, uintptr_t gateRva, const char* traceClass)
    {
        InitializeCriticalSection(&g_lock);
        if (lines) g_lossLines = g_lossCap = static_cast<LONG>(lines);
        if (traceClass) strncpy(g_traceClass, traceClass, sizeof g_traceClass - 1);
        uintptr_t retAt = 0;
        const uintptr_t target = CallTargetIn(wrapperRva, 0x40, &retAt);
        if (!target)
        {
            LOG_ERR("[hold] no call in the first 0x40 bytes of +0x%llX, so the hold acquirer is not hooked",
                    static_cast<unsigned long long>(wrapperRva));
            return false;
        }
        const uintptr_t start = bp::resolve::FunctionStart(target);
        if (start != target)
        {
            LOG_ERR("[hold] +0x%llX calls +0x%llX, which is not the start of a function (that is +0x%llX), "
                    "so the hold acquirer is not hooked", static_cast<unsigned long long>(wrapperRva),
                    static_cast<unsigned long long>(target), static_cast<unsigned long long>(start));
            return false;
        }
        g_wrapperRet = bp::mem::Game().base + retAt;

        if (gateRva)
        {
            DWORD64 imgBase = 0;
            RUNTIME_FUNCTION* fe = RtlLookupFunctionEntry(bp::mem::Game().base + gateRva, &imgBase, nullptr);
            if (fe) { g_gateLo = fe->BeginAddress; g_gateHi = fe->EndAddress; }
            else LOG("[hold] no unwind entry for the handler at +0x%llX, so requests will not be told apart "
                     "from the rest", static_cast<unsigned long long>(gateRva));
        }

        char why[160] = "";
        if (!bp::farhook::Install("holdwatch", bp::mem::Game().base + target,
                                  reinterpret_cast<void*>(&Detour), reinterpret_cast<void**>(&g_orig),
                                  why, sizeof why))
        {
            LOG_ERR("[hold] could not hook +0x%llX: %s", static_cast<unsigned long long>(target), why);
            return false;
        }
        LOG_OK("[hold] hooked the hold acquirer at +0x%llX (the call at +0x%llX inside the wrapper). Every "
               "refusal of a call from inside +0x%llX..+0x%llX is written, with dumps and an unwind; otherwise "
               "one line per sub-object's first sight, per plain change, and two per hold lost or got back, "
               "with the sample before it. %s.",
               static_cast<unsigned long long>(target), static_cast<unsigned long long>(retAt - 5),
               static_cast<unsigned long long>(g_gateLo), static_cast<unsigned long long>(g_gateHi),
               lines ? "Losses are capped by HoldLines" : "Nothing is capped");
        LOG("[hold] every call about an actor a site has marked%s%s%s is written with its caller; from inside the "
            "handler it gets the dumps, and a hold it loses or gets back gets an unwind",
            g_traceClass[0] ? ", or whose class name contains \"" : "", g_traceClass, g_traceClass[0] ? "\"" : "");
        return true;
    }

    void Summarise()
    {
        Refill(&g_lossLines, g_lossCap);
        Refill(&g_changeLines, g_changeCap);
        Refill(&g_firstLines, g_firstCap);
        Refill(&g_requestLines, g_requestCap);
        Refill(&g_dumpsLeft, g_dumpCap);
        Refill(&g_refusedDumpsLeft, g_refusedDumpCap);
        const LONG calls = InterlockedCompareExchange(&g_calls, 0, 0);
        const LONG refused = InterlockedCompareExchange(&g_refused, 0, 0);
        if (calls == g_reportedCalls && refused == g_reportedRefused) return;
        int subs = 0;
        EnterCriticalSection(&g_lock);
        subs = g_nSlots;
        LeaveCriticalSection(&g_lock);
        LOG("[hold] %ld calls (+%ld since last), %ld refused, %d sub-objects seen, %ld changes, %ld holds lost, "
            "%ld from the field-move handler of which %ld refused, %ld on traced actors", calls,
            calls - g_reportedCalls, refused, subs,
            InterlockedCompareExchange(&g_changes, 0, 0), InterlockedCompareExchange(&g_losses, 0, 0),
            InterlockedCompareExchange(&g_requests, 0, 0), InterlockedCompareExchange(&g_requestsRefused, 0, 0),
            InterlockedCompareExchange(&g_tracedCalls, 0, 0));
        g_reportedCalls = calls;
        g_reportedRefused = refused;
    }
}
