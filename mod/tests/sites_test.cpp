// Exercises bp::sites outside the game: hooks four functions in this very
// executable through the ini, calls them, and checks that arguments, return
// values, overrides, patches and watches all behave. Run it after any change
// to sites.cpp or farhook.cpp; a thunk that is wrong by one byte would
// otherwise cost a game session to discover.
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/log.h"
#include "core/paths.h"
#include "game/catchwatch.h"
#include "game/holdwatch.h"
#include "game/keepcarried.h"
#include "game/mem.h"
#include "game/resolve.h"
#include "game/sites.h"
#include "version.h"

// Optimisation off so the prologues spill their arguments: five-byte stores
// with no rip-relative operand, which is what farhook can steal.
#pragma optimize("", off)
__declspec(noinline) uint64_t Plain(uint64_t a, double f, uint64_t c, uint64_t d, uint64_t e, uint64_t g)
{
    volatile uint64_t s = a + c + d + e + g + static_cast<uint64_t>(f);
    if (a > 0) s += Plain(a - 1, f, c, d, e, g);   // nesting through the hook
    return s;
}
__declspec(noinline) uint64_t Forced(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = a * 3 + b + c + d;
    return s;
}
__declspec(noinline) uint64_t Skipped(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = a + b + c + d;
    return s + 1000;
}
__declspec(noinline) uint64_t WritesOut(uint32_t* out, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = b + c + d;
    *out = 0x1234;
    return s;
}
__declspec(noinline) uint64_t WritesZero(uint32_t* out, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = b + c + d;
    *out = 0;
    return s;
}
__declspec(noinline) uint64_t ReturnsMaybeNull(uint64_t a)
{
    volatile uint64_t s = a;
    return s ? 42 : 0;
}
__declspec(noinline) uint64_t ArgSwap(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = a + b * 2 + c + d;
    return s;
}
struct Marker { virtual ~Marker() {} int v = 7; };
__declspec(noinline) uint64_t Filtered(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = a + b + c + d;
    return s + 3;
}
__declspec(noinline) uint64_t Added(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = a + b + c + d;
    return s + 7;
}
__declspec(noinline) uint64_t MarkIt(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = a + b + c + d;
    return s + 5;
}
__declspec(noinline) uint64_t Watched(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = a + b + c + d;
    return s + 9;
}
// The shape of +0x2BBF2C0 and its wrapper +0x2BC4200: the acquirer writes
// its verdict at out+0x10 from a byte of the sub-object, and the wrapper's
// first call is the acquirer.
__declspec(noinline) uint64_t HoldLike(uint64_t sub, uint64_t out)
{
    volatile uint8_t* o = reinterpret_cast<volatile uint8_t*>(out);
    o[0x10] = reinterpret_cast<const uint8_t*>(sub)[0x58] ? 0 : 1;
    return out;
}
__declspec(noinline) uint64_t HoldWrap(uint64_t sub, uint64_t out)
{
    volatile uint64_t r = HoldLike(sub, out);
    return r;
}
__declspec(noinline) uint64_t Throwing(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    volatile uint64_t s = a + b + c + d;
    if (s) throw std::runtime_error("through the hook");
    return s;
}
// The shape of +0xE1478D0's answer: a byte, and the original says no.
__declspec(noinline) uint64_t HolderCheck(uint64_t comp, uint64_t key)
{
    volatile uint64_t s = comp ? 0x20 : 0;
    return s + (key ? 0 : 1);
}
#pragma optimize("", on)

static volatile uint8_t g_patchable[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

// A function whose prologue is `sub rsp,28h; call Helper; add rsp,28h; ret`,
// built in an executable page within 2 GB of Helper so the call can be a
// rel32. farhook has to relocate that call into the trampoline; several of
// the game's functions start this way.
__declspec(noinline) uint64_t Helper() { return 42; }
static uint8_t* g_relocated = nullptr;
static uint8_t* MakeRelocated()
{
    const uintptr_t anchor = reinterpret_cast<uintptr_t>(&Helper);
    uint8_t* page = nullptr;
    for (uintptr_t hint = (anchor & ~0xFFFFull) + 0x100000; hint < anchor + 0x40000000 && !page; hint += 0x100000)
        page = static_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(hint), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!page) return nullptr;
    uint8_t* p = page;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;             // sub rsp, 0x28
    *p++ = 0xE8;                                                    // call rel32
    const int32_t rel = static_cast<int32_t>(anchor - reinterpret_cast<uintptr_t>(p + 4));
    memcpy(p, &rel, 4); p += 4;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;             // add rsp, 0x28
    *p++ = 0xC3;                                                    // ret
    FlushInstructionCache(GetCurrentProcess(), page, 16);
    return page;
}
static volatile uint32_t g_watched = 0x11223344;
static uint8_t* g_builtinTarget = nullptr;

static int g_fail = 0;
static void Check(bool ok, const char* what)
{
    printf("%s  %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++g_fail;
}

static void Touch(const wchar_t* name)
{
    if (FILE* f = _wfopen(bp::Paths::File(name).c_str(), L"wb")) fclose(f);
}

static bool Exists(const wchar_t* name)
{
    return GetFileAttributesW(bp::Paths::File(name).c_str()) != INVALID_FILE_ATTRIBUTES;
}

static int CountLines(const char* needle)
{
    std::vector<std::string> lines;
    bp::Log::Snapshot(lines, 400);
    int n = 0;
    for (const auto& l : lines) if (l.find(needle) != std::string::npos) ++n;
    return n;
}

int main()
{
    bp::Paths::Init(GetModuleHandleW(nullptr));
    bp::Log::Claim(L"SitesTest");
    const uintptr_t base = bp::mem::Game().base;
    auto rva = [&](const void* p) { return reinterpret_cast<uintptr_t>(p) - base; };


    // resolve.cpp, as far as it can be reached without the game. The two steps
    // that read the game's error-registration blob are checked against the
    // recorded addresses at runtime instead, on the probe's own first lines.
    // This runs before Install so no entry has been patched yet.
    {
        const uintptr_t added = rva(reinterpret_cast<const void*>(&Added));
        Check(bp::resolve::FunctionStart(added) == added, "FunctionStart on an entry returns the entry");
        Check(bp::resolve::FunctionStart(added + 4) == added, "FunctionStart inside a body finds its start");
        Check(bp::resolve::FunctionStart(0) == 0, "FunctionStart refuses a zero rva");

        uintptr_t sites[4] = {};
        const int n = bp::resolve::Callers(added, sites, 4);
        Check(n >= 1, "Callers found the call to Added");
        Check(bp::resolve::Callers(added, nullptr, 0) == n, "Callers counts the same with nowhere to write");
        if (n >= 1)
        {
            Check(bp::resolve::LastCallBefore(sites[0], sites[0] + 5) == added,
                  "LastCallBefore reads that call's target back");
            Check(bp::resolve::LastCallBefore(sites[0], sites[0]) == 0, "LastCallBefore refuses an empty range");
            Check(bp::resolve::LastCallBefore(sites[0], sites[0] + 0x800) == 0, "LastCallBefore refuses a range past its limit");
        }

        char hex[64] = "";
        bp::resolve::HexAt(rva(const_cast<const uint8_t*>(g_patchable)), 4, hex, sizeof hex);
        Check(strcmp(hex, "01 02 03 04") == 0, "HexAt printed the bytes that are there");
    }

    g_relocated = MakeRelocated();
    Check(g_relocated != nullptr, "built a function with a call in its prologue");
    using Fn = uint64_t (*)();
    Check(g_relocated && reinterpret_cast<Fn>(g_relocated)() == 42, "that function works before hooking");

    char ini[1024];
    snprintf(ini, sizeof ini,
        "[sites]\r\n"
        "reloc = 0x%llX, lines=5, stack=1\r\n"
        "plain = 0x%llX, dump=1, lines=20, stack=4\r\n"
        "forced = 0x%llX, ret=0x2A, after=1\r\n"
        "skipped = 0x%llX, skip=0x77\r\n"
        "throwing = 0x%llX, leave=0\r\n"
        "writesout = 0x%llX, out=1\r\n"
        "argswap = 0x%llX, a2=0x100, after=1\r\n"
        "[patch]\r\n"
        "p = 0x%llX : 5A 5B\r\n"
        "[watch]\r\n"
        "w = 0x%llX, 4\r\n",
        static_cast<unsigned long long>(rva(g_relocated)),
        static_cast<unsigned long long>(rva(reinterpret_cast<const void*>(&Plain))),
        static_cast<unsigned long long>(rva(reinterpret_cast<const void*>(&Forced))),
        static_cast<unsigned long long>(rva(reinterpret_cast<const void*>(&Skipped))),
        static_cast<unsigned long long>(rva(reinterpret_cast<const void*>(&Throwing))),
        static_cast<unsigned long long>(rva(reinterpret_cast<const void*>(&WritesOut))),
        static_cast<unsigned long long>(rva(reinterpret_cast<const void*>(&ArgSwap))),
        static_cast<unsigned long long>(rva(const_cast<const uint8_t*>(g_patchable))),
        static_cast<unsigned long long>(rva(const_cast<const uint32_t*>(&g_watched))));
    {
        FILE* f = _wfopen(bp::Paths::File(BP_INI).c_str(), L"wb");
        if (!f) { printf("cannot write the ini\n"); return 2; }
        fputs(ini, f);
        fclose(f);
    }

    const bool installed = bp::sites::Install(true);
    Check(installed, "sites installed");
    Check(CountLines("hooked at") == 7, "seven sites hooked");
    Check(ArgSwap(1, 2, 3, 4) == 1 + 4 + 3 + 4, "a2= with after=1 leaves the first call alone");
    Check(ArgSwap(1, 2, 3, 4) == 1 + 0x200 + 3 + 4, "a2= replaced rdx on the second call");
    Check(CountLines("argument 2 replaced") == 1, "argument replacement logged once");
    {
        uint32_t o = 0;
        WritesOut(&o, 1, 2, 3);
        Check(o == 0x1234, "WritesOut still writes through its out-pointer");
        Check(CountLines("out arg1 -> u32 4660") == 1, "out= logged the value written through arg1");
    }
    Check(g_relocated && reinterpret_cast<Fn>(g_relocated)() == 42, "relocated call rel32 still reaches Helper through the trampoline");
    Check(CountLines("reloc call 1 returned 0x2A") == 1, "relocated site logged its return");
    Check(g_patchable[0] == 0x5A && g_patchable[1] == 0x5B && g_patchable[2] == 3, "patch applied to two bytes");
    {
        static volatile uint8_t target[4] = { 0x74, 0x75, 0x90, 0x90 };
        const uint8_t orig[2] = { 0x74, 0x75 }, repl[2] = { 0xEB, 0x75 }, wrong[2] = { 0x11, 0x22 };
        const uintptr_t r = rva(const_cast<const uint8_t*>(target));
        Check(!bp::sites::ApplyPatch("builtin", r, wrong, repl, 2) && target[0] == 0x74, "built-in patch refuses when the original bytes differ");
        Check(bp::sites::ApplyPatch("builtin", r, orig, repl, 2) && target[0] == 0xEB && target[1] == 0x75, "built-in patch writes when the original bytes match");
        Check(bp::sites::ApplyPatch("builtin", r, orig, repl, 2) && CountLines("already reads") == 1, "built-in patch is a no-op when already applied");
        Check(CountLines("not the bytes this build should have") == 1, "the refusal was logged");
        g_builtinTarget = const_cast<uint8_t*>(target);
    }
    Check(CountLines("[watch] w at") == 1, "watch logged once at install");

    // AddSite: the path the probe's own hooks take. Same machinery, address
    // passed in rather than parsed out of the ini.
    {
        const uintptr_t at = reinterpret_cast<uintptr_t>(&Added);
        Check(bp::sites::AddSite("added", at, "args=4, lines=10, dump=1, obj=0x20"), "AddSite hooked a function by address");
        Check(CountLines("added hooked at") == 1, "AddSite logged the hook the same way the ini does");
        Check(Added(1, 2, 3, 4) == 17, "the hooked function still returns its own value");
        Check(CountLines("added call 1 from") == 1, "AddSite's site logged the call");
        Check(CountLines("added call 1 returned 0x11") == 1, "AddSite's site logged the return");
        Check(!bp::sites::AddSite("nowhere", 0, "args=4"), "AddSite refuses a null target");
    }

    // only=: per-call lines only when an argument is of a named class.
    {
        Marker m;
        Check(bp::sites::AddSite("filtered", reinterpret_cast<uintptr_t>(&Filtered), "args=4, lines=10, only=Marker"),
              "only= site hooked");
        Check(Filtered(1, 2, 3, 4) == 13, "the filtered function still runs");
        Check(CountLines("filtered call 1 from") == 0 && CountLines("filtered call 1 returned") == 0,
              "a call without the class writes neither an entry nor a return line");
        Check(Filtered(1, reinterpret_cast<uint64_t>(&m), 3, 4) == 11 + reinterpret_cast<uint64_t>(&m),
              "the filtered function still runs with the marker");
        Check(CountLines("filtered call 2 from") == 1 && CountLines("filtered call 2 returned") == 1,
              "a call with the class writes both lines");
    }

    // mark= and onlymarked=: one site remembers an argument, another speaks
    // only about calls that carry it, or a component of it.
    {
        Marker m;
        struct Comp { uint64_t pad; Marker* owner; } comp{ 0, &m };
        bp::sites::ClearMarks();
        Check(bp::sites::AddSite("marker", reinterpret_cast<uintptr_t>(&MarkIt), "args=4, only=Marker, mark=2"),
              "mark= site hooked");
        Check(bp::sites::AddSite("watched", reinterpret_cast<uintptr_t>(&Watched), "args=4, onerr=1, onlymarked=1, obj=0x10, marks=0x10"),
              "onlymarked= site hooked");
        Check(Watched(1, reinterpret_cast<uint64_t>(&m), 3, 4) == 17 + reinterpret_cast<uint64_t>(&m) &&
              CountLines("watched call 1 from") == 0, "nothing is marked yet, so the watched site is quiet");
        Check(MarkIt(1, 2, 3, 4) == 15 && !bp::sites::Marked(2), "a call the only= filter rejects marks nothing");
        Check(MarkIt(1, reinterpret_cast<uint64_t>(&m), 3, 4) == 13 + reinterpret_cast<uint64_t>(&m) &&
              bp::sites::Marked(reinterpret_cast<uint64_t>(&m)), "a wanted call marks its second argument");
        Check(CountLines("marker marked 0x") == 1, "the mark was logged once");
        Watched(1, reinterpret_cast<uint64_t>(&m), 3, 4);
        Check(CountLines("watched call 2 from") == 1 && CountLines("watched call 2 returned") == 1,
              "a call carrying the marked object writes both lines, onerr or not");
        Check(CountLines("watched marked 0 0x") == 1 && bp::sites::MarkAt(0) == reinterpret_cast<uint64_t>(&m) &&
              bp::sites::MarkAt(1) == 0, "marks= dumped the one marked object after the written call");
        Watched(reinterpret_cast<uint64_t>(&comp), 2, 3, 4);
        Check(CountLines("watched call 3 from") == 1, "a component whose +8 is marked counts too");
        Check(bp::sites::Interesting(reinterpret_cast<uint64_t>(&comp)) && !bp::sites::Interesting(2),
              "Interesting follows +8 and refuses a non-pointer");
        Watched(1, 2, 3, 4);
        Check(CountLines("watched call 4 from") == 0, "an unmarked call stays quiet");
        bp::sites::ClearMarks();
        Check(!bp::sites::Marked(reinterpret_cast<uint64_t>(&m)), "ClearMarks empties the set");
    }

    // onerr: quiet until the out pointer comes back non-zero. This is what
    // every busy site runs on, so a fault here costs a whole session.
    {
        const uintptr_t nz = reinterpret_cast<uintptr_t>(&WritesOut);
        const uintptr_t z  = reinterpret_cast<uintptr_t>(&WritesZero);
        Check(bp::sites::AddSite("errsite", nz, "out=1, args=4, onerr=1, errlines=5, obj=0"), "onerr site hooked");
        Check(bp::sites::AddSite("zerosite", z, "out=1, args=4, onerr=1, errlines=5, obj=0"), "onerr site hooked on a function that writes zero");
        uint32_t o = 7;
        WritesZero(&o, 1, 2, 3);
        Check(o == 0, "WritesZero still writes zero");
        Check(CountLines("zerosite call") == 0, "a zero out value logs nothing");
        o = 0;
        WritesOut(&o, 1, 2, 3);
        Check(o == 0x1234, "WritesOut still writes through its out-pointer");
        Check(CountLines("errsite call 1 returned 4660") == 1, "a non-zero out value logs one line with the value");
        Check(CountLines("errsite call 1 returned 4660 (0x1234), called from") == 1, "that line carries the caller and the arguments");
    }

    // onnull: the same filter on the return value, for a lookup that reports
    // failure by returning nothing.
    {
        Check(bp::sites::AddSite("nullsite", reinterpret_cast<uintptr_t>(&ReturnsMaybeNull),
                                 "args=2, onnull=1, errlines=5, obj=0"), "onnull site hooked");
        Check(ReturnsMaybeNull(1) == 42, "the hooked lookup still returns its value");
        Check(CountLines("nullsite call") == 0, "a non-zero return logs nothing");
        Check(ReturnsMaybeNull(0) == 0, "the hooked lookup still returns nothing when it fails");
        Check(CountLines("nullsite call 2 returned nothing, called from") == 1, "a zero return logs one line");
    }

    const uint64_t p = Plain(2, 1.5, 3, 4, 5, 6);
    // 2+3+4+5+6+1 = 21, then 1+...=20, then 0+...=19 -> 60
    Check(p == 60, "Plain returned the right value through nested hooks");
    Check(CountLines("plain call 1 from") == 1 && CountLines("plain call 3 from") == 1, "three nested entries logged");
    Check(CountLines("plain call 3 returned") == 1 && CountLines("plain call 1 returned") == 1, "nested returns logged in order");
    Check(CountLines("1.5d") >= 1, "double argument in xmm1 logged");
    Check(CountLines("not executable memory") == 0 && CountLines("no RVA in") == 0, "no bogus entries from the ini");
    // main's call site (+0x1AEF or wherever it lands) must be the first frame,
    // and the walk must reach the CRT before leaving the image.
    Check(CountLines("[site]     +0x") >= 6, "unwind walked real frames inside the image");
    Check(CountLines("a5=0x5 a6=0x6") >= 1, "stack arguments read");
    Check(CountLines("unwind from the caller") >= 1, "caller unwind ran");

    const uint64_t f0 = Forced(1, 2, 3, 4);
    Check(f0 == 12, "ret= with after=1 leaves the first call alone");
    const uint64_t f = Forced(1, 2, 3, 4);
    Check(f == 0x2A, "ret= replaced the second call's return value");
    Check(CountLines("return value replaced with") == 1, "override logged once");

    const uint64_t s = Skipped(1, 2, 3, 4);
    Check(s == 0x77, "skip= returned without running the function");
    Check(CountLines("skipped: returning") == 1, "skip logged");

    bool caught = false;
    try { Throwing(1, 2, 3, 4); }
    catch (const std::runtime_error&) { caught = true; }
    Check(caught, "exception propagated through a leave=0 site");

    g_watched = 0x55667788;
    bp::sites::Tick();
    Check(CountLines("(changed)") == 1, "watch noticed the change");
    bp::sites::Summarise();
    Check(CountLines("plain          3 calls") == 1, "summary counted three plain calls");

    // keepcarried: the detour on the sweep's holder check, on a fake actor
    // laid out the way the check's callers reach the catch component.
    {
        static uint8_t comp[0x300] = {}, actor[0x80] = {}, table[0x100] = {}, catchc[0x60] = {};
        *reinterpret_cast<uintptr_t*>(comp + 8) = reinterpret_cast<uintptr_t>(actor);
        *reinterpret_cast<uintptr_t*>(actor + 0x68) = reinterpret_cast<uintptr_t>(table);
        *reinterpret_cast<uintptr_t*>(table + 0x70) = reinterpret_cast<uintptr_t>(catchc);
        const uint64_t c = reinterpret_cast<uint64_t>(comp);
        Check(bp::keepcarried::Hook(reinterpret_cast<uintptr_t>(&HolderCheck), false), "keepcarried hooked the holder check");
        Check(HolderCheck(c, 5) == 0x20, "an actor nobody carries gets the original answer");
        Check(CountLines("[keepcarried] kept") == 0, "and nothing is written for it");
        *reinterpret_cast<uint32_t*>(catchc + 0x28) = 0xA0100001;
        Check(HolderCheck(c, 5) == 1, "a carried actor is kept");
        Check(CountLines("[keepcarried] kept 1:") == 1 && CountLines("carried by handle 0xA0100001") == 1,
              "the kept actor was written with its carrier");
        *reinterpret_cast<uint32_t*>(catchc + 0x28) = 0;
        Check(HolderCheck(c, 5) == 0x20, "released, the original answers again");
        Check(HolderCheck(0, 5) == 0, "an unreadable component goes to the original");
        bp::keepcarried::Summarise();
        Check(CountLines("[keepcarried] 4 asked, 1 kept") == 1, "the summary counted");
    }

    // holdwatch: the sampler behind the first gate, on a fake sub-object laid
    // out the way +0x2BBF2C0 reads the real one, then the hook on a wrapper
    // that calls its acquirer the way +0x2BC4200 does.
    {
        static uint8_t actor[0x80] = {}, owner[0x10] = {}, sub[0x80] = {}, c68[0x1B0] = {}, c1a0[0x600] = {};
        *reinterpret_cast<uintptr_t*>(sub) = reinterpret_cast<uintptr_t>(owner);
        *reinterpret_cast<uintptr_t*>(owner + 8) = reinterpret_cast<uintptr_t>(actor);
        *reinterpret_cast<uintptr_t*>(actor + 0x68) = reinterpret_cast<uintptr_t>(c68);
        *reinterpret_cast<uintptr_t*>(c68 + 0x1a0) = reinterpret_cast<uintptr_t>(c1a0);
        *reinterpret_cast<uintptr_t*>(c1a0 + 0x540) = reinterpret_cast<uintptr_t>(sub);
        *reinterpret_cast<uintptr_t*>(sub + 0x10) = reinterpret_cast<uintptr_t>(actor);
        actor[0x4a] = 1;    // the "held field" is alive
        actor[0xC2] = 1;    // and the actor says yes
        sub[0x58] = 1;
        *reinterpret_cast<uint16_t*>(sub + 0x5a) = 3;

        bp::holdwatch::Sample s;
        Check(bp::holdwatch::Read(reinterpret_cast<uintptr_t>(sub), s), "sample read off the fake sub-object");
        Check(s.blocked == 1 && s.holds == 3, "blocked byte and hold count read");
        Check(s.p10Alive == 1 && s.actorFlag == 1, "alive byte and actor flag read");
        {
            char why[128];
            bp::holdwatch::Why(s, why, sizeof why);
            Check(!strcmp(why, "blocked"), "a blocked sub-object is named as such");
            bp::holdwatch::Sample u = s;
            u.blocked = 0; u.actorFlag = 0; u.p10Alive = 0;
            bp::holdwatch::Why(u, why, sizeof why);
            Check(!strcmp(why, "held field dead, actor flag 0"), "two refusals are listed together");
            u.ok = true;
            bp::holdwatch::Why(u, why, sizeof why);
            Check(!strcmp(why, "ok"), "a success is ok whatever the fields say");
        }
        Check(s.actor == reinterpret_cast<uintptr_t>(actor), "actor reached through [sub]+8");
        Check(s.c540 == reinterpret_cast<uintptr_t>(sub), "second gate chain walked to +0x540");
        bp::holdwatch::Sample t = s;
        t.holds = 99;
        Check(!bp::holdwatch::Differs(s, t), "hold count alone is not a change");
        t.c540 = 0;
        Check(bp::holdwatch::Differs(s, t), "a null +0x540 is a change");
        t = s;
        t.actorFlag = 0;
        Check(bp::holdwatch::Differs(s, t), "the actor flag flipping is a change");
        Check(!bp::holdwatch::Read(0x10, s), "an unreadable sub-object is reported");
        bp::holdwatch::Sample z;
        Check(bp::holdwatch::Read(reinterpret_cast<uintptr_t>(c1a0), z) && z.actor == 0 && z.c540 == 0,
              "an unlinked object reads as zeros past the break");

        const uintptr_t wrapRva = reinterpret_cast<uintptr_t>(&HoldWrap) - bp::mem::Game().base;
        uintptr_t retAt = 0;
        const uintptr_t acq = bp::holdwatch::CallTargetIn(wrapRva, 0x40, &retAt);
        Check(acq == reinterpret_cast<uintptr_t>(&HoldLike) - bp::mem::Game().base,
              "the wrapper's call resolves to the acquirer");
        Check(retAt > wrapRva && retAt < wrapRva + 0x40, "and the return address inside the wrapper is known");
        if (bp::holdwatch::Install(wrapRva, 4))
        {
            // Four lines in the loss budget, shared by losses and regains
            // and two lines an event, then a refill from Summarise().
            uint8_t spare[0x30] = {};
            for (int k = 0; k < 3; ++k)
            {
                c68[0x58] = 0; HoldWrap(reinterpret_cast<uint64_t>(c68), reinterpret_cast<uint64_t>(spare));
                c68[0x58] = 1; HoldWrap(reinterpret_cast<uint64_t>(c68), reinterpret_cast<uint64_t>(spare));
            }
            Check(CountLines("[hold] lost the hold at call") == 4 && CountLines("[hold] got the hold back at call") == 4,
                  "a spent loss budget writes nothing more");
            bp::holdwatch::Summarise();
            c68[0x58] = 0; HoldWrap(reinterpret_cast<uint64_t>(c68), reinterpret_cast<uint64_t>(spare));
            c68[0x58] = 1; HoldWrap(reinterpret_cast<uint64_t>(c68), reinterpret_cast<uint64_t>(spare));
            Check(CountLines("[hold] lost the hold at call 8.") == 2, "the budget refills on the mod thread's tick");
            uint8_t out[0x30] = {};
            HoldWrap(reinterpret_cast<uint64_t>(sub), reinterpret_cast<uint64_t>(out));
            Check(out[0x10] == 0, "the hooked acquirer still refuses a blocked sub-object");
            Check(CountLines("[hold] first sight at call 9: ok=0 (blocked) blocked=1 holds=3") == 1,
                  "the first call logs a first sight with the reason");
            HoldWrap(reinterpret_cast<uint64_t>(sub), reinterpret_cast<uint64_t>(out));
            Check(CountLines("[hold] first sight at call 10") == 0 && CountLines("[hold] change 1 at call 10") == 0,
                  "the same state logs nothing");
            sub[0x58] = 0;
            HoldWrap(reinterpret_cast<uint64_t>(sub), reinterpret_cast<uint64_t>(out));
            Check(out[0x10] == 1, "the hooked acquirer succeeds once unblocked");
            Check(CountLines("[hold] change 1 at call 11: ok=1 (ok) blocked=0") == 1, "the unblock logs a plain change");
            sub[0x58] = 1;
            HoldWrap(reinterpret_cast<uint64_t>(sub), reinterpret_cast<uint64_t>(out));
            Check(CountLines("[hold] lost the hold at call 12. was: ok=1 (ok)") == 1 &&
                  CountLines("[hold] lost the hold at call 12. now: ok=0 (blocked)") == 1,
                  "losing the hold logs the sample before and after");
            sub[0x58] = 0;
            HoldWrap(reinterpret_cast<uint64_t>(sub), reinterpret_cast<uint64_t>(out));
            Check(CountLines("[hold] got the hold back at call 13. now: ok=1 (ok)") == 1, "getting it back logs the same pair");
            bp::sites::Mark(reinterpret_cast<uint64_t>(actor), "test");
            HoldWrap(reinterpret_cast<uint64_t>(sub), reinterpret_cast<uint64_t>(out));
            Check(CountLines("[hold] traced actor at call 14: ok=1 (ok)") == 1, "a marked actor is written on every call");
            bp::sites::ClearMarks();
            bp::holdwatch::Summarise();
            Check(CountLines("[hold] 14 calls (+8 since last), 7 refused, 2 sub-objects seen, 1 changes, 5 holds lost, 0 from the field-move handler of which 0 refused, 1 on traced actors") == 1,
                  "summary counts calls, refusals, sub-objects, changes, losses and traced calls");
        }
        else Check(false, "holdwatch hooked the test acquirer");
    }

    bp::sites::Remove();
    Check(g_patchable[0] == 1 && g_patchable[1] == 2, "patch restored on remove");
    Check(g_builtinTarget && g_builtinTarget[0] == 0x74 && g_builtinTarget[1] == 0x75, "built-in patch restored on remove");

    // RemovePerProcessLogs deletes files, so it is checked against decoys
    // instead of trusted. Everything here is written next to this exe, which
    // is the folder Paths::Init pointed at.
    {
        const wchar_t* doomed[] = {
            L"BPTest.other-1.log", L"BPTest.other-99999.log", L"BPTest.other-x.log",
        };
        const wchar_t* spared[] = {
            L"BPTest.log", L"BPTest.01.log", L"BPTest.other.log",
            L"BPTest.other-1.txt", L"BPTestXother-1.log", L"Other.log",
        };
        for (const wchar_t* n : doomed) Touch(n);
        for (const wchar_t* n : spared) Touch(n);

        const int gone = bp::Log::RemovePerProcessLogs(L"BPTest");
        Check(gone == 3, "removed exactly the three per-process logs");
        for (const wchar_t* n : doomed) Check(!Exists(n), "per-process log deleted");
        for (const wchar_t* n : spared) Check(Exists(n), "neighbour left alone");
        Check(bp::Log::RemovePerProcessLogs(L"BPTest") == 0, "a second pass finds nothing");

        for (const wchar_t* n : spared) DeleteFileW(bp::Paths::File(n).c_str());
    }

    // catchwatch: a marked object's bytes, and every change to them.
    {
        static uint8_t comp[0x80] = {};
        bp::sites::ClearMarks();
        bp::sites::Mark(reinterpret_cast<uint64_t>(comp), "test");
        bp::catchwatch::Tick(true);
        Check(CountLines("[catchwatch] watching") == 1, "catchwatch reported the object it started watching");
        bp::catchwatch::Tick(true);
        Check(CountLines("+0x28 was") == 0, "an unchanged object writes nothing");
        *reinterpret_cast<uint32_t*>(comp + 0x28) = 0xA0100001;
        bp::catchwatch::Tick(true);
        Check(CountLines("+0x28 was 0x00000000, now 0xA0100001") == 1, "a changed dword is written with both values");
        *reinterpret_cast<uint32_t*>(comp + 0x28) = 0;
        bp::catchwatch::Tick(true);
        Check(CountLines("+0x28 was 0xA0100001, now 0x00000000") == 1, "and so is the change back");
        bp::sites::ClearMarks();
    }

    // Rotation must never empty a log it could not rename. An open handle on
    // the live file is what the game's own exit leaves behind.
    {
        const std::wstring live = bp::Paths::File(L"RotTest.log");
        FILE* held = _wfopen(live.c_str(), L"w");
        Check(held != nullptr, "made a live log for the rotation test");
        fputs("from the session that will not let go\n", held);
        fflush(held);

        Check(!bp::Log::RotateForTest(L"RotTest"), "rotation reports failure while the file is held open");
        fclose(held);

        FILE* r = _wfopen(live.c_str(), L"rb");
        char buf[64] = {};
        if (r) { fread(buf, 1, sizeof buf - 1, r); fclose(r); }
        Check(strstr(buf, "will not let go") != nullptr, "and the file it could not rename still has its lines");

        Check(bp::Log::RotateForTest(L"RotTest"), "once the handle is gone the same rotation succeeds");
        Check(Exists(L"RotTest.01.log"), "and the log is archived as .01");
        DeleteFileW(bp::Paths::File(L"RotTest.01.log").c_str());
        DeleteFileW(live.c_str());
    }

    // Log::Keep: a trial log leaves the numbered rotation. This runs last
    // because it closes the log and renames it out from under the writer.
    {
        const std::wstring keep = bp::Paths::File(L"SitesTest.keep");
        Check(GetFileAttributesW(keep.c_str()) != INVALID_FILE_ATTRIBUTES,
              "Keep wrote the sentinel when the first mark landed");

        wchar_t want[160] = L"";
        if (FILE* f = _wfopen(keep.c_str(), L"rb"))
        {
            const size_t n = fread(want, sizeof(wchar_t), 159, f);
            want[n] = 0;
            fclose(f);
        }
        Check(wcsstr(want, L"SitesTest.trial-") != nullptr && wcsstr(want, L"-pickup.log") != nullptr,
              "the sentinel names the trial file, with the reason in it");

        bp::Log::Shutdown();
        Check(Exists(want), "Shutdown renamed the log to its trial name");
        Check(!Exists(L"SitesTest.log"), "so the live name is free for the next session");
        Check(GetFileAttributesW(keep.c_str()) == INVALID_FILE_ATTRIBUTES, "and the sentinel is gone");
        DeleteFileW(bp::Paths::File(want).c_str());
    }

    std::vector<std::string> lines;
    bp::Log::Snapshot(lines, 400);
    printf("\n--- log ---\n");
    for (const auto& l : lines) printf("%s\n", l.c_str());
    printf("\n%s\n", g_fail ? "FAILED" : "ALL PASSED");
    bp::Log::Shutdown();
    return g_fail ? 1 : 0;
}
