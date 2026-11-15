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

    // keepcarried and its caller's registers. The game's check writes only
    // rax, r8, r9 and r10, and on exe 1.0.0.3663 the caller at +0xE9787A0
    // keeps r11, rcx and dl across the call and reads [r11+0x88] after it.
    // Justin's crash on 13 November 2026 was that read with r11 = -1. Both
    // the check and its caller are written here as machine code, so the
    // compiler has no say in which registers they use. This binary is built
    // with /guard:cf, which makes the detour's indirect calls go through the
    // dispatch that left r11 = -1 in the game.
    {
        static const unsigned char kCheck[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08,             // mov [rsp+8], rbx
            0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,       // mov r8d, -1
            0x45, 0x89, 0xC1,                         // mov r9d, r8d
            0x45, 0x31, 0xD2,                         // xor r10d, r10d
            0x0F, 0xB6, 0x81, 0x10, 0x02, 0x00, 0x00, // movzx eax, byte [rcx+0x210]
            0x48, 0x8B, 0x5C, 0x24, 0x08,             // mov rbx, [rsp+8]
            0xC3,                                     // ret
        };
        // void Call(check, comp, uint64_t out[5]): sets r11 and xmm5 to a
        // marker, calls check(comp, 0) and stores r11, rcx, rdx, xmm5 and
        // rax as they came back.
        static const unsigned char kCaller[] = {
            0x53,                                     // push rbx
            0x56,                                     // push rsi
            0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
            0x48, 0x89, 0xC8,                         // mov rax, rcx
            0x48, 0x89, 0xD1,                         // mov rcx, rdx
            0x4C, 0x89, 0xC3,                         // mov rbx, r8
            0x49, 0xBB, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov r11, 0x1122334455667788
            0x66, 0x49, 0x0F, 0x6E, 0xEB,             // movq xmm5, r11
            0x31, 0xD2,                               // xor edx, edx
            0xFF, 0xD0,                               // call rax
            0x4C, 0x89, 0x1B,                         // mov [rbx], r11
            0x48, 0x89, 0x4B, 0x08,                   // mov [rbx+8], rcx
            0x48, 0x89, 0x53, 0x10,                   // mov [rbx+0x10], rdx
            0x66, 0x0F, 0xD6, 0x6B, 0x18,             // movq [rbx+0x18], xmm5
            0x48, 0x89, 0x43, 0x20,                   // mov [rbx+0x20], rax
            0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
            0x5E,                                     // pop rsi
            0x5B,                                     // pop rbx
            0xC3,                                     // ret
        };
        unsigned char* page = static_cast<unsigned char*>(
            VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        memcpy(page, kCheck, sizeof kCheck);
        memcpy(page + 0x100, kCaller, sizeof kCaller);
        FlushInstructionCache(GetCurrentProcess(), page, 4096);
        using CallFn = void (*)(void* check, void* comp, uint64_t* out);
        const auto call = reinterpret_cast<CallFn>(page + 0x100);

        static uint8_t comp[0x300] = {}, actor[0x80] = {}, table[0x100] = {}, catchc[0x60] = {};
        *reinterpret_cast<uintptr_t*>(comp + 8) = reinterpret_cast<uintptr_t>(actor);
        *reinterpret_cast<uintptr_t*>(actor + 0x68) = reinterpret_cast<uintptr_t>(table);
        *reinterpret_cast<uintptr_t*>(table + 0x70) = reinterpret_cast<uintptr_t>(catchc);
        comp[0x210] = 0x33;
        const uint64_t marker = 0x1122334455667788ull;
        auto kept = [&](const uint64_t* o) {
            return o[0] == marker && o[1] == reinterpret_cast<uint64_t>(comp) && o[2] == 0 && o[3] == marker;
        };

        uint64_t out[5] = {};
        call(page, comp, out);
        Check(kept(out) && out[4] == 0x33, "the machine-code check leaves r11, rcx, rdx and xmm5 alone unhooked");

        Check(bp::keepcarried::Hook(reinterpret_cast<uintptr_t>(page), false), "keepcarried hooked the machine-code check");
        Check(CountLines("[keepcarried] the holder check is entered through a stub that keeps") == 2,
              "each hook says it goes through the register-keeping entry");
        memset(out, 0, sizeof out);
        call(page, comp, out);
        if (!kept(out))
            printf("    r11 %016llX rcx %016llX rdx %016llX xmm5 %016llX\n", static_cast<unsigned long long>(out[0]),
                   static_cast<unsigned long long>(out[1]), static_cast<unsigned long long>(out[2]),
                   static_cast<unsigned long long>(out[3]));
        Check(kept(out) && out[4] == 0x33, "hooked, the original answers and the caller's registers come back unchanged");
        Check(CountLines("[keepcarried] first call through the register-keeping entry") >= 1,
              "the first call from the machine-code caller was written");

        *reinterpret_cast<uint32_t*>(catchc + 0x28) = 0xA0100001;
        memset(out, 0, sizeof out);
        call(page, comp, out);
        Check(kept(out) && out[4] == 1, "a carried actor is kept and the registers still come back unchanged");
        *reinterpret_cast<uint32_t*>(catchc + 0x28) = 0;

        // KarlusPrime's crash on exe 1.0.0.2976 with 1.0.6 (issue 28). The
        // caller is the game's own routine, the same bytes at +0x10396BB0 on
        // 2976 and +0xE9787A0 on 3663 apart from two field offsets, trimmed
        // after its [r11+0x88] read. It keeps its argument in r11 across the
        // check, and when the answer is no it reads [rcx+0x3c0] against dl,
        // then [r11+0x88], then writes [r11+0xca]. A yes returns without
        // touching any of them, which is why the sweep's "kept 1" line was
        // the last one in his log. The gate opens when a map teleport starts
        // with something held, and from then on 1.0.6 ran its carried-actor
        // reads for every no, so r11 came back changed for every other actor
        // this routine asked about. The routine sits at page+0x200 and calls
        // the hooked check at page+0 by rel32, as the game's call does.
        {
            static const unsigned char kGameCaller[] = {
                0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
                0x80, 0xB9, 0xCA, 0x00, 0x00, 0x00, 0x00,       // cmp byte [rcx+0xca], 0
                0x4C, 0x8B, 0xD9,                               // mov r11, rcx
                0x74, 0x07,                                     // je past the early answer
                0xB0, 0x01,                                     // mov al, 1
                0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
                0xC3,                                           // ret
                0x48, 0x8B, 0x51, 0x68,                         // mov rdx, [rcx+0x68]
                0x48, 0x89, 0x5C, 0x24, 0x20,                   // mov [rsp+0x20], rbx
                0x48, 0x8B, 0x8A, 0xB0, 0x00, 0x00, 0x00,       // mov rcx, [rdx+0xb0]
                0x31, 0xD2,                                     // xor edx, edx
                0xE8, 0xD2, 0xFD, 0xFF, 0xFF,                   // call page+0, the hooked check
                0x84, 0xC0,                                     // test al, al
                0x75, 0x28,                                     // jne held
                0x38, 0x91, 0xC0, 0x03, 0x00, 0x00,             // cmp [rcx+0x3c0], dl
                0x75, 0x20,                                     // jne held
                0x49, 0x8D, 0x8B, 0x88, 0x00, 0x00, 0x00,       // lea rcx, [r11+0x88]
                0x48, 0x8B, 0x01,                               // mov rax, [rcx]
                0x0F, 0xB6, 0x40, 0x01,                         // movzx eax, byte [rax+1]
                0x41, 0xC6, 0x83, 0xCA, 0x00, 0x00, 0x00, 0x01, // mov byte [r11+0xca], 1
                0x48, 0x8B, 0x5C, 0x24, 0x20,                   // mov rbx, [rsp+0x20]
                0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
                0xC3,                                           // ret
                0x48, 0x8B, 0x5C, 0x24, 0x20,                   // held: mov rbx, [rsp+0x20]
                0x31, 0xC0,                                     // xor eax, eax
                0x48, 0x83, 0xC4, 0x28,                         // add rsp, 0x28
                0xC3,                                           // ret
            };
            memcpy(page + 0x200, kGameCaller, sizeof kGameCaller);
            FlushInstructionCache(GetCurrentProcess(), page, 4096);
            using RoutineFn = uint32_t (*)(void* self);
            const auto routine = reinterpret_cast<RoutineFn>(page + 0x200);

            // self is the routine's argument; its +0x68 table holds the
            // component at +0xb0, and its +0x88 points at a state whose
            // second byte the no path returns.
            static uint8_t self[0x100] = {}, selfTable[0x100] = {}, state[0x10] = {};
            static uint8_t gcomp[0x400] = {}, gactor[0x80] = {}, gtable[0x100] = {}, gcatch[0x60] = {};
            *reinterpret_cast<uintptr_t*>(self + 0x68) = reinterpret_cast<uintptr_t>(selfTable);
            *reinterpret_cast<uintptr_t*>(self + 0x88) = reinterpret_cast<uintptr_t>(state);
            *reinterpret_cast<uintptr_t*>(selfTable + 0xb0) = reinterpret_cast<uintptr_t>(gcomp);
            *reinterpret_cast<uintptr_t*>(gcomp + 8) = reinterpret_cast<uintptr_t>(gactor);
            *reinterpret_cast<uintptr_t*>(gactor + 0x68) = reinterpret_cast<uintptr_t>(gtable);
            *reinterpret_cast<uintptr_t*>(gtable + 0x70) = reinterpret_cast<uintptr_t>(gcatch);
            state[1] = 0x5A;
            gcomp[0x210] = 0;   // the game's own answer is no

            // One run of the routine. A changed r11 or rcx faults on the
            // reads after the call, and that comes back as a failed check
            // instead of ending the test.
            auto run = [&](uint32_t* result) -> bool {
                self[0xca] = 0;
                __try { *result = routine(self); }
                __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
                return true;
            };
            struct Gates
            {
                static bool On() { return true; }
                static bool Off() { return false; }
                static bool Refuse(uintptr_t, uint32_t) { return false; }
            };

            uint32_t r = 0;
            bp::keepcarried::SetGate(&Gates::Off);
            Check(run(&r) && r == 0x5A && self[0xca] == 1,
                  "the 2976 caller survives a no with the gate shut, as before a teleport");
            bp::keepcarried::SetGate(&Gates::On);
            Check(run(&r) && r == 0x5A && self[0xca] == 1,
                  "the 2976 caller survives a no for an actor nobody carries while a teleport's gate is open");
            *reinterpret_cast<uint32_t*>(gcatch + 0x28) = 0xA0100001;
            bp::keepcarried::SetAccept(&Gates::Refuse);
            Check(run(&r) && r == 0x5A && self[0xca] == 1,
                  "the 2976 caller survives a no for an actor someone else carries");
            bp::keepcarried::SetAccept(nullptr);
            Check(run(&r) && r == 0 && self[0xca] == 0, "the 2976 caller takes a yes for the carried actor");
            *reinterpret_cast<uint32_t*>(gcatch + 0x28) = 0;
            bp::keepcarried::SetGate(nullptr);
            Check(CountLines("[keepcarried] first call through the register-keeping entry") >= 2,
                  "the 2976 caller's first call was written as a caller of its own");
        }
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

    // Claim on a log the last session still holds open. Up to 1.0.20 its
    // error line went through Write while Claim held the log's mutex, and
    // the loading thread hung there for good. It runs on a thread here so
    // a hang is a failed check and not a test that never ends.
    {
        const std::wstring live = bp::Paths::File(L"ClaimTest.log");
        FILE* held = _wfopen(live.c_str(), L"w");
        Check(held != nullptr, "made a live log the claim cannot rename");
        if (held)
        {
            fputs("from the session that will not let go\n", held);
            fflush(held);
        }
        bp::Log::UnclaimForTest();
        const HANDLE t = CreateThread(
            nullptr, 0, [](LPVOID) -> DWORD { bp::Log::Claim(L"ClaimTest"); return 0; }, nullptr, 0, nullptr);
        const bool done = t && WaitForSingleObject(t, 10000) == WAIT_OBJECT_0;
        if (!done)
        {
            printf("FAILED: Claim did not return within 10 s on a log it could not rename\n\nFAILED\n");
            fflush(stdout);
            ExitProcess(1);
        }
        CloseHandle(t);
        Check(true, "Claim returned on a log it could not rename");
        Check(CountLines("could not be renamed after a second of trying") == 1, "and said why in the log");
        if (held) fclose(held);
        bp::Log::Shutdown();
        FILE* r = _wfopen(live.c_str(), L"rb");
        char buf[512] = {};
        if (r) { fread(buf, 1, sizeof buf - 1, r); fclose(r); }
        Check(strstr(buf, "will not let go") != nullptr && strstr(buf, "could not be renamed") != nullptr,
              "the file keeps the old session's lines with the new session's after them");
        DeleteFileW(live.c_str());
        DeleteFileW(bp::Paths::File(L"ClaimTest.01.log").c_str());
    }

    std::vector<std::string> lines;
    bp::Log::Snapshot(lines, 400);
    printf("\n--- log ---\n");
    for (const auto& l : lines) printf("%s\n", l.c_str());
    printf("\n%s\n", g_fail ? "FAILED" : "ALL PASSED");
    bp::Log::Shutdown();
    return g_fail ? 1 : 0;
}
