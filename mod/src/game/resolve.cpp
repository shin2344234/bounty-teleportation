#include "game/resolve.h"

#include <Windows.h>
#include <cstdio>
#include <cstring>

#include "core/log.h"
#include "game/mem.h"

namespace
{
    constexpr int kMaxSpans = 64;

    struct Span { uintptr_t lo, hi; bool exec; };

    // Committed, readable spans of the game image. The exe is packed and its
    // sections are not contiguous in memory, so a flat base..base+size walk
    // runs into uncommitted pages. mem.cpp keeps its own copy of this for
    // pattern scanning; this one also records which spans are executable, so a
    // search for an instruction never reads data.
    int Spans(Span* out, int max)
    {
        const uintptr_t base = bp::mem::Game().base;
        const uintptr_t end  = base + bp::mem::Game().size;
        if (!base) return 0;
        int n = 0;
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t a = base;
        while (a < end && n < max && VirtualQuery(reinterpret_cast<LPCVOID>(a), &mbi, sizeof mbi) == sizeof mbi)
        {
            const uintptr_t rlo = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t rhi = rlo + mbi.RegionSize;
            const DWORD prot = mbi.Protect & 0xFF;
            const bool readable = mbi.State == MEM_COMMIT && prot != PAGE_NOACCESS && !(mbi.Protect & PAGE_GUARD);
            if (readable)
            {
                const bool exec = (prot == PAGE_EXECUTE) || (prot == PAGE_EXECUTE_READ) ||
                                  (prot == PAGE_EXECUTE_READWRITE) || (prot == PAGE_EXECUTE_WRITECOPY);
                const uintptr_t lo = rlo < base ? base : rlo;
                const uintptr_t hi = rhi > end ? end : rhi;
                // Merge with the previous span when they touch and agree.
                if (n && out[n - 1].hi == lo && out[n - 1].exec == exec) out[n - 1].hi = hi;
                else { out[n].lo = lo; out[n].hi = hi; out[n].exec = exec; ++n; }
            }
            a = rhi > a ? rhi : a + 0x1000;
        }
        return n;
    }

    inline int32_t Disp32(const uint8_t* p) { int32_t v; memcpy(&v, p, 4); return v; }

    // lea reg,[rip+disp32]: an optional REX, 8D, and a modrm with mod=00 rm=101.
    bool IsRipLea(const uint8_t* b)
    {
        return b[0] >= 0x40 && b[0] <= 0x4F && b[1] == 0x8D && (b[2] & 0xC7) == 0x05;
    }
    uintptr_t RipLeaTarget(uintptr_t at) { return at + 7 + Disp32(reinterpret_cast<const uint8_t*>(at) + 3); }
}

namespace bp::resolve
{
    uintptr_t ErrorGlobal(const char* errName, int* leas)
    {
        if (leas) *leas = 0;
        const uintptr_t base = mem::Game().base;
        if (!base || !errName || !*errName) return 0;

        const size_t len = strlen(errName);
        Span sp[kMaxSpans];
        const int ns = Spans(sp, kMaxSpans);

        // The name, NUL-terminated and preceded by a NUL. These sit in one flat
        // run of name, then a description, then the next name, with no index, so
        // the leading NUL is what separates a name from the description before it.
        uintptr_t str = 0;
        for (int i = 0; i < ns && !str; ++i)
        {
            if (sp[i].exec) continue;
            for (uintptr_t p = sp[i].lo + 1; p + len + 1 < sp[i].hi; ++p)
            {
                if (*reinterpret_cast<const uint8_t*>(p - 1) != 0) continue;
                if (memcmp(reinterpret_cast<const void*>(p), errName, len + 1) != 0) continue;
                str = p;
                break;
            }
        }
        if (!str)
        {
            LOG_ERR("[resolve] the name %s is not in this image", errName);
            return 0;
        }

        // Every lea whose target is that string.
        uintptr_t hit[8];
        int n = 0;
        for (int i = 0; i < ns; ++i)
        {
            if (!sp[i].exec) continue;
            for (uintptr_t p = sp[i].lo; p + 7 < sp[i].hi; ++p)
            {
                if (!IsRipLea(reinterpret_cast<const uint8_t*>(p))) continue;
                if (RipLeaTarget(p) != str) continue;
                if (n < 8) hit[n] = p;
                ++n;
            }
        }
        if (leas) *leas = n;
        if (!n)
        {
            LOG_ERR("[resolve] %s: nothing points at the name, so it is never registered on this build", errName);
            return 0;
        }

        // The blob is emitted twice and only one copy carries the 0x1C
        // predecessor that A2's derivation reads. A lea without one is not an
        // error, it is the other copy: skip it. What would be an error is two
        // that both derive and disagree.
        uintptr_t derived = 0;
        int usable = 0;
        for (int k = 0; k < n && k < 8; ++k)
        {
            const uintptr_t zl = hit[k] - 0x1C;
            if (!IsRipLea(reinterpret_cast<const uint8_t*>(zl))) continue;
            const uintptr_t g = RipLeaTarget(zl);
            ++usable;
            if (!derived) derived = g;
            else if (g != derived)
            {
                LOG_ERR("[resolve] %s: two leas derive different globals (+0x%llX and +0x%llX); not guessing",
                        errName, static_cast<unsigned long long>(mem::Rva(derived)),
                        static_cast<unsigned long long>(mem::Rva(g)));
                return 0;
            }
        }
        if (!usable)
        {
            LOG_ERR("[resolve] %s: %d leas point at the name and none has a lea 0x1C before it, so the "
                    "registration blob has changed shape", errName, n);
            return 0;
        }
        return mem::Rva(derived);
    }

    int Readers(uintptr_t globalRva, uintptr_t* out, int max, int* total)
    {
        if (total) *total = 0;
        const uintptr_t base = mem::Game().base;
        if (!base || !globalRva || !out || max <= 0) return 0;
        const uintptr_t target = base + globalRva;

        Span sp[kMaxSpans];
        const int ns = Spans(sp, kMaxSpans);
        int n = 0, written = 0;
        for (int i = 0; i < ns; ++i)
        {
            if (!sp[i].exec) continue;
            for (uintptr_t p = sp[i].lo; p + 8 < sp[i].hi; ++p)
            {
                const uint8_t* b = reinterpret_cast<const uint8_t*>(p);
                unsigned len = 0;
                // mov r32,[rip+disp32], with and without a REX prefix.
                if (b[0] == 0x8B && (b[1] & 0xC7) == 0x05) len = 6;
                else if (b[0] >= 0x40 && b[0] <= 0x4F && b[1] == 0x8B && (b[2] & 0xC7) == 0x05) len = 7;
                else continue;
                if (p + len + Disp32(b + len - 4) != target) continue;
                // A mov-from-rip is six bytes at its shortest, so two real
                // readers are never adjacent. When they look adjacent, the
                // earlier hit matched a REX prefix that belongs to whatever
                // came before: the jne at the gate ends in 0x4E, which reads
                // as one. The later address is the instruction.
                const uintptr_t rva = mem::Rva(p);
                if (written && out[written - 1] == rva - 1) { out[written - 1] = rva; continue; }
                ++n;
                if (written < max) out[written++] = rva;
            }
        }
        if (total) *total = n;
        return written;
    }

    const char* SectionOf(uintptr_t rva)
    {
        const uintptr_t base = mem::Game().base;
        if (!base || !rva) return "?";
        static char name[12];
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return "?";
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return "?";
        const IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s)
        {
            const DWORD vs = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
            if (rva < s->VirtualAddress || rva >= s->VirtualAddress + vs) continue;
            memcpy(name, s->Name, 8);
            name[8] = 0;
            return name;
        }
        return "?";
    }

    uintptr_t FunctionStart(uintptr_t codeRva)
    {
        const uintptr_t base = mem::Game().base;
        if (!base || !codeRva) return 0;
        DWORD64 imgBase = 0;
        RUNTIME_FUNCTION* fe = RtlLookupFunctionEntry(base + codeRva, &imgBase, nullptr);
        if (!fe || !imgBase) return 0;
        return static_cast<uintptr_t>(fe->BeginAddress);
    }

    int Callers(uintptr_t funcRva, uintptr_t* outCallSites, int max)
    {
        const uintptr_t base = mem::Game().base;
        if (!base || !funcRva) return 0;
        const uintptr_t target = base + funcRva;
        Span sp[kMaxSpans];
        const int ns = Spans(sp, kMaxSpans);
        int n = 0, written = 0;
        for (int i = 0; i < ns; ++i)
        {
            if (!sp[i].exec) continue;
            for (uintptr_t p = sp[i].lo; p + 5 < sp[i].hi; ++p)
            {
                const uint8_t op = *reinterpret_cast<const uint8_t*>(p);
                if (op != 0xE8 && op != 0xE9) continue;
                if (p + 5 + Disp32(reinterpret_cast<const uint8_t*>(p + 1)) != target) continue;
                if (written < max && outCallSites) outCallSites[written++] = mem::Rva(p);
                ++n;
            }
        }
        return n;
    }

    uintptr_t LastCallBefore(uintptr_t fromRva, uintptr_t beforeRva)
    {
        const uintptr_t base = mem::Game().base;
        if (!base || !fromRva || beforeRva <= fromRva) return 0;
        // The predicate is at the top of the gate or it is not this predicate.
        if (beforeRva - fromRva > 0x400) return 0;
        uintptr_t best = 0;
        for (uintptr_t p = base + fromRva; p + 5 <= base + beforeRva; ++p)
        {
            if (*reinterpret_cast<const uint8_t*>(p) != 0xE8) continue;
            const uintptr_t t = p + 5 + Disp32(reinterpret_cast<const uint8_t*>(p + 1));
            if (!mem::InImage(t)) continue;
            best = t;
        }
        return best ? mem::Rva(best) : 0;
    }

    void HexAt(uintptr_t rva, unsigned n, char* out, unsigned cap)
    {
        if (!out || !cap) return;
        out[0] = 0;
        uint8_t b[32];
        if (n > sizeof b) n = static_cast<unsigned>(sizeof b);
        if (!mem::ReadBytes(mem::Game().base + rva, b, n)) { snprintf(out, cap, "unreadable"); return; }
        unsigned o = 0;
        for (unsigned i = 0; i < n && o + 3 < cap; ++i)
            o += static_cast<unsigned>(snprintf(out + o, cap - o, "%02X ", b[i]));
        if (o) out[o - 1] = 0;
    }
}
