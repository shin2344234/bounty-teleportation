#include "finder.h"

#include <Windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>

// How each site is found. Every rule below was checked by hand against the ten
// exes under patch-baseline, from 1.0.0.2976 to 1.0.0.3576, and
// tests\finder_test.cpp checks it again on every build of the plugin.
//
// The catch tick and catch_update. The watchdog's guard, test edi,edi / jne /
// test ebx,ebx / je, is in one place in the game. Its je lands just past a
// call, and that call is to catch_update. The function the guard is in is
// the catch tick. The je has skipped 0x3E bytes on every Steam build, and
// where those exact bytes are not in one place the same guard with any
// displacement is tried, kept only where it passes every check above.
//
// The map teleport handler. It reads the player's character control
// component off the actor and calls its release through the vtable:
// mov r,[r+68] / mov r,[r+40] / mov r,[r] / call [r+slot], where the slot is
// 0x200 or 0x1F8. That shape turns up in a few functions, and the handler is
// the one that starts with either of its two known prologues. Its two
// callers are the only two calls to it.
//
// The releases. Each sits behind kTeleportGuard, with a je over its call to
// catch_update less than 0x7C bytes on. There have always been five. The
// server's is the function in the release slot of the vtable whose RTTI
// names ServerCharacterControlActorComponent, and the client's is what the
// same slot of ClientCharacterControlActorComponent's reaches: on every
// Steam build so far through one jmp, and here through any chain of up to
// kMaxHops jmps, adjustor thunks or jmps through a pointer, since another
// store's build of the same version may link that stub differently. Of the
// other three, the client state release is the one that passes reason 9 and
// skips a short block, and the last two are only named in the log.
//
// The holder check. It is the one function starting with kHolderHead, and
// the departure sweep is the one place that loads [rsi+68], [r14+30] and
// [rcx+B0] and then calls either it or a jmp to it.
//
// What is read. Every section of the image, in the pieces the caller says
// can be read. On 1.0.0.3576 the client release is the one site in the
// second code section, so dropping that section whole because part of it
// could not be read loses the client release and nothing else, and the scan
// then reports exactly what a missing jmp would. A section is scanned piece
// by piece, and every left-out piece is named in the notes.
//
// What is code. The sections the header marks executable. When that fails,
// a second pass also reads as code every piece whose pages are executable
// now or whose header says it holds code, since a protector can leave the
// header's flags behind when it unpacks.
//
// What a refused scan logs. Every region of every section with its
// protection, and a survey of every hit of every pattern above in every
// readable piece, code or not, with the bytes around it and what each check
// made of it, so one log from a build nobody here has says where each site
// went.
namespace bt::finder
{
namespace
{
    constexpr uint32_t kExec = IMAGE_SCN_MEM_EXECUTE;
    constexpr uint32_t kLiveExec = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    constexpr int kMaxSec = 1024;
    constexpr int kMaxHdr = 96;

    // One readable piece of a section. `exec` is the header's flag and what
    // the first pass reads as code. `alt` marks a piece the header does not
    // call executable but whose pages are, or whose header says it holds
    // code, which the second pass reads as code too.
    struct Sec
    {
        uint32_t va = 0, end = 0;
        bool exec = false, alt = false;
        char name[9] = {};
    };

    struct Hdr
    {
        char     name[9] = {};
        uint32_t va = 0, vsize = 0, raw = 0, chars = 0;
    };

    // The release candidates. Five on every build so far; room for a few more
    // so a new one is counted and named instead of overflowing.
    constexpr int kMaxCand = 12;
    struct Cand
    {
        uint32_t guard = 0, je = 0, call = 0, fn = 0;
        uint8_t  disp = 0;
        bool     reason9 = false;
        int      jmps = 0;                         // rel32 jmps that land on fn, for the notes
        uint32_t serverVt = 0, clientVt = 0;
        int      servers = 0, clients = 0;
        uint32_t serverSlot = 0, clientSlot = 0;   // what each vtable's release slot holds
        int      serverHops = 0, clientHops = 0;   // jmps between that and fn
    };

    struct Img
    {
        const View* v = nullptr;
        Sec      secs[kMaxSec];
        int      nsec = 0;
        Hdr      hdrs[kMaxHdr];
        int      nhdr = 0, hdrCount = 0;
        bool     wide = false;   // the second pass: `alt` pieces count as code
        uint32_t headers = 0;
        uint32_t pdata = 0, pcount = 0;
        uint32_t rsrc = 0, rsrcSize = 0;
        uint32_t size = 0;

        const Sec* SecOf(uint32_t rva, uint32_t n) const
        {
            for (int i = 0; i < nsec; ++i)
                if (rva >= secs[i].va && rva + n <= secs[i].end) return &secs[i];
            return nullptr;
        }
        const uint8_t* At(uint32_t rva, uint32_t n) const
        {
            if (static_cast<uint64_t>(rva) + n > size) return nullptr;
            if (rva + n <= headers) return v->base + rva;
            return SecOf(rva, n) ? v->base + rva : nullptr;
        }
        bool Code(const Sec& s) const { return s.exec || (wide && s.alt); }
        bool InCode(uint32_t rva) const
        {
            const Sec* s = SecOf(rva, 1);
            return s && Code(*s);
        }
        bool U32(uint32_t rva, uint32_t* out) const
        {
            const uint8_t* p = At(rva, 4);
            if (!p) return false;
            memcpy(out, p, 4);
            return true;
        }
        bool U64(uint32_t rva, uint64_t* out) const
        {
            const uint8_t* p = At(rva, 8);
            if (!p) return false;
            memcpy(out, p, 8);
            return true;
        }
        // Where a rel32 E8 or E9 at `at` goes, or 0.
        uint32_t Branch(uint32_t at, uint8_t op) const
        {
            const uint8_t* p = At(at, 5);
            if (!p || p[0] != op) return 0;
            int32_t rel;
            memcpy(&rel, p + 1, 4);
            return static_cast<uint32_t>(static_cast<int64_t>(at) + 5 + rel);
        }
        bool Is(uint32_t rva, const uint8_t* bytes, uint32_t n) const
        {
            const uint8_t* p = At(rva, n);
            return p && memcmp(p, bytes, n) == 0;
        }
        // The pdata entry that holds rva: its start and end, or false.
        bool Func(uint32_t rva, uint32_t* begin, uint32_t* end) const
        {
            if (!pcount) return false;
            const uint8_t* t = At(pdata, pcount * 12);
            if (!t) return false;
            uint32_t lo = 0, hi = pcount;
            while (lo < hi)
            {
                const uint32_t mid = (lo + hi) / 2;
                uint32_t b;
                memcpy(&b, t + mid * 12, 4);
                if (b <= rva) lo = mid + 1; else hi = mid;
            }
            if (!lo) return false;
            uint32_t b, e;
            memcpy(&b, t + (lo - 1) * 12, 4);
            memcpy(&e, t + (lo - 1) * 12 + 4, 4);
            if (rva >= e) return false;
            *begin = b;
            *end = e;
            return true;
        }
        uint32_t FuncOf(uint32_t rva) const
        {
            uint32_t b = 0, e = 0;
            return Func(rva, &b, &e) ? b : 0;
        }
    };

    void Why(char* why, size_t n, const char* fmt, ...)
    {
        if (!why || !n) return;
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(why, n, fmt, ap);
        va_end(ap);
    }

    void Note(const View& v, const char* fmt, ...)
    {
        if (!v.note) return;
        char line[2048];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(line, sizeof line, fmt, ap);
        va_end(ap);
        v.note(line);
    }

    bool Parse(const View& v, Img* im, char* why, size_t whyLen)
    {
        im->v = &v;
        if (!v.base || v.size < 0x1000)
        {
            Why(why, whyLen, "there is no image to read");
            return false;
        }
        const uint8_t* b = v.base;
        if (b[0] != 'M' || b[1] != 'Z')
        {
            Why(why, whyLen, "the image does not start with MZ");
            return false;
        }
        uint32_t pe;
        memcpy(&pe, b + 0x3C, 4);
        if (pe > 0x800 || memcmp(b + pe, "PE\0\0", 4) != 0)
        {
            Why(why, whyLen, "the image has no PE header");
            return false;
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(b + pe);
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            Why(why, whyLen, "the image is not 64-bit");
            return false;
        }
        im->size = nt->OptionalHeader.SizeOfImage;
        if (im->size > v.size) im->size = static_cast<uint32_t>(v.size);
        im->headers = nt->OptionalHeader.SizeOfHeaders;
        const auto& dirs = nt->OptionalHeader.DataDirectory;
        im->pdata = dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        im->pcount = dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / 12;
        im->rsrc = dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        im->rsrcSize = dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;

        // Each section in the pieces that can be read. Adjacent readable
        // pieces of one section are one Sec; an unreadable piece is named
        // and left out, and the rest of the section is still scanned.
        const auto* sh = IMAGE_FIRST_SECTION(nt);
        const int n = nt->FileHeader.NumberOfSections;
        im->hdrCount = n;
        for (int i = 0; i < n; ++i)
        {
            const uint32_t va = sh[i].VirtualAddress;
            char name[9] = {};
            for (int k = 0; k < 8 && sh[i].Name[k]; ++k)
            {
                const char ch = static_cast<char>(sh[i].Name[k]);
                name[k] = ch >= 0x20 && ch < 0x7F ? ch : '?';
            }
            if (im->nhdr < kMaxHdr)
            {
                Hdr& h = im->hdrs[im->nhdr++];
                memcpy(h.name, name, sizeof name);
                h.va = va;
                h.vsize = sh[i].Misc.VirtualSize;
                h.raw = sh[i].SizeOfRawData;
                h.chars = sh[i].Characteristics;
            }
            uint32_t len = sh[i].Misc.VirtualSize > sh[i].SizeOfRawData ? sh[i].Misc.VirtualSize
                                                                         : sh[i].SizeOfRawData;
            if (va >= im->size || !len) continue;
            if (va + len > im->size) len = im->size - va;
            const bool exec = (sh[i].Characteristics & kExec) != 0;
            const bool cntCode = (sh[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0;
            uint32_t o = 0;
            while (o < len)
            {
                size_t run = len - o;
                bool readable = true;
                uint32_t protect = 0;
                if (v.runs)
                {
                    run = v.runs(b + va + o, len - o, &readable, &protect);
                    if (!run)
                    {
                        run = len - o;
                        readable = false;
                    }
                }
                if (run > len - o) run = len - o;
                const bool alt = !exec && (cntCode || (protect & kLiveExec) != 0);
                const uint32_t at = va + o, to = va + o + static_cast<uint32_t>(run);
                if (!readable)
                    Note(v, "+0x%X..+0x%X of %s cannot be read and is left out of the scan", at, to, name);
                else if (im->nsec && im->secs[im->nsec - 1].end == at && im->secs[im->nsec - 1].exec == exec &&
                         im->secs[im->nsec - 1].alt == alt && strcmp(im->secs[im->nsec - 1].name, name) == 0)
                    im->secs[im->nsec - 1].end = to;
                else if (im->nsec < kMaxSec)
                {
                    Sec& s = im->secs[im->nsec++];
                    s.va = at;
                    s.end = to;
                    s.exec = exec;
                    s.alt = alt;
                    memcpy(s.name, name, sizeof name);
                }
                else
                    Note(v, "+0x%X..+0x%X of %s is left out: the image is in more readable pieces than this keeps",
                         at, to, name);
                o += static_cast<uint32_t>(run);
            }
        }
        if (!im->pcount || !im->At(im->pdata, im->pcount * 12))
        {
            Why(why, whyLen, "the image's function table cannot be read");
            return false;
        }
        return true;
    }

    void ProtText(uint32_t p, char* out, size_t n)
    {
        if (!p)
        {
            snprintf(out, n, "not committed");
            return;
        }
        const char* base = "other";
        switch (p & 0xFF)
        {
        case PAGE_NOACCESS: base = "no access"; break;
        case PAGE_READONLY: base = "read"; break;
        case PAGE_READWRITE: base = "read/write"; break;
        case PAGE_WRITECOPY: base = "read/copy-on-write"; break;
        case PAGE_EXECUTE: base = "execute only"; break;
        case PAGE_EXECUTE_READ: base = "execute/read"; break;
        case PAGE_EXECUTE_READWRITE: base = "execute/read/write"; break;
        case PAGE_EXECUTE_WRITECOPY: base = "execute/read/copy-on-write"; break;
        }
        snprintf(out, n, "%s%s%s (0x%X)", base, (p & PAGE_GUARD) ? ", guard" : "", (p & PAGE_NOCACHE) ? ", no cache" : "",
                 p);
    }

    // The section table as the header has it, on every scan.
    void NoteHeaders(const Img& im)
    {
        const View& v = *im.v;
        Note(v, "the image is %u bytes with %d sections, headers 0x%X bytes, function table +0x%X with %u entries",
             im.size, im.hdrCount, im.headers, im.pdata, im.pcount);
        for (int i = 0; i < im.nhdr; ++i)
        {
            const Hdr& h = im.hdrs[i];
            const uint32_t c = h.chars;
            Note(v, "section %d %s: +0x%X, 0x%X bytes in memory, 0x%X in the file, characteristics 0x%08X (%s%s%s%s%s%s%s)",
                 i + 1, h.name, h.va, h.vsize, h.raw, c, (c & IMAGE_SCN_CNT_CODE) ? "code " : "",
                 (c & IMAGE_SCN_CNT_INITIALIZED_DATA) ? "data " : "",
                 (c & IMAGE_SCN_CNT_UNINITIALIZED_DATA) ? "bss " : "", (c & IMAGE_SCN_MEM_EXECUTE) ? "execute " : "",
                 (c & IMAGE_SCN_MEM_READ) ? "read " : "", (c & IMAGE_SCN_MEM_WRITE) ? "write " : "",
                 (c & IMAGE_SCN_MEM_DISCARDABLE) ? "discardable" : "");
        }
        if (im.nhdr < im.hdrCount)
            Note(v, "sections %d to %d are not listed, past what this keeps", im.nhdr + 1, im.hdrCount);
    }

    // Every region of every section as the pages are now, with whether it
    // was scanned and as what. Asks the caller again, so a refused scan
    // names each protection change without the scan keeping them all.
    void NoteSections(const Img& im)
    {
        const View& v = *im.v;
        for (int i = 0; i < im.nhdr; ++i)
        {
            const Hdr& h = im.hdrs[i];
            uint32_t len = h.vsize > h.raw ? h.vsize : h.raw;
            if (h.va >= im.size || !len) continue;
            if (h.va + len > im.size) len = im.size - h.va;
            const bool exec = (h.chars & kExec) != 0;
            uint32_t o = 0;
            while (o < len)
            {
                size_t run = len - o;
                bool readable = true;
                uint32_t protect = 0;
                if (v.runs)
                {
                    run = v.runs(v.base + h.va + o, len - o, &readable, &protect);
                    if (!run)
                    {
                        run = len - o;
                        readable = false;
                    }
                }
                if (run > len - o) run = len - o;
                const uint32_t at = h.va + o, to = h.va + o + static_cast<uint32_t>(run);
                char pt[64];
                if (v.runs) ProtText(protect, pt, sizeof pt);
                else snprintf(pt, sizeof pt, "a file copy");
                const Sec* s = im.SecOf(at, 1);
                const char* as = !readable ? "left out, unreadable"
                                 : !s ? "left out"
                                 : s->exec ? "scanned as code"
                                 : s->alt ? (im.wide ? "scanned as code on the second pass" : "scanned as data, code on a second pass")
                                 : "scanned as data";
                Note(v, "%s +0x%X..+0x%X, 0x%X bytes: %s, %s", h.name, at, to, to - at, pt, as);
                o += static_cast<uint32_t>(run);
            }
        }
    }

    // Every rva in an executable section where `n` bytes equal `pat`, up to
    // `max` of them; returns how many there were in all.
    int FindAll(const Img& im, const uint8_t* pat, uint32_t n, uint32_t* out, int max)
    {
        int hits = 0;
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            if (!im.Code(s) || s.end - s.va < n) continue;
            const uint8_t* p = im.v->base + s.va;
            const uint8_t* end = im.v->base + s.end - n + 1;
            while (p < end)
            {
                p = static_cast<const uint8_t*>(memchr(p, pat[0], end - p));
                if (!p) break;
                if (memcmp(p, pat, n) == 0)
                {
                    if (hits < max) out[hits] = static_cast<uint32_t>(p - im.v->base);
                    ++hits;
                }
                ++p;
            }
        }
        return hits;
    }

    // The release call through the vtable in the teleport handler:
    // [48-4F] 8B [40-7F] 68 / [48-4F] 8B [40-7F] 40 / [48-4F] 8B [00-3F] /
    // FF [90-97] then a slot of 0x200 or 0x1F8.
    bool IsSlotCall(const uint8_t* p, uint32_t* slot)
    {
        if ((p[0] & 0xF8) != 0x48 || p[1] != 0x8B || (p[2] & 0xC0) != 0x40 || p[3] != 0x68) return false;
        if ((p[4] & 0xF8) != 0x48 || p[5] != 0x8B || (p[6] & 0xC0) != 0x40 || p[7] != 0x40) return false;
        if ((p[8] & 0xF8) != 0x48 || p[9] != 0x8B || (p[10] & 0xC0) != 0x00) return false;
        if (p[11] != 0xFF || (p[12] & 0xF8) != 0x90 || p[15] != 0 || p[16] != 0) return false;
        if (p[13] == 0x00 && p[14] == 0x02) { *slot = 0x200; return true; }
        if (p[13] == 0xF8 && p[14] == 0x01) { *slot = 0x1F8; return true; }
        return false;
    }

    // One pass over the code for every rel32 E8 or E9 that lands on one of
    // `targets`. counts[i] is how many did, and first[i] and second[i] the
    // first two found, in address order.
    void Branches(const Img& im, uint8_t op, const uint32_t* targets, int nt, int* counts, uint32_t* first,
                  uint32_t* second)
    {
        for (int k = 0; k < nt; ++k) { counts[k] = 0; first[k] = 0; second[k] = 0; }
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            if (!im.Code(s) || s.end - s.va < 5) continue;
            const uint8_t* base = im.v->base;
            const uint8_t* p = base + s.va;
            const uint8_t* end = base + s.end - 4;
            while (p < end)
            {
                p = static_cast<const uint8_t*>(memchr(p, op, end - p));
                if (!p) break;
                int32_t rel;
                memcpy(&rel, p + 1, 4);
                const uint32_t at = static_cast<uint32_t>(p - base);
                const uint32_t to = static_cast<uint32_t>(static_cast<int64_t>(at) + 5 + rel);
                for (int k = 0; k < nt; ++k)
                    if (to == targets[k])
                    {
                        if (counts[k] == 0) first[k] = at;
                        if (counts[k] == 1) second[k] = at;
                        ++counts[k];
                    }
                ++p;
            }
        }
    }

    // The RTTI name of the class whose vtable starts at rva, or nullptr, and
    // the vtable's offset in that class: 0 for the one the object starts with.
    const char* RttiName(const Img& im, uint32_t vt, uint32_t* offset = nullptr)
    {
        uint64_t col = 0;
        if (vt < 8 || !im.U64(vt - 8, &col)) return nullptr;
        if (col < im.v->loadedAt || col - im.v->loadedAt >= im.size) return nullptr;
        const uint32_t c = static_cast<uint32_t>(col - im.v->loadedAt);
        uint32_t sig = 0, td = 0;
        if (!im.U32(c, &sig) || sig != 1 || !im.U32(c + 12, &td)) return nullptr;
        if (offset && !im.U32(c + 4, offset)) return nullptr;
        const uint8_t* name = im.At(td + 0x10, 64);
        if (!name || name[0] != '.' || name[1] != '?') return nullptr;
        return reinterpret_cast<const char*>(name);
    }

    bool NameIs(const char* rtti, const char* cls)
    {
        if (!rtti || strncmp(rtti, ".?AV", 4) != 0) return false;
        const size_t n = strlen(cls);
        return strncmp(rtti + 4, cls, n) == 0 && rtti[4 + n] == '@';
    }

    // The class name out of ".?AVName@pa@@", for the notes.
    void ShortName(const char* rtti, char* out, size_t n)
    {
        out[0] = 0;
        if (!rtti || strncmp(rtti, ".?AV", 4) != 0) return;
        size_t i = 0;
        for (const char* p = rtti + 4; *p && *p != '@' && i + 1 < n; ++p) out[i++] = *p;
        out[i] = 0;
    }

    // Where a chain of up to kMaxHops jmps from rva ends, with every stop
    // after rva in hops[]. rva itself when the bytes there are no jmp.
    uint32_t Follow(const Img& im, uint32_t rva, uint32_t* hops, int* nhops)
    {
        *nhops = 0;
        uint32_t at = rva;
        for (int h = 0; h < kMaxHops; ++h)
        {
            if (!im.InCode(at)) break;
            uint8_t b[12] = {};
            size_t n = 12;
            const uint8_t* p = im.At(at, 12);
            if (!p)
            {
                p = im.At(at, 5);
                n = 5;
                if (!p) break;
            }
            memcpy(b, p, n);
            uint32_t indirect = 0;
            uint32_t next = JmpHop(b, n, at, &indirect);
            if (!next && indirect)
            {
                uint64_t q = 0;
                if (!im.U64(indirect, &q) || q < im.v->loadedAt || q - im.v->loadedAt >= im.size) break;
                next = static_cast<uint32_t>(q - im.v->loadedAt);
            }
            if (!next) break;
            hops[(*nhops)++] = next;
            at = next;
        }
        return at;
    }

    void ChainText(const uint32_t* hops, int nhops, char* out, size_t n)
    {
        out[0] = 0;
        size_t used = 0;
        for (int i = 0; i < nhops && used + 16 < n; ++i)
            used += snprintf(out + used, n - used, ", a jmp to +0x%X", hops[i]);
    }

    // Every aligned qword that reaches a candidate, straight or through jmps,
    // checked as the release slot of a CharacterControl vtable. Code sections
    // are read too, since a build laid out differently may keep a vtable in
    // one, and the RTTI check is what makes a match. Only the vtable the
    // object starts with counts, because that is the one the teleport handler
    // calls through.
    void Vtables(const Img& im, Cand* c, int nc, uint32_t slot)
    {
        uint64_t lo = ~0ull, hi = 0;
        for (int i = 0; i < im.nsec; ++i)
        {
            if (!im.Code(im.secs[i])) continue;
            const uint64_t a = im.v->loadedAt + im.secs[i].va, e = im.v->loadedAt + im.secs[i].end;
            if (a < lo) lo = a;
            if (e > hi) hi = e;
        }
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            const uint32_t from = (s.va + 7) & ~7u;
            for (uint32_t r = from; r + 8 <= s.end; r += 8)
            {
                uint64_t q;
                memcpy(&q, im.v->base + r, 8);
                if (q < lo || q >= hi || r < slot) continue;
                const uint32_t to = static_cast<uint32_t>(q - im.v->loadedAt);
                uint32_t hops[kMaxHops];
                int nh = 0;
                const uint32_t fn = Follow(im, to, hops, &nh);
                for (int k = 0; k < nc; ++k)
                {
                    if (fn != c[k].fn) continue;
                    uint32_t offset = 1;
                    const char* name = RttiName(im, r - slot, &offset);
                    if (offset != 0) continue;
                    if (NameIs(name, "ServerCharacterControlActorComponent"))
                    {
                        c[k].serverVt = r - slot;
                        c[k].serverSlot = to;
                        c[k].serverHops = nh;
                        ++c[k].servers;
                    }
                    if (NameIs(name, "ClientCharacterControlActorComponent"))
                    {
                        c[k].clientVt = r - slot;
                        c[k].clientSlot = to;
                        c[k].clientHops = nh;
                        ++c[k].clients;
                    }
                }
            }
        }
    }

    // Up to 0x100 bytes from rva as hex, 0x80 to a line, so a function the
    // patterns did not recognise can be read out of a log.
    void NoteBytes(const Img& im, uint32_t rva, uint32_t end)
    {
        uint32_t len = end > rva ? end - rva : 0x80;
        if (len > 0x100) len = 0x100;
        for (uint32_t o = 0; o < len; o += 0x80)
        {
            const uint32_t n = len - o < 0x80 ? len - o : 0x80;
            const uint8_t* p = im.At(rva + o, n);
            if (!p)
            {
                Note(*im.v, "  bytes at +0x%X cannot be read", rva + o);
                return;
            }
            char hex[0x80 * 2 + 1];
            for (uint32_t k = 0; k < n; ++k) snprintf(hex + k * 2, 3, "%02X", p[k]);
            Note(*im.v, "  +0x%X: %s", rva + o, hex);
        }
    }

    // Every vtable whose class name has CharacterControl in it, with what
    // its release slot holds and where that leads. Only for the notes of a
    // refused scan, so a log from a build nobody here has says which slot
    // holds what instead of only that none held a candidate.
    void NoteVtables(const Img& im, const Cand* c, int nc, uint32_t slot, uint32_t cu)
    {
        const View& v = *im.v;
        int shown = 0;
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            const uint32_t from = (s.va + 7) & ~7u;
            for (uint32_t r = from; r + 8 <= s.end; r += 8)
            {
                uint64_t q;
                memcpy(&q, im.v->base + r, 8);
                if (q < v.loadedAt || q - v.loadedAt >= im.size) continue;
                const uint32_t col = static_cast<uint32_t>(q - v.loadedAt);
                uint32_t sig = 0, self = 0, td = 0, offset = 0;
                if (!im.U32(col, &sig) || sig != 1 || !im.U32(col + 20, &self) || self != col) continue;
                if (!im.U32(col + 12, &td) || !im.U32(col + 4, &offset)) continue;
                const uint8_t* raw = im.At(td + 0x10, 96);
                if (!raw || raw[0] != '.' || raw[1] != '?') continue;
                char full[97];
                memcpy(full, raw, 96);
                full[96] = 0;
                if (!strstr(full, "CharacterControl")) continue;
                char cls[64];
                ShortName(full, cls, sizeof cls);
                const uint32_t vt = r + 8;
                ++shown;
                uint64_t held = 0;
                if (!im.U64(vt + slot, &held))
                {
                    Note(v, "vtable +0x%X (%s, offset %u): slot 0x%X cannot be read", vt, cls, offset, slot);
                    continue;
                }
                if (held < v.loadedAt || held - v.loadedAt >= im.size)
                {
                    Note(v, "vtable +0x%X (%s, offset %u): slot 0x%X holds 0x%llX, which is outside the image", vt,
                         cls, offset, slot, static_cast<unsigned long long>(held));
                    continue;
                }
                const uint32_t to = static_cast<uint32_t>(held - v.loadedAt);
                uint32_t hops[kMaxHops];
                int nh = 0;
                const uint32_t fn = Follow(im, to, hops, &nh);
                char chain[128];
                ChainText(hops, nh, chain, sizeof chain);
                int cand = -1;
                for (int k = 0; k < nc; ++k)
                    if (c[k].fn == fn) cand = k;
                uint32_t fb = 0, fe = 0;
                const bool listed = im.Func(fn, &fb, &fe);
                bool guardIn = false, callIn = false;
                if (listed && fe > fb && fe - fb < 0x10000)
                    for (uint32_t a = fb; a + 5 <= fe && !(guardIn && callIn); ++a)
                    {
                        if (!guardIn && a + 16 <= fe && im.Is(a, kTeleportGuard, 16)) guardIn = true;
                        if (!callIn && im.Branch(a, 0xE8) == cu) callIn = true;
                    }
                if (cand >= 0)
                    Note(v, "vtable +0x%X (%s, offset %u): slot 0x%X holds +0x%X%s, which is release candidate +0x%X", vt,
                         cls, offset, slot, to, chain, fn);
                else if (listed)
                {
                    Note(v, "vtable +0x%X (%s, offset %u): slot 0x%X holds +0x%X%s, which is in the function "
                            "+0x%X..+0x%X, no candidate; that function %s the catch check and %s catch_update",
                         vt, cls, offset, slot, to, chain, fb, fe, guardIn ? "has" : "lacks",
                         callIn ? "calls" : "never calls");
                    NoteBytes(im, fb, fe);
                }
                else
                {
                    Note(v, "vtable +0x%X (%s, offset %u): slot 0x%X holds +0x%X%s, which is in no function the image "
                            "lists and is %s the pieces scanned",
                         vt, cls, offset, slot, to, chain, im.InCode(fn) ? "inside" : "outside");
                    NoteBytes(im, fn, 0);
                }
            }
        }
        if (!shown) Note(v, "no vtable with CharacterControl in its class name was found in the data scanned");
    }

    void NoteCandidates(const Img& im, const Cand* c, int nc, uint32_t slot, uint32_t cu)
    {
        const View& v = *im.v;
        Note(v, "%d release candidates sit behind the catch check with a je over a call to catch_update +0x%X", nc, cu);
        for (int k = 0; k < nc; ++k)
        {
            Note(v, "candidate +0x%X: guard +0x%X, je +0x%X over 0x%02X, call +0x%X, reason 9 %s, %d jmp%s land on it, "
                    "in slot 0x%X of %d server and %d client CharacterControl vtable%s",
                 c[k].fn, c[k].guard, c[k].je, c[k].disp, c[k].call, c[k].reason9 ? "passed" : "not passed",
                 c[k].jmps, c[k].jmps == 1 ? "" : "s", slot, c[k].servers, c[k].clients,
                 c[k].servers + c[k].clients == 1 ? "" : "s");
            if (c[k].servers)
                Note(v, "  the server vtable +0x%X holds +0x%X there, %d jmp%s from the function", c[k].serverVt,
                     c[k].serverSlot, c[k].serverHops, c[k].serverHops == 1 ? "" : "s");
            if (c[k].clients)
                Note(v, "  the client vtable +0x%X holds +0x%X there, %d jmp%s from the function", c[k].clientVt,
                     c[k].clientSlot, c[k].clientHops, c[k].clientHops == 1 ? "" : "s");
        }
    }

    void FillRelease(Release* r, const char* label, const Cand& c)
    {
        r->label = label;
        r->at = c.je;
        r->orig[0] = 0x74;
        r->orig[1] = c.disp;
        r->repl[0] = 0xEB;
        r->repl[1] = c.disp;
        r->call = c.call;
        r->guard = c.guard;
        r->shape = kTeleportGuard;
        r->shapeLen = sizeof kTeleportGuard;
        r->vtable = 0;
        r->slotTarget = 0;
        r->thunkTo = 0;
    }

    // mov rcx,[rsi+68] / mov rdx,[r14+30] / mov rcx,[rcx+B0] / call, the
    // departure sweep's call to the holder check.
    constexpr uint8_t kSweep[16] = { 0x48, 0x8B, 0x4E, 0x68, 0x49, 0x8B, 0x56, 0x30,
                                     0x48, 0x8B, 0x89, 0xB0, 0x00, 0x00, 0x00, 0xE8 };

    // `lead`, then the bytes from `before` ahead of rva to `after` past it as
    // hex, with a | at rva. A byte that cannot be read shows as ??.
    void NoteAround(const Img& im, const char* lead, uint32_t rva, uint32_t before, uint32_t after)
    {
        char hex[0xC0 * 2 + 8];
        size_t u = 0;
        const uint32_t from = rva > before ? rva - before : 0;
        for (uint32_t a = from; a < rva + after && u + 4 < sizeof hex; ++a)
        {
            if (a == rva) hex[u++] = '|';
            const uint8_t* p = im.At(a, 1);
            if (p) u += snprintf(hex + u, sizeof hex - u, "%02X", *p);
            else
            {
                hex[u++] = '?';
                hex[u++] = '?';
            }
        }
        hex[u] = 0;
        Note(*im.v, "%s: +0x%X %s", lead, from, hex);
    }

    // Why the 8 bytes at g, shaped like the watchdog's guard, are not it, or
    // nullptr when they are, with catch_update in *cu.
    const char* WatchdogReject(const Img& im, uint32_t g, uint32_t* cu)
    {
        *cu = 0;
        const uint8_t* p = im.At(g, 8);
        if (!p) return "its bytes cannot be read";
        if (p[7] & 0x80) return "its je jumps backwards";
        const uint32_t landing = g + 8 + p[7];
        const uint32_t c = im.Branch(landing - 5, 0xE8);
        if (!c) return "its je does not land just past a call";
        if (landing - (g + 2) > 0x7F) return "the call is too far for a short jump from the guard";
        const uint32_t f = im.FuncOf(g);
        if (!f) return "it is in no function the image lists";
        if (!im.Is(f, kTickHead, sizeof kTickHead)) return "its function does not start the way the catch tick does";
        *cu = c;
        return nullptr;
    }

    // test r32,r32 / jne over the next test / test r32,r32 / je, either test
    // with a REX prefix. The offset of the je's displacement byte, or 0.
    uint32_t SelfTest(const uint8_t* p, size_t n)
    {
        size_t o = 0;
        if (o < n && (p[o] & 0xF0) == 0x40) ++o;
        if (o + 4 > n || p[o] != 0x85 || p[o + 1] < 0xC0 || p[o + 2] != 0x75) return 0;
        const size_t skip = p[o + 3];
        o += 4;
        const size_t second = o;
        if (o < n && (p[o] & 0xF0) == 0x40) ++o;
        if (o + 4 > n || p[o] != 0x85 || p[o + 1] < 0xC0 || p[o + 2] != 0x74) return 0;
        if (o + 4 - second != skip) return 0;
        return static_cast<uint32_t>(o + 3);
    }

    // Every hit of every pattern the search uses, in every readable piece,
    // code or not, with the bytes around it and what each check made of
    // it. Only for a refused scan, so one log from a build nobody here has
    // is enough to see where each site went.
    void Survey(const Img& im)
    {
        const View& v = *im.v;
        const uint8_t* base = v.base;
        Note(v, "survey: every hit of every pattern the search uses, in every readable piece, read as code or not");

        // The catch checks, and the call most of them have a je over: what
        // catch_update would be without the watchdog.
        uint32_t tgt[64] = {};
        int tally[64] = {}, ntgt = 0, guards = 0;
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            if (s.end - s.va < 16) continue;
            const uint8_t* p = base + s.va;
            const uint8_t* end = base + s.end - 15;
            while (p < end && (p = static_cast<const uint8_t*>(memchr(p, 0x83, end - p))) != nullptr)
            {
                if (memcmp(p, kTeleportGuard, 16) != 0)
                {
                    ++p;
                    continue;
                }
                const uint32_t g = static_cast<uint32_t>(p - base);
                ++guards;
                char lead[640];
                int u = snprintf(lead, sizeof lead, "catch check +0x%X in %s (%s), function +0x%X; calls within 0x7C:",
                                 g, s.name, im.Code(s) ? "code" : "not code", im.FuncOf(g));
                int calls = 0;
                for (uint32_t k = g; k < g + 0x7C; ++k)
                {
                    const uint32_t t = im.Branch(k, 0xE8);
                    if (!t) continue;
                    uint32_t je = 0;
                    for (uint32_t q = g; q < k; ++q)
                    {
                        const uint8_t* j = im.At(q, 2);
                        if (j && j[0] == 0x74 && q + 2 + j[1] == k + 5) je = q;
                    }
                    ++calls;
                    if (u > 0 && u < static_cast<int>(sizeof lead))
                        u += snprintf(lead + u, sizeof lead - u, " +0x%X to +0x%X%s", k, t,
                                      je ? " with a je over it" : "");
                    if (!je) continue;
                    int t2 = 0;
                    while (t2 < ntgt && tgt[t2] != t) ++t2;
                    if (t2 == ntgt && ntgt < 64) tgt[ntgt++] = t;
                    if (t2 < 64) ++tally[t2];
                }
                if (!calls && u > 0 && u < static_cast<int>(sizeof lead)) snprintf(lead + u, sizeof lead - u, " none");
                NoteAround(im, lead, g, 0x10, 0x90);
                ++p;
            }
        }
        uint32_t cu = 0;
        int best = 0;
        for (int k = 0; k < ntgt; ++k)
            if (tally[k] > best)
            {
                best = tally[k];
                cu = tgt[k];
            }
        Note(v, "%d catch checks; the call with a je over it behind most of them is to +0x%X, behind %d, so that is "
                "taken as catch_update below",
             guards, cu, best);

        // The rest in one pass over each piece.
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            int nSelf = 0, nExact = 0, nLoose = 0, nTick = 0, nHead = 0, nHead3392 = 0, nHead3840 = 0, nHolder = 0, nSweep = 0,
                nSlot = 0, nSlotShape = 0, nCu = 0, nCuJe = 0;
            for (uint32_t r = s.va; r < s.end; ++r)
            {
                const uint8_t* p = base + r;
                const size_t avail = s.end - r;
                const uint8_t b0 = p[0];
                if (b0 == 0x85 || (b0 & 0xF0) == 0x40)
                {
                    const uint32_t d = SelfTest(p, avail);
                    // The same pair seen from its REX prefix one byte back.
                    const bool seen = r > s.va && (p[-1] & 0xF0) == 0x40 && SelfTest(p - 1, avail + 1) != 0;
                    if (d && !seen)
                    {
                        ++nSelf;
                        const bool exact = avail >= 8 && memcmp(p, kWatchdogGuard, 8) == 0;
                        const bool loose = avail >= 8 && memcmp(p, kWatchdogGuard, 7) == 0;
                        nExact += exact;
                        nLoose += loose;
                        const uint32_t landing = r + d + 1 + p[d];
                        const uint32_t call = (p[d] & 0x80) ? 0 : im.Branch(landing - 5, 0xE8);
                        const uint32_t f = im.FuncOf(r);
                        uint32_t wcu = 0;
                        const char* rej = loose ? WatchdogReject(im, r, &wcu) : nullptr;
                        char callText[48] = "not past a call";
                        if (call) snprintf(callText, sizeof callText, "just past a call to +0x%X", call);
                        char lead[320];
                        snprintf(lead, sizeof lead,
                                 "self-test pair +0x%X in %s (%s), function +0x%X%s: je to +0x%X, %s%s; %s%s",
                                 r, s.name, im.Code(s) ? "code" : "not code", f,
                                 f && im.Is(f, kTickHead, sizeof kTickHead) ? " (starts like the catch tick)" : "",
                                 landing, callText, call && call == cu ? ", catch_update" : "",
                                 exact ? "the watchdog's exact bytes" : loose ? "the watchdog's bytes but the je displacement"
                                                                             : "other registers than the watchdog's",
                                 loose ? (rej ? ", turned down: " : ", fits") : "");
                        if (rej) strncat(lead, rej, sizeof lead - strlen(lead) - 1);
                        NoteAround(im, lead, r, 0x20, 0x40);
                    }
                }
                if (b0 == 0x48 && avail >= 27 && memcmp(p, kTickHead, sizeof kTickHead) == 0)
                {
                    ++nTick;
                    Note(v, "catch tick prologue +0x%X in %s, %s", r, s.name,
                         im.FuncOf(r) == r ? "a function starts there" : "no function starts there");
                }
                if (b0 == 0x48 && avail >= 15 && memcmp(p, kTeleportHead, sizeof kTeleportHead) == 0) ++nHead;
                if (b0 == 0x48 && avail >= 15 && memcmp(p, kTeleportHead3392, sizeof kTeleportHead3392) == 0)
                    ++nHead3392;
                if (b0 == 0x48 && avail >= 15 && memcmp(p, kTeleportHead3840, sizeof kTeleportHead3840) == 0)
                    ++nHead3840;
                if (b0 == 0x48 && avail >= 9 && memcmp(p, kHolderHead, sizeof kHolderHead) == 0)
                {
                    ++nHolder;
                    char lead[160];
                    snprintf(lead, sizeof lead, "holder check head +0x%X in %s, %s", r, s.name,
                             im.FuncOf(r) == r ? "a function starts there" : "no function starts there");
                    NoteAround(im, lead, r, 0x10, 0x30);
                }
                if (b0 == 0x48 && avail >= 20 && memcmp(p, kSweep, sizeof kSweep) == 0)
                {
                    ++nSweep;
                    const uint32_t t = im.Branch(r + 15, 0xE8);
                    const uint32_t t2 = t ? im.Branch(t, 0xE9) : 0;
                    char lead[256];
                    snprintf(lead, sizeof lead, "departure sweep +0x%X in %s, calls +0x%X%s", r, s.name, t,
                             t && im.Is(t, kHolderHead, sizeof kHolderHead) ? ", which starts like the holder check"
                             : t2 && im.Is(t2, kHolderHead, sizeof kHolderHead)
                                 ? ", a jmp to a function that starts like the holder check"
                                 : ", which does not start like the holder check");
                    NoteAround(im, lead, r, 0x10, 0x20);
                }
                if (b0 == 0xFF && avail >= 6 && (p[1] & 0xF8) == 0x90 && p[4] == 0 && p[5] == 0 &&
                    ((p[2] == 0x00 && p[3] == 0x02) || (p[2] == 0xF8 && p[3] == 0x01)))
                {
                    ++nSlot;
                    uint32_t slot = 0;
                    const bool shape = r >= s.va + 11 && avail >= 6 && IsSlotCall(p - 11, &slot);
                    nSlotShape += shape;
                    const uint32_t f = im.FuncOf(r);
                    const char* head = !f ? "in no listed function"
                                       : im.Is(f, kTeleportHead, sizeof kTeleportHead) ? "starts like the teleport handler"
                                       : im.Is(f, kTeleportHead3392, sizeof kTeleportHead3392)
                                           ? "starts like the 3392 teleport handler"
                                       : im.Is(f, kTeleportHead3840, sizeof kTeleportHead3840)
                                           ? "starts like the 3840 teleport handler"
                                           : "starts like neither teleport handler";
                    char fh[40] = "";
                    if (const uint8_t* q = f ? im.At(f, 15) : nullptr)
                        for (int k = 0; k < 15; ++k) snprintf(fh + k * 2, 3, "%02X", q[k]);
                    char lead[320];
                    snprintf(lead, sizeof lead,
                             "release-slot call +0x%X in %s (%s), slot 0x%X, %s the teleport handler's three loads, "
                             "function +0x%X %s (%s)",
                             r, s.name, im.Code(s) ? "code" : "not code", p[2] == 0 ? 0x200 : 0x1F8,
                             shape ? "after" : "without", f, head, fh);
                    NoteAround(im, lead, r, 0x18, 6);
                }
                if (b0 == 0xE8 && cu && avail >= 5 && im.Branch(r, 0xE8) == cu)
                {
                    ++nCu;
                    uint32_t je = 0;
                    for (uint32_t q = r > 0x80 ? r - 0x80 : 0; q < r; ++q)
                    {
                        const uint8_t* j = im.At(q, 2);
                        if (j && j[0] == 0x74 && q + 2 + j[1] == r + 5) je = q;
                    }
                    nCuJe += je != 0;
                    bool guarded = false;
                    for (uint32_t q = r > 0x7C ? r - 0x7C : 0; q < r && !guarded; ++q)
                        guarded = im.Is(q, kTeleportGuard, sizeof kTeleportGuard);
                    const uint32_t f = im.FuncOf(r);
                    char jeText[48] = "no short je lands past it";
                    if (je) snprintf(jeText, sizeof jeText, "a je lands past it from +0x%X", je);
                    char lead[320];
                    snprintf(lead, sizeof lead, "call to catch_update +0x%X in %s, function +0x%X%s, %s%s", r, s.name,
                             f, f && im.Is(f, kTickHead, sizeof kTickHead) ? " (starts like the catch tick)" : "",
                             jeText, guarded ? ", behind a catch check" : "");
                    NoteAround(im, lead, je ? je : r, 0x20, je ? r + 5 - je + 4 : 0x10);
                }
            }
            Note(v, "%s +0x%X..+0x%X (%s): %d self-test pairs (%d the watchdog exactly, %d but the je), %d catch tick "
                    "prologues, %d, %d and %d teleport prologues, %d holder heads, %d sweeps, %d release-slot calls (%d "
                    "with the handler's loads), %d calls to catch_update (%d with a je over them)",
                 s.name, s.va, s.end, im.Code(s) ? "code" : s.alt ? "code on a second pass" : "data", nSelf, nExact,
                 nLoose - nExact, nTick, nHead, nHead3392, nHead3840, nHolder, nSweep, nSlot, nSlotShape, nCu, nCuJe);
        }
    }

    bool FindAllSites(const Img& im, Found* out, char* why, size_t whyLen)
    {
        Build& b = out->build;

        // ---- the watchdog, catch_update and the catch tick ----
        // The exact bytes first. Where they are not in one place, the same
        // guard with any je displacement, kept only where the je lands just
        // past a call, close enough for a short jump, in a function that
        // starts the way the catch tick does. Each one tried is named.
        uint32_t hit[16];
        int n = FindAll(im, kWatchdogGuard, sizeof kWatchdogGuard, hit, 16);
        uint32_t wg = n == 1 ? hit[0] : 0;
        if (n != 1)
        {
            uint32_t loose[64];
            const int nl = FindAll(im, kWatchdogGuard, sizeof kWatchdogGuard - 1, loose, 64);
            Note(*im.v, "the watchdog's guard 85 FF 75 04 85 DB 74 3E is in %d places in the code, so any je "
                        "displacement is tried: 85 FF 75 04 85 DB 74 is in %d",
                 n, nl);
            int fits = 0;
            for (int i = 0; i < nl && i < 64; ++i)
            {
                uint32_t c = 0;
                const char* r = WatchdogReject(im, loose[i], &c);
                char lead[160];
                snprintf(lead, sizeof lead, "  +0x%X in %s, function +0x%X: %s", loose[i],
                         im.SecOf(loose[i], 1) ? im.SecOf(loose[i], 1)->name : "?", im.FuncOf(loose[i]),
                         r ? r : "fits, catch_update would be +0x");
                if (!r) snprintf(lead + strlen(lead), sizeof lead - strlen(lead), "%X", c);
                NoteAround(im, lead, loose[i], 0x20, 0x40);
                if (!r)
                {
                    ++fits;
                    wg = loose[i];
                }
            }
            if (fits != 1)
            {
                Why(why, whyLen,
                    "the watchdog's guard is in %d places as it is on Steam, and %d with any je displacement, %d of "
                    "which fit",
                    n, nl, fits);
                return false;
            }
            Note(*im.v, "the watchdog is taken at +0x%X, with a je displacement of 0x%02X", wg, im.At(wg + 7, 1)[0]);
        }
        const uint32_t landing = wg + 8 + im.At(wg + 7, 1)[0];
        const uint32_t wcall = landing - 5;
        const uint32_t cu = im.Branch(wcall, 0xE8);
        if (!cu)
        {
            Why(why, whyLen, "the watchdog's je at +0x%X does not land past a call", wg + 6);
            return false;
        }
        const uint32_t wdisp = landing - (wg + 2);
        if (wdisp > 0x7F)
        {
            Why(why, whyLen, "the watchdog's call is too far for a short jump");
            return false;
        }
        b.catchUpdate = cu;
        const uint32_t tick = im.FuncOf(wg);
        b.catchTick = tick;
        if (!tick || !im.Is(tick, kTickHead, sizeof kTickHead))
        {
            Why(why, whyLen, "the function the watchdog is in, +0x%X, does not start the way the catch tick does",
                tick);
            return false;
        }
        Release& w = b.releases[3];
        w.label = "keepcatch_watchdog";
        w.at = wg;
        w.orig[0] = 0x85;
        w.orig[1] = 0xFF;
        w.repl[0] = 0xEB;
        w.repl[1] = static_cast<uint8_t>(wdisp);
        w.call = wcall;
        w.guard = wg;
        memcpy(out->watchdog, im.At(wg, sizeof out->watchdog), sizeof out->watchdog);
        w.shape = out->watchdog;
        w.shapeLen = sizeof out->watchdog;

        // ---- the map teleport handler and the release slot ----
        uint32_t tfn = 0, tslot = 0;
        int tfns = 0;
        const uint8_t* thead = nullptr;
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            if (!im.Code(s) || s.end - s.va < 17) continue;
            for (uint32_t r = s.va; r + 17 <= s.end; ++r)
            {
                const uint8_t* p = im.v->base + r;
                if (p[1] != 0x8B || p[3] != 0x68) continue;
                uint32_t slot;
                if (!IsSlotCall(p, &slot)) continue;
                const uint32_t fn = im.FuncOf(r);
                const uint8_t* head = nullptr;
                if (fn && im.Is(fn, kTeleportHead, sizeof kTeleportHead)) head = kTeleportHead;
                else if (fn && im.Is(fn, kTeleportHead3392, sizeof kTeleportHead3392)) head = kTeleportHead3392;
                else if (fn && im.Is(fn, kTeleportHead3840, sizeof kTeleportHead3840)) head = kTeleportHead3840;
                if (!head) continue;
                if (fn == tfn && slot == tslot) continue;
                if (fn == tfn)
                {
                    Why(why, whyLen, "the teleport handler at +0x%X calls slots 0x%X and 0x%X", fn, tslot, slot);
                    return false;
                }
                tfn = fn;
                tslot = slot;
                thead = head;
                ++tfns;
            }
        }
        if (tfns != 1)
        {
            Why(why, whyLen, "%d functions look like the teleport handler, and not one", tfns);
            return false;
        }
        b.teleport = tfn;
        b.releaseSlot = tslot;
        b.teleportHead = thead;

        // ---- the holder check and the departure sweep ----
        n = FindAll(im, kHolderHead, sizeof kHolderHead, hit, 16);
        if (n != 1)
        {
            Why(why, whyLen, "the holder check's first bytes are in %d places and not one", n);
            return false;
        }
        b.holderCheck = hit[0];
        n = FindAll(im, kSweep, sizeof kSweep, hit, 16);
        if (n != 1)
        {
            Why(why, whyLen, "the departure sweep's call is in %d places and not one", n);
            return false;
        }
        b.sweepCall = hit[0] + 15;
        const uint32_t sweepTo = im.Branch(static_cast<uint32_t>(b.sweepCall), 0xE8);
        if (sweepTo == b.holderCheck)
            b.holderThunk = 0;
        else if (sweepTo && im.Branch(sweepTo, 0xE9) == b.holderCheck)
            b.holderThunk = sweepTo;
        else
        {
            Why(why, whyLen, "the departure sweep calls +0x%X, which is not the holder check or a jmp to it", sweepTo);
            return false;
        }

        // ---- the release candidates ----
        Cand c[kMaxCand];
        int nc = 0;
        uint32_t g[64];
        const int ng = FindAll(im, kTeleportGuard, sizeof kTeleportGuard, g, 64);
        if (ng > 64)
        {
            Why(why, whyLen, "the catch check is in %d places, more than this looks through", ng);
            return false;
        }
        for (int i = 0; i < ng; ++i)
        {
            uint32_t call = 0;
            for (uint32_t k = g[i]; k < g[i] + 0x7C; ++k)
                if (im.Branch(k, 0xE8) == cu) { call = k; break; }
            if (!call) continue;
            uint32_t je = 0;
            for (uint32_t k = g[i]; k < call; ++k)
            {
                const uint8_t* p = im.At(k, 2);
                if (p && p[0] == 0x74 && k + 2 + p[1] == call + 5) je = k;
            }
            if (!je) continue;
            if (nc == kMaxCand)
            {
                Why(why, whyLen, "more than %d releases sit behind the catch check", kMaxCand);
                return false;
            }
            Cand& x = c[nc++];
            x.guard = g[i];
            x.je = je;
            x.call = call;
            x.disp = im.At(je + 1, 1)[0];
            x.fn = im.FuncOf(g[i]);
            static const uint8_t kReason9[5] = { 0xC6, 0x44, 0x24, 0x20, 0x09 };
            for (uint32_t k = je + 2; k + 5 <= call && !x.reason9; ++k)
                x.reason9 = im.Is(k, kReason9, 5);
            if (!x.fn)
            {
                Why(why, whyLen, "the release at +0x%X is in no function the image lists", g[i]);
                return false;
            }
        }
        if (nc < 3)
        {
            Why(why, whyLen, "only %d releases sit behind the catch check, where there have been five", nc);
            return false;
        }

        // ---- calls to the handler, jmps to each candidate ----
        uint32_t targets[1 + kMaxCand];
        int counts[1 + kMaxCand];
        uint32_t first[1 + kMaxCand], second[1 + kMaxCand];
        targets[0] = tfn;
        Branches(im, 0xE8, targets, 1, counts, first, second);
        if (counts[0] != 2)
        {
            Why(why, whyLen, "the teleport handler at +0x%X is called from %d places and not two", tfn, counts[0]);
            return false;
        }
        b.teleportCall1 = first[0];
        b.teleportCall2 = second[0];

        for (int k = 0; k < nc; ++k) targets[k] = c[k].fn;
        Branches(im, 0xE9, targets, nc, counts, first, second);
        for (int k = 0; k < nc; ++k) c[k].jmps = counts[k];

        // ---- which is which ----
        Vtables(im, c, nc, tslot);
        int srv = -1, cli = -1;
        for (int k = 0; k < nc; ++k)
        {
            if (c[k].servers)
            {
                if (srv >= 0 || c[k].servers != 1)
                {
                    NoteCandidates(im, c, nc, tslot, cu);
                    NoteVtables(im, c, nc, tslot, cu);
                    Why(why, whyLen, "more than one server CharacterControl vtable holds a release");
                    return false;
                }
                srv = k;
            }
            if (c[k].clients)
            {
                if (cli >= 0 || c[k].clients != 1)
                {
                    NoteCandidates(im, c, nc, tslot, cu);
                    NoteVtables(im, c, nc, tslot, cu);
                    Why(why, whyLen, "more than one client CharacterControl vtable holds a release");
                    return false;
                }
                cli = k;
            }
        }
        if (srv < 0 || cli < 0 || srv == cli)
        {
            NoteCandidates(im, c, nc, tslot, cu);
            NoteVtables(im, c, nc, tslot, cu);
            if (srv >= 0 && srv == cli)
                Why(why, whyLen, "the server and client CharacterControl vtables reach the same release, +0x%X", c[srv].fn);
            else
                Why(why, whyLen,
                    "the %s CharacterControl release is in no vtable slot 0x%X, straight or through jmps; the lines "
                    "above list every candidate and what each CharacterControl vtable holds there",
                    srv < 0 ? "server" : "client", tslot);
            return false;
        }
        int state = -1;
        for (int k = 0; k < nc; ++k)
        {
            if (k == srv || k == cli || !c[k].reason9 || c[k].disp > 0x30) continue;
            if (state >= 0)
            {
                Why(why, whyLen, "two releases, in +0x%X and +0x%X, look like the client state one", c[state].fn,
                    c[k].fn);
                return false;
            }
            state = k;
        }
        if (state < 0)
        {
            Why(why, whyLen, "none of the releases looks like the client state one");
            return false;
        }

        FillRelease(&b.releases[0], "keepcatch", c[srv]);
        b.releases[0].vtable = c[srv].serverVt;
        b.releases[0].slotTarget = c[srv].serverSlot;
        b.releases[0].thunkTo = c[srv].serverSlot != c[srv].fn ? c[srv].fn : 0;
        FillRelease(&b.releases[1], "keepcatch_client", c[cli]);
        b.releases[1].vtable = c[cli].clientVt;
        b.releases[1].slotTarget = c[cli].clientSlot;
        b.releases[1].thunkTo = c[cli].clientSlot != c[cli].fn ? c[cli].fn : 0;
        FillRelease(&b.releases[2], "keepcatch_state", c[state]);

        // The rest, by function address, for the log.
        int rest[kMaxCand], nr = 0;
        for (int k = 0; k < nc; ++k)
            if (k != srv && k != cli && k != state) rest[nr++] = k;
        for (int i = 1; i < nr; ++i)
            for (int j = i; j > 0 && c[rest[j]].fn < c[rest[j - 1]].fn; --j)
            {
                const int t = rest[j];
                rest[j] = rest[j - 1];
                rest[j - 1] = t;
            }
        for (int i = 0; i < 2; ++i)
        {
            if (i < nr)
            {
                snprintf(out->other[i], sizeof out->other[i], "the release in +0x%X", c[rest[i]].fn);
                b.others[i].label = out->other[i];
                b.others[i].call = c[rest[i]].call;
            }
            else
                b.others[i] = OtherRelease{};
        }
        NoteCandidates(im, c, nc, tslot, cu);
        return true;
    }
}

uint32_t JmpHop(const uint8_t* p, size_t n, uint32_t at, uint32_t* indirect)
{
    *indirect = 0;
    if (!p) return 0;
    auto rel = [&](size_t o) -> uint32_t {
        if (o + 5 > n || p[o] != 0xE9) return 0;
        int32_t r;
        memcpy(&r, p + o + 1, 4);
        return static_cast<uint32_t>(static_cast<int64_t>(at) + o + 5 + r);
    };
    if (n >= 5 && p[0] == 0xE9) return rel(0);
    if (n >= 6 && p[0] == 0xFF && p[1] == 0x25)
    {
        int32_t d;
        memcpy(&d, p + 2, 4);
        *indirect = static_cast<uint32_t>(static_cast<int64_t>(at) + 6 + d);
        return 0;
    }
    // sub rcx,imm8 / add rcx,imm8 / lea rcx,[rcx+disp8], then the jmp.
    if (n >= 4 && p[0] == 0x48 &&
        ((p[1] == 0x83 && (p[2] == 0xE9 || p[2] == 0xC1)) || (p[1] == 0x8D && p[2] == 0x49)))
        return rel(4);
    // The same with imm32 or disp32.
    if (n >= 7 && p[0] == 0x48 &&
        ((p[1] == 0x81 && (p[2] == 0xE9 || p[2] == 0xC1)) || (p[1] == 0x8D && p[2] == 0x89)))
        return rel(7);
    return 0;
}

bool FileVersion(const View& v, char* out, size_t n)
{
    // Find parses the image again and writes the notes then, once.
    View quiet = v;
    quiet.note = nullptr;
    Img im;
    char why[8];
    if (!Parse(quiet, &im, why, sizeof why) || !im.rsrc) return false;
    // Resource directory: type, then name, then language; take RT_VERSION
    // and the first entry at each level below it.
    auto entry = [&](uint32_t dir, bool byId, uint32_t id, uint32_t* off) -> bool {
        const uint8_t* d = im.At(im.rsrc + dir, 16);
        if (!d) return false;
        uint16_t named, ids;
        memcpy(&named, d + 12, 2);
        memcpy(&ids, d + 14, 2);
        for (uint32_t i = 0; i < static_cast<uint32_t>(named) + ids; ++i)
        {
            const uint8_t* e = im.At(im.rsrc + dir + 16 + i * 8, 8);
            if (!e) return false;
            uint32_t name, to;
            memcpy(&name, e, 4);
            memcpy(&to, e + 4, 4);
            if (!byId || name == id)
            {
                *off = to;
                return true;
            }
        }
        return false;
    };
    uint32_t o = 0;
    if (!entry(0, true, 16, &o) || !(o & 0x80000000u)) return false;
    if (!entry(o & 0x7FFFFFFFu, false, 0, &o) || !(o & 0x80000000u)) return false;
    if (!entry(o & 0x7FFFFFFFu, false, 0, &o) || (o & 0x80000000u)) return false;
    uint32_t dataRva = 0, dataLen = 0;
    if (!im.U32(im.rsrc + o, &dataRva) || !im.U32(im.rsrc + o + 4, &dataLen)) return false;
    for (uint32_t k = 0; k + 52 <= dataLen; k += 4)
    {
        uint32_t sig = 0;
        if (!im.U32(dataRva + k, &sig) || sig != 0xFEEF04BDu) continue;
        uint32_t ms = 0, ls = 0;
        if (!im.U32(dataRva + k + 8, &ms) || !im.U32(dataRva + k + 12, &ls)) return false;
        snprintf(out, n, "%u.%u.%u.%u", ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF);
        return true;
    }
    return false;
}

bool Find(const View& v, Found* out, char* why, size_t whyLen)
{
    const ULONGLONG t0 = GetTickCount64();
    *out = Found{};
    Img im;
    if (!Parse(v, &im, why, whyLen)) return false;
    if (!FileVersion(v, out->name, sizeof out->name))
        snprintf(out->name, sizeof out->name, "an unlisted build");
    out->build.name = out->name;
    NoteHeaders(im);
    bool ok = FindAllSites(im, out, why, whyLen);

    // A protector may leave code in a section its header does not mark
    // executable and make the pages executable when it unpacks. Those
    // pieces, and any whose header says code, are read as code on a second
    // pass, only when the first one failed.
    int alt = 0;
    for (int i = 0; i < im.nsec; ++i) alt += im.secs[i].alt;
    if (!ok && alt)
    {
        char first[256];
        snprintf(first, sizeof first, "%s", why);
        Note(v, "the scan of the executable sections failed (%s), so it runs again with %d more piece%s read as code, "
                "whose pages are executable or whose header says code",
             first, alt, alt == 1 ? "" : "s");
        im.wide = true;
        char second[256] = "";
        char keep[sizeof out->name];
        memcpy(keep, out->name, sizeof keep);
        *out = Found{};
        memcpy(out->name, keep, sizeof keep);
        out->build.name = out->name;
        ok = FindAllSites(im, out, second, sizeof second);
        out->wide = ok;
        if (ok) Note(v, "the second pass found every site");
        else if (strcmp(first, second) == 0)
            Why(why, whyLen, "%s, and the same with %d more piece%s read as code", first, alt, alt == 1 ? "" : "s");
        else Why(why, whyLen, "%s; with %d more piece%s read as code: %s", first, alt, alt == 1 ? "" : "s", second);
    }
    if (!ok)
    {
        NoteSections(im);
        if (v.survey) Survey(im);
    }
    out->scanMs = GetTickCount64() - t0;
    return ok;
}
}
