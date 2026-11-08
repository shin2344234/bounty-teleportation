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
// the catch tick.
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
namespace bt::finder
{
namespace
{
    constexpr uint32_t kExec = IMAGE_SCN_MEM_EXECUTE;
    constexpr int kMaxSec = 256;

    struct Sec
    {
        uint32_t va = 0, end = 0;
        bool exec = false;
        char name[9] = {};
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
        bool InCode(uint32_t rva) const
        {
            const Sec* s = SecOf(rva, 1);
            return s && s->exec;
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
        char line[512];
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
        for (int i = 0; i < n; ++i)
        {
            const uint32_t va = sh[i].VirtualAddress;
            uint32_t len = sh[i].Misc.VirtualSize > sh[i].SizeOfRawData ? sh[i].Misc.VirtualSize
                                                                         : sh[i].SizeOfRawData;
            if (va >= im->size || !len) continue;
            if (va + len > im->size) len = im->size - va;
            char name[9] = {};
            for (int k = 0; k < 8 && sh[i].Name[k]; ++k)
            {
                const char ch = static_cast<char>(sh[i].Name[k]);
                name[k] = ch >= 0x20 && ch < 0x7F ? ch : '?';
            }
            const bool exec = (sh[i].Characteristics & kExec) != 0;
            uint32_t o = 0;
            while (o < len)
            {
                size_t run = len - o;
                bool readable = true;
                if (v.runs)
                {
                    run = v.runs(b + va + o, len - o, &readable);
                    if (!run)
                    {
                        run = len - o;
                        readable = false;
                    }
                }
                if (run > len - o) run = len - o;
                const uint32_t at = va + o, to = va + o + static_cast<uint32_t>(run);
                if (!readable)
                    Note(v, "+0x%X..+0x%X of %s cannot be read and is left out of the scan", at, to, name);
                else if (im->nsec && im->secs[im->nsec - 1].end == at && im->secs[im->nsec - 1].exec == exec &&
                         strcmp(im->secs[im->nsec - 1].name, name) == 0)
                    im->secs[im->nsec - 1].end = to;
                else if (im->nsec < kMaxSec)
                {
                    Sec& s = im->secs[im->nsec++];
                    s.va = at;
                    s.end = to;
                    s.exec = exec;
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

    void NoteSections(const Img& im)
    {
        for (int i = 0; i < im.nsec; ++i)
            Note(*im.v, "scanned %s +0x%X..+0x%X as %s", im.secs[i].name, im.secs[i].va, im.secs[i].end,
                 im.secs[i].exec ? "code" : "data");
    }

    // Every rva in an executable section where `n` bytes equal `pat`, up to
    // `max` of them; returns how many there were in all.
    int FindAll(const Img& im, const uint8_t* pat, uint32_t n, uint32_t* out, int max)
    {
        int hits = 0;
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            if (!s.exec || s.end - s.va < n) continue;
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
            if (!s.exec || s.end - s.va < 5) continue;
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
            if (!im.secs[i].exec) continue;
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

    bool FindAllSites(const Img& im, Found* out, char* why, size_t whyLen)
    {
        Build& b = out->build;

        // ---- the watchdog, catch_update and the catch tick ----
        uint32_t hit[16];
        int n = FindAll(im, kWatchdogGuard, sizeof kWatchdogGuard, hit, 16);
        if (n != 1)
        {
            Why(why, whyLen, "the watchdog's guard is in %d places and not one", n);
            return false;
        }
        const uint32_t wg = hit[0];
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
        w.shape = kWatchdogGuard;
        w.shapeLen = sizeof kWatchdogGuard;

        // ---- the map teleport handler and the release slot ----
        uint32_t tfn = 0, tslot = 0;
        int tfns = 0;
        const uint8_t* thead = nullptr;
        for (int i = 0; i < im.nsec; ++i)
        {
            const Sec& s = im.secs[i];
            if (!s.exec || s.end - s.va < 17) continue;
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
        static const uint8_t kSweep[16] = { 0x48, 0x8B, 0x4E, 0x68, 0x49, 0x8B, 0x56, 0x30,
                                            0x48, 0x8B, 0x89, 0xB0, 0x00, 0x00, 0x00, 0xE8 };
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
    const bool ok = FindAllSites(im, out, why, whyLen);
    if (!ok) NoteSections(im);
    out->scanMs = GetTickCount64() - t0;
    return ok;
}
}
