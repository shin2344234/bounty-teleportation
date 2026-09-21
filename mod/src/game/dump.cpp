#include "game/dump.h"

#include <Windows.h>
#include <intrin.h>

#include "core/log.h"
#include "game/mem.h"

namespace bp::dump
{
    void Object(const char* what, uintptr_t obj, unsigned bytes)
    {
        if (!bp::mem::Plausible(obj) || !bp::mem::Readable(obj, bytes))
        {
            LOG("[obj] %s 0x%p unreadable", what, reinterpret_cast<void*>(obj));
            return;
        }
        LOG("[obj] %s 0x%p", what, reinterpret_cast<void*>(obj));
        for (unsigned off = 0; off < bytes; off += 8)
        {
            uintptr_t v = 0;
            if (!bp::mem::ReadPtr(obj + off, &v))
            {
                uint64_t raw = 0;
                if (bp::mem::Read64(obj + off, &raw))
                    LOG("[obj]   +0x%03X  %016llX", off, static_cast<unsigned long long>(raw));
                continue;
            }
            const char* n = bp::mem::RttiShort(v);
            if (n) LOG("[obj]   +0x%03X  %016llX  %s", off, static_cast<unsigned long long>(v), n);
            else   LOG("[obj]   +0x%03X  %016llX%s", off, static_cast<unsigned long long>(v),
                       bp::mem::InImage(v) ? "  (in image)" : "");
        }
    }

    void Stack(const char* why)
    {
        uintptr_t sp = reinterpret_cast<uintptr_t>(_AddressOfReturnAddress());
        LOG("[stack] %s: scanning 4 KB up from 0x%p", why, reinterpret_cast<void*>(sp));
        int shown = 0;
        for (uintptr_t p = sp & ~7ull; p < sp + 4096 && shown < 80; p += 8)
        {
            uintptr_t v = 0;
            if (!bp::mem::ReadPtr(p, &v) || !bp::mem::InImage(v)) continue;
            // A return address has a call immediately before it. Direct call is
            // E8 rel32 five bytes back; the indirect forms are two to seven.
            const char* kind = "value";
            uint8_t b[8] = {};
            if (bp::mem::ReadBytes(v - 7, b, 7))
            {
                if (b[2] == 0xE8) kind = "ret-addr (call rel32)";
                else if (b[5] == 0xFF || b[4] == 0xFF || b[1] == 0xFF) kind = "ret-addr (call indirect)";
            }
            LOG("[stack]   +0x%06llX  +0x%llX  %s",
                static_cast<unsigned long long>(p - sp),
                static_cast<unsigned long long>(bp::mem::Rva(v)), kind);
            ++shown;
        }
        if (!shown) LOG("[stack]   nothing in the image found on the stack");
    }
}
