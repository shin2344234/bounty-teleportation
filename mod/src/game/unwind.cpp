#include "game/unwind.h"

#include <Windows.h>

#include "core/log.h"
#include "game/mem.h"
#include "game/sites.h"

namespace bp::unwind
{
    void Here(const char* why, int maxFrames)
    {
        CONTEXT ctx = {};
        RtlCaptureContext(&ctx);
        LOG("[unwind] %s", why);
        int shown = 0, blind = 0;
        for (int i = 0; i < maxFrames && ctx.Rip; ++i)
        {
            // A hooked function returns into a leave thunk, so after its
            // frame is unwound Rip is the thunk and not in any image. The
            // thunk's real return address is on sites' shadow stack, keyed by
            // the slot it replaced, which is the qword just below Rsp now.
            if (!bp::mem::InImage(static_cast<uintptr_t>(ctx.Rip)))
            {
                const uint64_t real = bp::sites::RealReturnAt(reinterpret_cast<const uint64_t*>(ctx.Rsp) - 8);
                if (real) { ctx.Rip = real; --i; continue; }
            }
            DWORD64 imgBase = 0;
            RUNTIME_FUNCTION* fe = RtlLookupFunctionEntry(ctx.Rip, &imgBase, nullptr);
            if (!fe)
            {
                // A leaf function, or something without unwind data: the
                // return address is at rsp. Three in a row means the walk has
                // left anything it can describe.
                if (++blind > 3) break;
                ctx.Rip = *reinterpret_cast<DWORD64*>(ctx.Rsp);
                ctx.Rsp += 8;
                continue;
            }
            blind = 0;
            const bool inGame = bp::mem::InImage(static_cast<uintptr_t>(ctx.Rip));
            if (inGame)
            {
                LOG("[unwind]   %2d  +0x%llX  (function +0x%llX)", shown,
                    static_cast<unsigned long long>(bp::mem::Rva(static_cast<uintptr_t>(ctx.Rip))),
                    static_cast<unsigned long long>(imgBase + fe->BeginAddress - bp::mem::Game().base));
                ++shown;
            }
            void* handler = nullptr;
            DWORD64 est = 0;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgBase, ctx.Rip, fe, &ctx, &handler, &est, nullptr);
        }
        if (!shown) LOG("[unwind]   nothing in the game's image on this thread's stack");
    }
}
