#pragma once
#include <cstdint>

// What the static analysis found, as constants, so a session can see at a
// glance whether the running game still matches the notes.
//
// Nothing here is used to address anything. The probe resolves the handlers
// from the eErr name at runtime (resolve.h) precisely so a game update does not
// silently point it at the wrong bytes. These are the answers that derivation
// produced on 2.03.00, kept for the log line that compares the two: when they
// disagree, the resolver is right and this header is stale.
//
// FEASIBILITY.md in the repository root has the working behind every number.
namespace bp::sig
{
    inline constexpr const char* kBuild = "2.03.00 / exe 1.0.0.2944";

    // The refusal the player sees, "Cannot teleport in the current state.",
    // is localstringinfo row 0x6599F0AD, which points at localstringinfo.paloc
    // entry 7321147295087460528. Recorded because the string is how the
    // investigation started and how a report will describe it; the plugin
    // never looks either up.
    inline constexpr uint32_t kLocalStringRow = 0x6599F0ADu;
    inline constexpr uint64_t kLocalStringKey = 7321147295087460528ull;

    // The error the handlers store, and the chain the resolver walks to them.
    inline constexpr const char* kGateError   = "eErrNoFieldMoveHolding";
    inline constexpr uintptr_t kGateErrGlobal = 0x6CF6B5C;   // derived, .sbss
    inline constexpr int kGateReaderCount     = 3;

    // Three functions raise it, and nothing in the file says which one refuses
    // a map teleport.
    //
    // The first pass through this said there was one, because it scanned only
    // the section named .code. This exe has two executable sections and the
    // names mean nothing: .code holds 218,224 functions, .didata holds 26,218
    // and the entry point. Both hold real code with unwind entries, and calls
    // cross between them.
    //
    // The polarity of the skipping branch is not the same in all three, which
    // is why the probe reads the opcode rather than assuming one.
    //
    //   handler      reader       branch     shape
    //   +0x2BCD820   +0x2BCD88A   75 (jne)   .code,   5,324 bytes, 3 callers
    //   +0x10C71160  +0x10C71204  74 (je)    .didata,   430 bytes, 1 caller
    //   +0x10C78190  +0x10C7826F  74 (je)    .didata,   668 bytes, 1 caller
    //
    // The .code one also raises nothing else nearby; the first .didata one
    // also raises eErrNoInvalidField, and the second eErrNoInvalidUserActor
    // and eErrNoInvalidFieldInfoKey, which reads like a second request path.
    inline constexpr uintptr_t kGateFunction  = 0x2BCD820;
    inline constexpr uintptr_t kGateErrReader = 0x2BCD88A;
    inline constexpr uintptr_t kGateBranch    = 0x2BCD888;
    inline constexpr uintptr_t kGateHoldCheck = 0x2BC4200;   // this+0x4F0, the call it branches on

    inline constexpr uintptr_t kGateFunction2  = 0x10C71160;
    inline constexpr uintptr_t kGateErrReader2 = 0x10C71204;
    inline constexpr uintptr_t kGateFunction3  = 0x10C78190;
    inline constexpr uintptr_t kGateErrReader3 = 0x10C7826F;

    // Catch handling, pinned by RVA because none of these errors has a single
    // reader to resolve from. They are listed in BountyProbe.ini instead, where
    // they can be turned off without a rebuild; these are the same numbers.
    inline constexpr uintptr_t kCatchMatch   = 0x20ABAE0;
    inline constexpr uintptr_t kCatchAble    = 0x20AC2D0;
    inline constexpr uintptr_t kCatchRelease = 0x20AD3A0;
    inline constexpr uintptr_t kCatchSpawn   = 0x2792F80;
    inline constexpr uintptr_t kCatchSpawn2  = 0x2793C20;
    inline constexpr uintptr_t kCatchTarget  = 0x21276F0;
}
