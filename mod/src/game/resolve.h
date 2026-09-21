#pragma once
#include <cstdint>

// Finding the teleport gate without trusting an address.
//
// Flight Freedom pins its four patches to RVAs and 2.03.00 moved every one of
// them, so 1.1.3 refused all four on the new build. The chain below is the
// alternative: start from an eErr name, which a patch does not change, and walk
// to the code. Each step reports how many candidates it saw, because a step
// that used to be unique and is no longer is the thing worth knowing.
//
//   name string  ->  the lea that points at it
//                ->  the global 0x1C before that lea      (A2's derivation)
//                ->  the instruction that reads the global
//                ->  the function containing it           (the unwind tables)
//
// Every value here is an RVA, so the log reads the same as the research notes.
namespace bp::resolve
{
    // Address of the global holding this error's runtime value, or 0.
    // `leas` receives how many lea instructions pointed at the name string;
    // anything but 1 means the derivation is guessing and 0 is returned.
    uintptr_t ErrorGlobal(const char* errName, int* leas = nullptr);

    // Every instruction that reads that global, across both executable
    // sections and every form of mov-from-rip. Returns how many were written
    // to `out`, which is capped at `max`; the true count goes to `total`.
    //
    // This is deliberately not "find the one". eErrNoFieldMoveHolding is
    // raised in three different functions on this build, one in .code and two
    // in .didata, and which of them refuses a given teleport is exactly what a
    // session is supposed to find out.
    int Readers(uintptr_t globalRva, uintptr_t* out, int max, int* total = nullptr);

    // Name of the section an RVA falls in, or "?" . Only for the log: on this
    // build the section names carry no meaning (the entry point is in one
    // called .didata) but they still tell two addresses apart.
    const char* SectionOf(uintptr_t rva);

    // Start of the function containing an RVA, from the exception directory,
    // which is exact where a scan back for int3 padding is not.
    uintptr_t FunctionStart(uintptr_t codeRva);

    // Every direct call or jump to a function. Writes at most `max` of them to
    // `outCallSites` and returns the real total, which is the point: the count
    // is how you tell a handler's own predicate from general plumbing, and a
    // capped count would say 1 where the truth is thousands. Callers of this
    // clamp the return value before indexing.
    int Callers(uintptr_t funcRva, uintptr_t* outCallSites, int max);

    // Target of the last `call rel32` between two RVAs, or 0. The gate's
    // predicate is the call whose result it branches on, and that is the last
    // call before the error is stored.
    uintptr_t LastCallBefore(uintptr_t fromRva, uintptr_t beforeRva);

    // Bytes at an RVA, as hex, into `out`. For logging a patch site's current
    // contents next to what the notes say should be there.
    void HexAt(uintptr_t rva, unsigned n, char* out, unsigned cap);
}
