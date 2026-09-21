#pragma once
#include <cstdint>

// Hooks on arbitrary functions, named by RVA in FlightProbe.ini, so a new
// suspect can be watched by editing the ini rather than writing a detour.
//
//   [sites]
//   ; name = 0xRVA [, ret=0xN] [, skip=0xN] [, dump=N] [, lines=N] [, stack=N]
//   ;               [, leave=0|1] [, args=N] [, obj=0xN] [, onerr=1] [, errlines=N]
//   server_summon = 0x271F9B0, dump=3, lines=200
//
// `onerr=1` turns all of that off and logs only the calls that come back with
// a non-zero out pointer, with the arguments the entry saw. `onnull=1` is the
// same filter on the return value instead, for a lookup that reports failure
// by returning nothing rather than by writing a code. `only=Name` writes the
// per-call lines only when an argument's class name contains Name. Non-zero
// out values are counted for every site either way, and the summary reports
// the count and the last one by name.
//
// `mark=13` remembers arguments 1 and 3 of every call that passes `only=`,
// and with each the object at its +8 when that has a class name (a
// component's owner). `onlymarked=1` writes per-call lines only for calls
// where one of the first `args` arguments is remembered, or is a component
// of one (its +8 is), or a sub-object of one (the +8 of what its +0 points
// to is). Both work with `onerr=1`: a marked call is written in full and an
// unmarked one only when it errs. `marks=0xN` dumps every marked object, N
// bytes each, after each written call, so the state of the player's catch
// component is in the log at the moment the outlaw is moved. Session nine
// uses these to follow the carried outlaw and the player through a teleport
// without hearing about the other thousand actors the same functions handle.
//
// Every hooked call logs its caller, its six integer arguments (with RTTI
// class names, text, or engine strings where the pointer resolves to one),
// the low float of xmm0..xmm3, a raw dump of the first three pointer
// arguments and an unwind of the caller's stack. Nothing is capped unless a
// site asks for it with lines=, dump= or stack=. A
// return hook logs the value in rax; `ret=` replaces it, `skip=` returns it
// without running the function at all. `leave=0` turns the return hook off for
// a function that might throw through it.
//
//   [patch]
//   ; name = 0xRVA : hex bytes
//   dev_flag = 0x5642F2C : 01
//
// Bytes written over the image at startup, logged before and after, restored
// on unload.
//
//   [watch]
//   ; name = 0xRVA , length
//   dev_flag = 0x5642F2C, 8
//
// Bytes logged at startup and again whenever they change.
namespace bp::sites
{
    // `research` reads the [sites], [resolve], [patch] and [watch] sections;
    // without it nothing from the ini is hooked or written. Built-in patches go
    // through ApplyPatch either way.
    bool Install(bool research = true);

    // Hook a function whose address was worked out at runtime rather than read
    // out of the ini. `spec` takes the same options as an ini value with the
    // RVA left off, e.g. "out=2, args=4, lines=60". Call it after Install().
    bool AddSite(const char* name, uintptr_t target, const char* spec);
    void Remove();

    // Write `n` bytes at image+rva, only if the bytes there are exactly
    // `orig` (or already `repl`, in which case nothing is written). Logged
    // either way; restored on Remove(). Returns true when the bytes are in
    // place afterwards.
    bool ApplyPatch(const char* name, uintptr_t rva, const uint8_t* orig, const uint8_t* repl, unsigned n);
    void Tick();       // watches; call from the mod thread
    void Summarise();  // call counts; call from the mod thread

    // The return address a leave thunk replaced in `slot` on this thread, or
    // 0. An unwinder that lands on a thunk uses it to keep going.
    uint64_t RealReturnAt(const uint64_t* slot);

    // The interest set behind `mark=` and `onlymarked=`. Mark() remembers a
    // readable object and, when the pointer at its +8 has a class name, that
    // object too; both are logged with `by`. Interesting() is what
    // `onlymarked=` asks of each argument, and other watchers ask the same.
    // Sixteen slots, never reused within a session; ClearMarks() is for
    // tests.
    void Mark(uint64_t v, const char* by);
    bool Marked(uint64_t v);
    bool Interesting(uint64_t v);
    uint64_t MarkAt(int i);   // slot i, or 0 past the last one
    void ClearMarks();
}
