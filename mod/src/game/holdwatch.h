#pragma once
#include <cstdint>

// The first gate is not a rule about carrying. +0x2BCD820 asks
// +0x2BC4200(this+0x4F0, &result) for a "hold" on the actor's field
// attachment and refuses with eErrNoFieldMoveHolding when result+0x10 comes
// back zero. That wrapper tail-calls +0x2BBF2C0, and reading that function
// from its entry gives the four things the byte depends on:
//
//     byte [sub+0x58] is non-zero              blocked outright
//     [sub+0x10] == 0                          no field held
//     virtual +0x1d8 on [[sub]+8] returns 0    the actor says no
//     +0x1434420([sub+0x10]) returns 0         the held field is gone
//
// Both calls are one byte each once followed: the actor's virtual is
// `movzx eax, byte [this+0xC2]; ret` on ServerNormalInGameActor, and the
// validity call is a weak-reference lock that tests byte [ref+0x4a] before
// bumping a count. [sub+0x10] is a weak reference to the field the actor is
// attached to, and the result the wrapper fills is a FieldAttacherForActor
// over ScopeAttacherBase. So every input is a direct read and a refusal can
// be named: blocked, no field held, held field dead, or actor flag 0.
//
// One of those is what carrying changes, and a re-pickup after a drop
// evidently changes it back (Dehavol, r/CrimsonDesert, 19 Sep 2026: kill the
// outlaw during the interrogation, pick up, fly up so the body drops, pick up
// again, fast travel; "15+ bounties, works every time"). This hooks
// +0x2BBF2C0 itself and logs the sample only when it differs from the last,
// so a function that runs 380,069 times a session costs a handful of lines,
// and the two pickups of one test session sit next to each other in the log.
//
// It also walks the second gate's chain from the same actor,
// [[[actor+0x68]+0x1a0]+0x540], which +0x2AF8010 dereferences after testing
// for null, so both gates are read off one sample.
namespace bp::holdwatch
{
    struct Sample
    {
        uintptr_t sub = 0;      // this: the component's +0x4F0 sub-object
        uint8_t   blocked = 0;  // byte [sub+0x58]; 2 and 3 are written by the field-move code itself
        uint16_t  holds = 0;    // word [sub+0x5a], incremented on each success
        uintptr_t p10 = 0;      // [sub+0x10], weak reference to the held field
        uint8_t   p10Alive = 0; // byte [p10+0x4a], what the validity call tests
        uintptr_t p50 = 0;      // [sub+0x50], stored into the result at +0x20
        uintptr_t owner = 0;    // [sub], the transform sync component
        uintptr_t actor = 0;    // [owner+8]
        uint8_t   actorFlag = 0; // byte [actor+0xC2], what the actor's virtual returns
        uintptr_t c68 = 0, c1a0 = 0, c540 = 0;   // the second gate's chain
        bool      ok = false;   // result+0x10 after the original ran
        uintptr_t caller = 0;   // who asked the wrapper, or the acquirer directly
        const char* resultType = nullptr;   // RTTI of the result object
    };

    // Reads what it can reach from `sub`; a pointer that cannot be read stays
    // zero and everything past it does too. Returns false only when `sub`
    // itself is unreadable.
    bool Read(uintptr_t sub, Sample& s);

    // The fields that decide either gate. `holds` is left out because it
    // counts every success and would make every call a change.
    bool Differs(const Sample& a, const Sample& b);

    // Which of the four refused, in words, or "ok".
    void Why(const Sample& s, char* out, unsigned cap);
    void Describe(const Sample& s, char* out, unsigned cap);

    // The first `call rel32` in the `span` bytes at `rva`, as an RVA, or 0,
    // with the address the call returns to in *retAt. The wrapper's only
    // call is the function this hooks.
    uintptr_t CallTargetIn(uintptr_t rva, unsigned span, uintptr_t* retAt = nullptr);

    // Hooks the function the wrapper at `wrapperRva` calls. `lines` caps how
    // many lost-and-regained holds are written in full, each with the sample
    // before it; 0 is no cap. `gateRva` is the field-move handler: it asks on
    // every one of its calls, so only its refusals are written, which puts
    // the sample the refusal was decided on in the log next to the refusal.
    // An actor that a site has marked (sites::Interesting), or whose class
    // name contains `traceClass`, is traced: every call about it is written
    // with its caller, a call from inside the handler gets the dumps, and a
    // hold it loses or gets back gets an unwind.
    bool Install(uintptr_t wrapperRva, unsigned lines, uintptr_t gateRva = 0, const char* traceClass = nullptr);

    void Summarise();   // call from the mod thread
}
