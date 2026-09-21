#pragma once
#include <cstdint>

// Session ten's answer to the departure sweep.
//
// Both session-nine logs, with and without KeepCatch, end the same way for
// the outlaw: a message handler (+0x10DC8D90) that runs at every map confirm
// tears down every actor the player's session spawned in the field it is
// leaving (+0x287DB30, then +0x287D440 for each of three lists, then
// +0x2808D00 -> +0x107313E0 -> +0x2817E00 for each spawn record), and the
// outlaw is one of those actors. The 15:33 log's "re-placed outlaw" was a
// fresh NPC at the same address: his component table at +0x68 had changed.
//
// +0x2817E00 asks one question before it removes an actor:
//
//     +0x1F53D10([[actor+0x68]+0xb0], record key)      (a thunk to +0xE1478D0)
//
// which is "does anyone other than this record still hold the actor". It
// walks the holder list on that component (entries at +0x18, count +0x1c,
// each a key at +8 and a state at [+0x10]+0xac), then compares the actor's
// own key at +0x2e0 with the record's and finally reads a flag at +0x210. A
// yes leaves the actor in the world and moves on. This detour answers yes
// for an actor whose own catch component ([[actor+0x68]+0x70]) says at +0x28
// that someone is carrying it, and lets the original answer for everything
// else. With KeepCatch keeping the catch through the confirm, the outlaw is
// moved with the player by the wrapper's tail, kept by this, and still tied
// on when the client reloads at the destination. Whether the client side
// re-attaches him is what the trial is for.
namespace bp::keepcarried
{
    // Hooks the check at `target`, which is +0xE1478D0 in 2.03.00; the caller
    // verifies the bytes there and the thunk and call that reach it. With
    // requireClass the catch component must resolve to a class name
    // containing "CatchActorComponent" before its +0x28 is believed; the
    // tests turn that off because their fake objects have no RTTI.
    bool Hook(uintptr_t target, bool requireClass = true);

    // Counts, from the mod thread: how often the check ran, how often it was
    // answered here.
    void Summarise();
}
