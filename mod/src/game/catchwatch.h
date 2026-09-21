#pragma once

// Four trials, four times the outlaw arrived on the ground, and three
// different copies of the catch release patched out between them. Each one
// was found by reading which call ran just before the state went, which is
// guesswork dressed up as analysis: the log says what was called, not what
// changed.
//
// This says what changed. Every object a site has marked whose class name
// contains "Catch" is snapshotted, and any byte that moves is written with
// the offset, the old value and the new one. The pickup marks both catch
// components, the player's and the outlaw's, on the server and on the
// client, so one teleport gives the exact moment each side stopped
// believing in the catch, to the tick, and the call log around that
// timestamp names what did it.
//
// Called from the mod thread ten times a second. It only reads.
namespace bp::catchwatch
{
    // `anyClass` drops the name filter, for tests whose objects have no RTTI.
    void Tick(bool anyClass = false);
}
