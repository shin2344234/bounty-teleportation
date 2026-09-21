#pragma once

#include <cstdint>

// Byte patches with their originals kept, so unloading the plugin puts the
// game back. The probe's version of this lives in its sites.cpp along with
// everything else that file does; this is the same idea with nothing else
// attached.
//
// 1.0.0 wrote every patch once at startup and left it there. 1.0.1 checks
// them at startup and writes them only while they are wanted, because the
// catch releases they skip are also how petting an animal, reading a note or
// an interrupted grab gets cleaned up.
namespace bp::patch
{
    // Checks that the `n` bytes at `rva` (relative to the game's image base)
    // are `orig` and remembers the patch without writing it. Returns an index
    // for Set, or -1 when the bytes are wrong, which means either the game was
    // updated or another mod is on the same address; the log says which bytes
    // were found.
    int Register(const char* name, uintptr_t rva, const uint8_t* orig, const uint8_t* repl, unsigned n);

    // Writes the replacement (on) or the original (off). Each patch replaces
    // exactly one instruction of the same length, so a thread that reaches
    // it sees either the old instruction or the new one and never half of
    // each. Returns false if the write did not read back.
    bool Set(int index, bool on);

    // Registers and writes at once, for a patch that stays on. Kept for
    // anything that should never be switched.
    bool Apply(const char* name, uintptr_t rva, const uint8_t* orig, const uint8_t* repl, unsigned n);

    // Puts back every patch that is currently written, newest first.
    void RestoreAll();
}
