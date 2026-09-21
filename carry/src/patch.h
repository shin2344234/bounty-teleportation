#pragma once

#include <cstdint>

// Byte patches with their originals kept, so unloading the plugin puts the
// game back. The probe's version of this lives in its sites.cpp along with
// everything else that file does; this is the same idea with nothing else
// attached.
namespace bp::patch
{
    // `rva` is relative to the game's image base. Writes nothing unless the
    // bytes there are `orig`, and says so in the log when they are not:
    // either the game was updated or another mod is on the same address.
    // Already reading `repl` counts as done.
    bool Apply(const char* name, uintptr_t rva, const uint8_t* orig, const uint8_t* repl, unsigned n);

    // Puts back every patch that went in, newest first.
    void RestoreAll();
}
