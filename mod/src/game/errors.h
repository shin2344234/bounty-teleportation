#pragma once
#include <cstdint>

// Names for the game's eErr* codes.
//
// The codes are not constants in the file. Each eErr name's numeric value is a
// hash of the name, computed once at process start and written into a private
// global; every comparison in the game reads that global. Flight Freedom's A2
// established the derivation, and research/gen_errors.py applies it to all
// 1,560 names in the image, writing the ones whose global is unambiguous into
// errors_table.h.
//
// So this reads the globals after the game has filled them and builds value ->
// name from what it finds. A table belonging to a different build reads as
// zeros rather than as wrong names, and Load() says so.
namespace bp::errors
{
    // Reads every global in the table. Returns the number of codes resolved.
    //
    // Call it again when it returns nothing. The plugin is injected before the
    // game's static initialisers run, and on the first session every one of
    // the 1,353 globals still read zero, so there is nothing to read until the
    // game has started properly. Once it succeeds, later calls are free.
    int Load();

    // True once Load() has found enough to name codes by.
    bool Ready();

    // "eErrNoFieldMoveHolding" for a known code, otherwise nullptr. Callers
    // print the number either way.
    const char* Name(uint32_t code);

    // The code a name resolved to, or 0. For logging anchors, and for a check
    // that the table belongs to this build.
    uint32_t Value(const char* name);

    // True when too few globals answered for the names to be trusted. Every
    // lookup returns nullptr in that case rather than guessing.
    bool Stale();

    // One line per name, into the log. Only for a session that needs the whole
    // set written down; it is 1,353 lines.
    void DumpAll();
}
