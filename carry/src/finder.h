#pragma once

#include <cstddef>
#include <cstdint>

#include "builds.h"

// Finds every address of a Build row by byte pattern, for a game build that is
// not in kBuilds. The rules are the ones research\derive_2949.py and the
// per-patch scripts under patch-dlc\work\bounty-teleportation followed by
// hand, and nothing is taken from an offset in an older build. Each pattern
// has to match exactly once, or exactly once after the checks named beside
// it, and anything else is refused with the pattern named.
//
// Nothing here touches the running game. It reads a copy of an image laid
// out by RVA, which is the game's own image in memory when the plugin runs
// and an exe file laid out by tests\finder_test.cpp offline, so the same code
// is what the test proves.
namespace bt::finder
{
    struct View
    {
        const uint8_t* base = nullptr;  // RVA 0
        size_t         size = 0;        // SizeOfImage
        uint64_t       loadedAt = 0;    // what an absolute pointer to RVA 0 reads as in this copy
        // Optional: false for a section that cannot be read in place, which
        // is then left out of every scan. The test passes nothing.
        bool (*readable)(const void* p, size_t n) = nullptr;
    };

    // A found row. build.name and build.others[].label point into this
    // object, so it is filled in place and never copied.
    struct Found
    {
        Build build{};
        char  name[40] = {};
        char  other[2][48] = {};
        unsigned long long scanMs = 0;
    };

    // True when every site was found. Otherwise `why` says which pattern
    // matched how many times, and `out` is not to be used.
    bool Find(const View& v, Found* out, char* why, size_t whyLen);

    // The exe's FILEVERSION from its version resource, as "1.0.0.3576".
    bool FileVersion(const View& v, char* out, size_t n);
}
