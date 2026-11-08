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
        // Optional: how many bytes from p, up to n, share p's protection, and
        // whether they can be read. A section is scanned in its readable
        // pieces and the rest is left out and named in the notes. The test
        // passes nothing and every byte is read.
        size_t (*runs)(const void* p, size_t n, bool* readable) = nullptr;
        // Optional: one line of detail at a time, for the log. Every scan
        // names the release candidates it saw; a refused one also lists each
        // CharacterControl vtable's release slot and the image's sections.
        void (*note)(const char* line) = nullptr;
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

    // One step along a chain of jmps. `p` holds `n` bytes read at rva `at`.
    // Returns where a jmp there lands: E9 rel32 on its own, or behind the
    // this-adjusting prefix of an adjustor thunk (sub rcx,imm / add rcx,imm /
    // lea rcx,[rcx+disp]). For jmp [rip+disp32] (FF 25) it returns 0 and sets
    // *indirect to the rva of the pointer to read. 0 with *indirect 0 means
    // the bytes are not a jmp. Needs up to 12 bytes to see every form.
    // mod.cpp checks a listed build's release slot with the same steps.
    uint32_t JmpHop(const uint8_t* p, size_t n, uint32_t at, uint32_t* indirect);
    constexpr int kMaxHops = 4;
}
