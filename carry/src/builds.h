#pragma once

#include <cstddef>
#include <cstdint>

// Every game build the plugin knows, with each address it patches, hooks or
// checks, and the byte shapes those addresses must read. mod.cpp picks the
// row whose every check passes. When none does, finder.cpp looks for the same
// sites by pattern and fills in a row of the same shape, and
// tests\finder_test.cpp runs that finder over each exe kept under
// patch-baseline and compares what it finds with the row here.
namespace bt
{
    struct Release
    {
        const char* label;
        uintptr_t   at;          // the two bytes that decide whether it runs
        uint8_t     orig[2];
        uint8_t     repl[2];
        uintptr_t   call;        // the catch_update call it skips
        uintptr_t   guard;       // the test in front of it
        const uint8_t* shape;    // what that test must read
        unsigned    shapeLen;
        uintptr_t   vtable;      // 0 when the function is in no vtable
        uintptr_t   slotTarget;  // what the build's release slot of it must hold
        uintptr_t   thunkTo;     // 0 unless that slot points at a jmp
    };

    // cmp [rcx+0x38],0 / je / mov bl,1 / jmp / cmp [rcx+0x28],0 / setne.
    // The three teleport copies are the same function compiled three times
    // and all three read this.
    inline const uint8_t kTeleportGuard[16] = { 0x83, 0x79, 0x38, 0x00, 0x74, 0x04, 0xB3, 0x01,
                                         0xEB, 0x07, 0x83, 0x79, 0x28, 0x00, 0x0F, 0x95 };

    // The watchdog reads both handles into registers first:
    // test edi,edi / jne / test ebx,ebx / je.
    inline const uint8_t kWatchdogGuard[8] = { 0x85, 0xFF, 0x75, 0x04, 0x85, 0xDB, 0x74, 0x3E };

    constexpr int kReleaseCount = 4;

    // A catch_update call the plugin does not patch, named only so the log
    // can say which one ran. Nothing is written at these.
    struct OtherRelease
    {
        const char* label;
        uintptr_t   call;
    };

    struct Build
    {
        const char* name;          // the exe version it was read off
        uintptr_t   catchUpdate;   // where every release below must call
        Release     releases[kReleaseCount];
        uintptr_t   holderCheck;   // the departure sweep's "does anyone hold it"
        uintptr_t   holderThunk;   // the jmp that reaches it, 0 where the sweep calls it directly
        uintptr_t   sweepCall;     // the sweep's call to that thunk, or to the check itself
        uintptr_t   teleport;      // the map teleport handler
        uintptr_t   teleportCall1; // its two callers, both in the message handler
        uintptr_t   teleportCall2;
        OtherRelease others[2];    // zero where they were never derived
        uintptr_t   catchTick;     // the catch component's tick, the watchdog's own function
        uintptr_t   releaseSlot;   // the vtable slot the character control release is in
        const uint8_t* teleportHead; // the teleport handler's first 15 bytes
    };

    // mov rax,rsp / mov [rax+10],rbx / mov [rax+18],rsi / mov [rax+20],rdi,
    // the teleport handler's up to 1.0.0.2976.
    inline const uint8_t kTeleportHead[15] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48,
                                        0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20 };
    // mov [rsp+10],rbx / mov [rsp+18],r8 / mov [rsp+8],rcx, its prologue on
    // 1.0.0.3392, which keeps the moved actor in its home slot instead of r13.
    inline const uint8_t kTeleportHead3392[15] = { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x4C, 0x89, 0x44,
                                            0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08 };

    // The releases, in order: the release slot (0x200, or 0x1F8 from
    // 1.0.0.3392) of the server and common CharacterControl components,
    // called by the teleport handler once the player has been moved; the
    // client's own copy of that function, reached through a thunk, whose
    // absence is what made the outlaw arrive lying on the ground when only
    // the server's was patched; a client state
    // transition that is in no vtable and fires a second after the confirm;
    // and the watchdog on the catch component itself, which runs about six
    // times a second on every catch in the world and drops one the carry
    // animation no longer backs. The watchdog's patch goes over the first
    // test rather than the `je` below it: with something actually held, the
    // `jne` in between jumps past that `je` and never reads it.
    inline const Build kBuilds[] = {
        {
            "1.0.0.3576", 0x226E700,
            {
                { "keepcatch", 0x251A6E4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x251A703, 0x251A6C4,
                  kTeleportGuard, 16, 0x5EEEB68, 0x251A690, 0 },
                { "keepcatch_client", 0x959F814, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x959F833, 0x959F7F4,
                  kTeleportGuard, 16, 0x59459F0, 0x9466A0, 0x959F7C0 },
                { "keepcatch_state", 0x178A5BD, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178A5DA, 0x178A59B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226F928, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226F969, 0x226F928,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213F490, 0, 0x2A5D472,
            0x2E6E210, 0x2E6EFBA, 0x2E6F58C,
            { { "the release in +0x178A960", 0x178AE23 }, { "the release in +0x2282DF0", 0x2282FA6 } },
            0x226F8A0, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3549", 0x226DAC0,
            {
                { "keepcatch", 0x2519914, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2519933, 0x25198F4,
                  kTeleportGuard, 16, 0x5EEC968, 0x25198C0, 0 },
                { "keepcatch_client", 0x94B76B4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x94B76D3, 0x94B7694,
                  kTeleportGuard, 16, 0x59438F0, 0x946330, 0x94B7660 },
                { "keepcatch_state", 0x1789C5D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x1789C7A, 0x1789C3B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226ECE8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226ED29, 0x226ECE8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213E850, 0, 0x2A5C822,
            0x2E6D5A0, 0x2E6E34A, 0x2E6E91C,
            { { "the release in +0x178A000", 0x178A4C3 }, { "the release in +0x22821B0", 0x2282366 } },
            0x226EC60, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3527", 0x226DAC0,
            {
                { "keepcatch", 0x2519914, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2519933, 0x25198F4,
                  kTeleportGuard, 16, 0x5EEC968, 0x25198C0, 0 },
                { "keepcatch_client", 0x94FCC54, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x94FCC73, 0x94FCC34,
                  kTeleportGuard, 16, 0x59438F0, 0x946330, 0x94FCC00 },
                { "keepcatch_state", 0x1789C5D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x1789C7A, 0x1789C3B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226ECE8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226ED29, 0x226ECE8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213E850, 0, 0x2A5C822,
            0x2E6D5A0, 0x2E6E34A, 0x2E6E91C,
            { { "the release in +0x178A000", 0x178A4C3 }, { "the release in +0x22821B0", 0x2282366 } },
            0x226EC60, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3479", 0x226AE10,
            {
                { "keepcatch", 0x2515C54, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2515C73, 0x2515C34,
                  kTeleportGuard, 16, 0x5EE6718, 0x2515C00, 0 },
                { "keepcatch_client", 0x96487D4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x96487F3, 0x96487B4,
                  kTeleportGuard, 16, 0x593D8E0, 0x945540, 0x9648780 },
                { "keepcatch_state", 0x17886DD, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x17886FA, 0x17886BB,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226C038, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226C079, 0x226C038,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213BC30, 0, 0x2A5895C,
            0x2E67C30, 0x2E689DA, 0x2E68FAC,
            { { "the release in +0x1788A80", 0x1788F43 }, { "the release in +0x227F500", 0x227F6B6 } },
            0x226BFB0, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3462", 0x226AE60,
            {
                { "keepcatch", 0x2515CA4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2515CC3, 0x2515C84,
                  kTeleportGuard, 16, 0x5EE6718, 0x2515C50, 0 },
                { "keepcatch_client", 0x95B8B54, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x95B8B73, 0x95B8B34,
                  kTeleportGuard, 16, 0x593D8E0, 0x945570, 0x95B8B00 },
                { "keepcatch_state", 0x178872D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178874A, 0x178870B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226C088, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226C0C9, 0x226C088,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213BC80, 0, 0x2A589AC,
            0x2E67C80, 0x2E68A2A, 0x2E68FFC,
            { { "the release in +0x1788AD0", 0x1788F93 }, { "the release in +0x227F550", 0x227F706 } },
            0x226C000, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3460", 0x226AE60,
            {
                { "keepcatch", 0x2515994, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x25159B3, 0x2515974,
                  kTeleportGuard, 16, 0x5EE57C8, 0x2515940, 0 },
                { "keepcatch_client", 0x94CE5A4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x94CE5C3, 0x94CE584,
                  kTeleportGuard, 16, 0x593C8E0, 0x945570, 0x94CE550 },
                { "keepcatch_state", 0x178872D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178874A, 0x178870B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x226C088, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x226C0C9, 0x226C088,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x213BC80, 0, 0x2A5867C,
            0x2E67940, 0x2E686EA, 0x2E68CBC,
            { { "the release in +0x1788AD0", 0x1788F93 }, { "the release in +0x227F550", 0x227F706 } },
            0x226C000, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3446", 0x2267AA0,
            {
                { "keepcatch", 0x2512214, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2512233, 0x25121F4,
                  kTeleportGuard, 16, 0x5EE15C8, 0x25121C0, 0 },
                { "keepcatch_client", 0x9536C44, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x9536C63, 0x9536C24,
                  kTeleportGuard, 16, 0x59388D0, 0x944A30, 0x9536BF0 },
                { "keepcatch_state", 0x178561D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178563A, 0x17855FB,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x2268CC8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x2268D09, 0x2268CC8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0x21388B0, 0, 0x2A5505C,
            0x2E63DF0, 0x2E64B9A, 0x2E6516C,
            { { "the release in +0x17859C0", 0x1785E83 }, { "the release in +0x227C190", 0x227C346 } },
            0x2268C40, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3424", 0x22668F0,
            {
                { "keepcatch", 0x2511064, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2511083, 0x2511044,
                  kTeleportGuard, 16, 0x5EDF4C8, 0x2511010, 0 },
                { "keepcatch_client", 0x97BF134, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x97BF153, 0x97BF114,
                  kTeleportGuard, 16, 0x5936838, 0x944A00, 0x97BF0E0 },
                { "keepcatch_state", 0x1784A6D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x1784A8A, 0x1784A4B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x2267B18, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x2267B59, 0x2267B18,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xC9F4A10, 0x2137880, 0x2A539DC,
            0x2E624A0, 0x2E6324A, 0x2E6381C,
            { { "the release in +0x1784E10", 0x17852D3 }, { "the release in +0x227AFE0", 0x227B196 } },
            0x2267A90, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.3392", 0x22656B0,
            {
                { "keepcatch", 0x250FDD4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x250FDF3, 0x250FDB4,
                  kTeleportGuard, 16, 0x5EDD4B8, 0x250FD80, 0 },
                { "keepcatch_client", 0x967143F, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x967145E, 0x967141F,
                  kTeleportGuard, 16, 0x5934850, 0x9441D0, 0x96713E0 },
                { "keepcatch_state", 0x178393D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x178395A, 0x178391B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x22668D8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x2266919, 0x22668D8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xC91E0F0, 0x2136620, 0x2A5274C,
            0x2E60CA0, 0x2E61A4A, 0x2E6201C,
            { { "the release in +0x1783CE0", 0x17841A3 }, { "the release in +0x2279DA0", 0x2279F56 } },
            0x2266850, 0x1F8, kTeleportHead3392,
        },
        {
            "1.0.0.2976", 0x20AD400,
            {
                { "keepcatch", 0x2329184, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x23291A3, 0x2329164,
                  kTeleportGuard, 16, 0x5B25468, 0x2329130, 0 },
                { "keepcatch_client", 0x9857044, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x9857063, 0x9857024,
                  kTeleportGuard, 16, 0x55B5460, 0x860FF0, 0x9856FF0 },
                { "keepcatch_state", 0x156F1CD, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x156F1EA, 0x156F1AB,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x20AE628, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x20AE669, 0x20AE628,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xDD9D1E0, 0x1F53D50, 0x28181E0,
            0x2BC96C0, 0x2BCA5DD, 0x2BCAB80,
            { { "the release in +0x156F550", 0x156F9F5 }, { "the release in +0x20C0610", 0x20C07C6 } },
            0x20AE5A0, 0x200, kTeleportHead,
        },
        {
            "1.0.0.2949", 0x20AD3B0,
            {
                { "keepcatch", 0x2329134, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2329153, 0x2329114,
                  kTeleportGuard, 16, 0x5B25260, 0x23290E0, 0 },
                { "keepcatch_client", 0x983EDC4, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x983EDE3, 0x983EDA4,
                  kTeleportGuard, 16, 0x55B53C8, 0x860F90, 0x983ED70 },
                { "keepcatch_state", 0x156F25D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x156F27A, 0x156F23B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x20AE5D8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x20AE619, 0x20AE5D8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xDD526C0, 0x1F53D20, 0x2818170,
            0x2BC9650, 0x2BCA56D, 0x2BCAB10,
            {}, 0x20AE550, 0x200, kTeleportHead,
        },
        {
            "1.0.0.2944", 0x20AD3A0,
            {
                { "keepcatch", 0x2329124, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x2329143, 0x2329104,
                  kTeleportGuard, 16, 0x5B25260, 0x23290D0, 0 },
                { "keepcatch_client", 0x99B6D0F, { 0x74, 0x22 }, { 0xEB, 0x22 }, 0x99B6D2E, 0x99B6CEF,
                  kTeleportGuard, 16, 0x55B53C8, 0x860F90, 0x99B6CB0 },
                { "keepcatch_state", 0x156F24D, { 0x74, 0x20 }, { 0xEB, 0x20 }, 0x156F26A, 0x156F22B,
                  kTeleportGuard, 16, 0, 0, 0 },
                { "keepcatch_watchdog", 0x20AE5C8, { 0x85, 0xFF }, { 0xEB, 0x44 }, 0x20AE609, 0x20AE5C8,
                  kWatchdogGuard, 8, 0, 0, 0 },
            },
            0xE1478D0, 0x1F53D10, 0x2818160,
            0x2BC9640, 0x2BCA55D, 0x2BCAB00,
            {}, 0x20AE540, 0x200, kTeleportHead,
        },
    };

    // mov [rsp+8],rbx / mov eax,[rcx+0x1c], the holder check's first bytes.
    inline const uint8_t kHolderHead[9] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x44, 0x8B, 0x41, 0x1C };

    // mov [rsp+8],rbx / mov [rsp+0x18],rbp / mov [rsp+0x20],rsi / push rdi /
    // push r14 / push r15 / sub rsp,0x40 / mov rsi,rcx / cmp byte [rdx],0.
    inline const uint8_t kTickHead[27] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24,
                                    0x20, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xF1 };

    inline constexpr size_t kBuildCount = sizeof kBuilds / sizeof kBuilds[0];
}
