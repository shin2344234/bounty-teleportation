# Bounty Teleportation

Fast travel while carrying a bounty target in Crimson Desert. He rides along
on your back and is still worth turning in at the other end. Built and tested
on 2.03.00, exe 1.0.0.2944.

Without it the teleport goes through and the outlaw does not. Two separate
things remove him during the confirm: the teleport releases the catch, and
leaving a field tears down every actor the session spawned in it. This turns
off the first and answers the second.

## Layout

    carry\        the plugin that ships, BountyTeleportation.asi
    mod\          Bounty Probe, the research plugin that found the addresses
    research\     scripts that read the game executable
    FEASIBILITY.md  the working, oldest reading first

`carry` is 225 KB of plugin that writes about twenty lines a session. `mod` is
what it took to get there and writes half a gigabyte a minute. They patch the
same bytes and hook the same function, so only one of them is ever loaded.

## Building

    carry\build.bat

MSVC Build Tools 2022 with the CMake and Ninja they bundle, called by full
quoted path from PowerShell. MinHook is fetched at configure time for its
HDE64 length decoder, which is all the hook installer uses it for. Five of the
plugin's source files are compiled out of `mod\src` rather than copied, so a
fix to the log, the memory reads or the hook engine lands in both plugins.

`carry\package.ps1` builds the two archives and prints their checksums.

## What it patches

Five addresses, each checked against the bytes that should be there before
anything is written, and all of it put back if the plugin is unloaded. A game
update moves them; the plugin then writes nothing and names the failed check
in its log.

Carrying an actor is a catch, and `catch_update` at `+0x20AD3A0` ends one.
Four callers reach it. Three are on the teleport path: the server's character
control at `+0x23290D0`, the client's copy through a thunk at `+0x860F90`, and
a client state transition at `+0x156EF40`. The fourth, `+0x20AE540`, runs on
the catch component several times a second and drops a catch the carry
animation no longer backs, which a teleport is enough to trip.

The departure sweep asks whether anyone else holds an actor through a thunk at
`+0x1F53D10` into `+0xE1478D0`, and on no it removes it. The plugin hooks that
check and answers yes for an actor whose catch component names a carrier.

`research\verify_carry.py` reads all five out of the executable and checks
them, which is the test to run first if an update breaks the mod.

## Licence

MIT. Third party notices are in THIRD_PARTY_NOTICES.md.
