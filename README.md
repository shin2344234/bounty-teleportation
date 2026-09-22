# Bounty Teleportation

Fast travel while carrying a bounty target in Crimson Desert. He rides along
on your back and is still worth turning in at the other end. Works on 2.03.00
exe 1.0.0.2944 and on the 1.0.0.2949 patch. 1.0.0 was tested in game; 1.0.1
and 1.0.2 went out untested, so reports with the log attached are what shows
whether they work.

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

Six addresses, each checked against the bytes that should be there before
anything is written, and all of it put back if the plugin is unloaded. A game
update moves them, as the 21 September 2026 patch to exe 1.0.0.2949 moved
every one. The plugin holds a table per game build and uses the one whose
addresses all check out; matching none, it writes nothing and names the
closest build's failed check in its log.

`research\derive_2949.py` and `derive_2949b.py` are how the second table was
found, each address from a byte pattern or from a reference to something
already found rather than an offset against the old build. They are the
starting point for the next patch. `find_2949.py` was the first pass over the
patched executable and only counts pattern hits; the derive scripts replaced
it.

The four catch releases are only written during a teleport carry. 1.0.0 wrote
them for the whole session, and they turned out to be how the game also ends
petting an animal, putting a note away and an interrupted grab, so players got
stuck in all three. 1.0.1 hooks the map teleport handler at `+0x2BC9640`,
which has two callers, both in the teleport's message handler, and which moves
the player before calling the first release at `+0x2BC9928`. If the player is
holding something when it starts, the releases are written there, and they
come out again when the sweep keeps nobody within five seconds, when the kept
outlaw is no longer carried, or when the player is no longer holding
anything.

Addresses below are the 1.0.0.2944 ones. Carrying an actor is a catch, and
`catch_update` at `+0x20AD3A0` ends one.
Four callers reach it. Three are on the teleport path: the server's character
control at `+0x23290D0`, the client's copy through a thunk at `+0x860F90`, and
a client state transition at `+0x156EF40`. The fourth, `+0x20AE540`, runs on
the catch component several times a second and drops a catch the carry
animation no longer backs, which a teleport is enough to trip.

The departure sweep asks whether anyone else holds an actor through a thunk at
`+0x1F53D10` into `+0xE1478D0`, and on no it removes it. The plugin hooks that
check and answers yes for an actor whose catch component names a carrier.

`research\verify_carry.py` reads all six out of the executable and checks
them, which is the test to run first if an update breaks the mod.

## Antivirus

VirusTotal counts 1.0.2's archives at 0/68 for the DMM one and 0/55 for the
manual one, and 1.0.2's loose plugin at 1/70. The one is Microsoft, returning
Trojan:Win32/Wacatac.B!ml, the label it gives a file its model dislikes rather
than one it recognises. Three other readings of the same day disagree with it.
Desktop Defender finds nothing in that file on engine 1.1.26080.3 with the
22 September 2026 definitions. Microsoft's engine passed the plugin when it
scanned it inside both archives. And 1.0.1's plugin, resubmitted the same
afternoon, still came back 0/68 with Microsoft among the engines that cleared
it, though it differs from 1.0.2 only in the second build table and the code
that picks between them.

The plugin imports kernel32 and nothing else, reads and writes no registry key
and no game file, and is signed under Microsoft's identity-verified chain as
Seth Walker. A model looking at a DLL that writes jumps over four of a game's
own functions has something to object to. Every line of it is here so you can
check the objection yourself.

## Licence

MIT. Third party notices are in THIRD_PARTY_NOTICES.md.
