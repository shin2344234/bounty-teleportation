# Bounty Teleportation

Fast travel while carrying a bounty target in Crimson Desert. He rides along
on your back and is still worth turning in at the other end. Works on 2.03.00
exe 1.0.0.2944, on the 1.0.0.2949 and 1.0.0.2976 patches, on 1.0.0.3392,
the DLC update of 29 October 2026, and on 1.0.0.3424 and 1.0.0.3446, the two
hotfixes of 30 October. Before release, Seth carried an outlaw through a map
teleport with 1.0.3 and with 1.0.4 on 1.0.0.2976, did it again with the 3392
table on 1.0.0.3392, with 1.0.10 on 1.0.0.3424, and with a 1.0.11 test build
on 1.0.0.3446. 1.0.5 went out untested and a player confirmed it the same
day. The fix in 1.0.6 went to one player as a test build
first, and they carried their bounty through with it. 1.0.1, 1.0.2, 1.0.7,
1.0.8 and 1.0.9 went out untested.

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

`carry\scripts\sign.ps1` signs the plugin and `carry\scripts\package.ps1` then
checks the eight addresses against the game, builds the two archives and prints
their checksums.

## What it patches

Eight addresses, each checked against the bytes that should be there before
anything is written, and all of it put back if the plugin is unloaded. A game
update moves them, as the 21 September 2026 patch to exe 1.0.0.2949 moved
every one, the 23 September patch to 1.0.0.2976 moved them again, the DLC
update of 29 October to 1.0.0.3392 moved them a third time, and the two
hotfixes the next day, 1.0.0.3424 and 1.0.0.3446, moved them twice more. The
plugin holds a table per game build and uses the one whose addresses all check
out. Matching none, it writes nothing and names the newest build's failed
check in its log.

`research\derive_2949.py` finds each address from a byte pattern or from a
reference to something already found, never from an offset against the old
build, and it found both later tables unchanged. `derive_2949b.py` confirmed
the 2949 table by its vtables and thunk, which had not moved. On 2976 they had,
so `derive_2976b.py` reads the class name behind each vtable instead and picks
the sweep's call out of the holder thunk's eleven callers by its offset inside
its function. Those scripts are the starting point for the next patch.
`find_2949.py` was the first pass over the 2949 executable and only counts
pattern hits.

The four catch releases are only written during a teleport carry. 1.0.0 wrote
them for the whole session, and they turned out to be how the game also ends
petting an animal, putting a note away and an interrupted grab, so players got
stuck in all three. 1.0.1 hooks the map teleport handler at `+0x2BC9640`,
which has two callers, both in the teleport's message handler, and which moves
the player before calling the first release at `+0x2BC9928`. If the player is
holding something when it starts, the carry is armed there, and it ends when
the sweep keeps nobody within five seconds, when the kept outlaw is no longer
carried, or when the player is no longer holding anything.

Up to 1.0.6 arming wrote the four patches, which skip each release for every
catch in the game, NPCs' included. Since 1.0.7 the `catch_update` hook does the
skipping instead, and only for the player's catch, the outlaw's, and a client
catch holding the outlaw. Each patch jumps from its guard to the instruction
after the call, over a block that only loads the call's arguments, so
returning from the hook without calling through is the same thing for one
catch. The patches are still written if the hook cannot go in. An actor's
handle is the dword at `+0x60`, before its component table, and a component's
actor is at its `+8`; the player-tagged actor is `0xA0100001`.

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

The seventh is `catch_update` itself. Besides the skipping above, every call on a
catch that is holding or carried something is remembered with the address it
returns to, and the log lists the recent ones when a carry ends and when a map
teleport starts with nothing held. On 24 September 2026 two players found
the KLIFF TELEPORT patch of Even Faster Vanilla Animations Trimmer leaving the
bounty behind, and no log could say which release had let go.

The eighth is the catch component's tick, `+0x20AE5A0` on 2976, the function
the watchdog release sits in. Since 1.0.8 a release that an early hold skipped
is made again there when no teleport follows, so it runs on the thread and side
it was meant for. `catch_update` picks the server's actors or the client's from
a thread-local flag, which is why the plugin's own thread cannot make that call.

`research\verify_carry.py` reads all eight out of the executable and checks
them, which is the test to run first if an update breaks the mod.

## Known conflict

Even Faster Vanilla Animations Trimmer by kuiye123, part of Skip All Loading
Scene, left the bounty behind up to 1.0.4. Its KLIFF TELEPORT category cuts
the start and end of Kliff's teleport sequence to almost nothing, and the game
then let go of the bounty about 60 ms before this mod started holding the
carry. 1.0.5 starts holding at that earlier moment, so the trimmer can stay on.
zx3691 played 1.0.5 with KLIFF TELEPORT on the day it came out and the bounty
came through, and their log shows the early hold taking effect 60 ms before the
teleport handler. zx3691 found the conflict, hansdepaula narrowed it to that
category, and zx3691's logs named the release and confirmed the fix.

## Crashes in 1.0.6

Five players reported crashes on 1.0.6, four in quest cutscenes, among them
Chapter 6 when Yann enters and "Find William in Ivynook". gamniac's crash dump
is a stack overflow on the game's main thread: `+0x141A900`, which numbers a
graph by depth, called itself 347,922 times, the way it does when the graph
has a loop. Their DMM history crashed with this plugin as the only ASI. 1.0.6
armed early on any catch that let go through a teleport release, an NPC's in a
cutscene included, then skipped the releases for every catch in the game and
let the sweep keep any carried actor. 1.0.7 arms early only on the player's own
catch, skips releases only for the player's carry, and keeps only an actor the
player carries. It went out without a play test.

1.0.5 only started early when the client's state transition let go first.
thatswedishdad's log on 27 September 2026 had the client's character control
letting go 78 ms before the teleport handler instead, with no trimmer named,
and the bounty stayed behind. 1.0.6 starts early from any of the three
teleport releases. thatswedishdad ran it as a test build and the bounty came
through.

## Stuck carries after cutscenes in 1.0.7

wanjia1234566 reported on 10 October 2026 that on 1.0.7 a carried actor stays
stuck to Kliff once a quest cutscene starts: the sheep brought back to the
child who lost it, and the man carried out of the burning house. The scene ends
the player's catch through a client release, and 1.0.7 took that for a
shortened teleport, held the catch and skipped the release. With no teleport
coming, it disarmed a second later, but nothing made the skipped release
again, so the catch stayed on.

1.0.8 keeps every release it skips while an early hold waits for its teleport.
If no teleport handler runs within 500 ms, it makes each one again at that
catch's next tick, provided the catch still holds the same actor. The early
hold now starts only from the two client releases. The server's character
control is called by the teleport handler after it arms, so it never comes
first in a teleport, and 1.0.6 and 1.0.7 were wrong to start from it. 1.0.8
went out without a play test, and wanjia1234566 sent no log, so the cause is
read from the code rather than seen in a log.

## The early hold as Damiane or Oongka

kuodo20's logs from 24 September 2026 show the carried outlaw held by
`0xB0100002`, where every log from a Kliff player says `0xA0100001`. Playing
Damiane or Oongka, the body on screen is its own `0xB0` actor, and the catch
belongs to that body. The early hold, the one the trimmer's KLIFF TELEPORT
depends on, only accepted `0xA0100001` since 1.0.7, so for those two characters
a trimmed teleport left the bounty behind again.

1.0.9 notes the actor and handle that every map teleport moves, and accepts an
early release from that same actor object as well as from `0xA0100001`. A
teleport as Kliff, or the Kliff identity seen holding someone, forgets it, so
after switching back an NPC's catch is never held the way 1.0.6 held them. The
first trimmed teleport of a session as Damiane or Oongka still has nothing
learned and can lose the bounty. The log says which body it learned and its
class.

Two smaller changes came with it. When the four release patches are only
partly written because one is refused, the written ones go back, and a failed
write-back when a carry ends is logged. 1.0.9 builds and went out without a
play test.

## The DLC update

Exe 1.0.0.3392 moved all eight addresses, so 1.0.9 matches none of its builds
there and does nothing. 1.0.10 adds a table for it. Two things changed besides
the addresses. The character control release moved from vtable slot 0x200 to
0x1F8, and 0x200 is now a stub that returns 0, so each build names the slot it
reads. The map teleport handler starts with different bytes too, so each
build names the 15 bytes it checks there. `research\verify_carry.py` checks
both per build and takes the path of an exe to read.

The DLC also added a client docking release, at return address +0x227A2B8 on
3392, +0x227B4F8 on 3424 and +0x227C6A8 on 3446. The plugin never skips it.
What triggers it in play is not known yet, and a `[release]` line naming it is worth a report.

Seth played the 3392 table on 29 October 2026 as Kliff. An outlaw came through
a map teleport, the departure sweep kept him, asked from +0x2A52751, and the
four releases went back to the game's own when the carry ended 35 seconds
later. Damiane and Oongka, the trimmer's KLIFF TELEPORT, and petting, notes
and broken grabs have not been played on 3392.

The hotfix of 30 October, exe 1.0.0.3424, moved every address again, by
0x1130 to 0x14DD00 depending on where in the exe it sits. The release slot is
still 0x1F8 and the teleport handler still starts with the 3392 bytes.
`patch-dlc\work\bounty-teleportation\3424\compare.py` pairs each function the
plugin touches with its 3392 counterpart. Eleven of the thirteen are the same
code moved. The client release and the holder check each load one constant
differently. The client release's 8 is read from a table on 3392 and written
inline on 3424, and the holder check's 0xFFFFFFFF goes the other way. The
blocks the plugin patches or hooks in those two are byte for byte the same.

Seth played the signed 1.0.10 on 3424 on 30 October as Kliff. The sweep kept
the outlaw, asked from +0x2A539E1, and the releases went back to the game's
own 24 seconds later. The same things are unplayed on 3424 as on 3392.

A second hotfix came out at midday on 30 October, exe 1.0.0.3446, and moved
every address once more. Most moved by 0xBB0 to 0x1950. The client release
moved 0x2884F0 lower, still behind a thunk in vtable slot 0x1F8. The holder
check changed more. On 3392 and 3424 the sweep called a thunk that jumped to
the check far up the exe, at +0xC9F4A10 on 3424. Now the sweep calls the
check directly, at +0x21388B0, near where the thunk used to be. So a build's
thunk can be 0, and for such a build the plugin makes sure the sweep's call
lands on the check itself. `patch-dlc\work\bounty-teleportation\3446\compare.py` pairs each
function with its 3424 counterpart. Eight are the same code moved. In four of
the other five only a jump table at the end differs, and every entry in it
moved by the function's own shift. The fifth is the holder check, which writes
its 0xFFFFFFFF inline where 3424 loaded it from a global, and is otherwise
the same. Seth played the 1.0.11 test build on 3446 that afternoon as Kliff.
The sweep kept the outlaw, asked from +0x2A55061, and the releases went back to
the game's own 14 seconds later.

## Antivirus

VirusTotal counts 1.0.11's loose plugin at 0/71, its DMM archive at 0/67 and
the manual archive at 0/63. The plugin read 0/70 for 1.0.0, 0/71 for 1.0.1,
and 0/71 for each of 1.0.3 to 1.0.10. 1.0.2's read 1/70, the one being Microsoft's
Trojan:Win32/Wacatac.B!ml, the label it gives a file its model dislikes rather
than one it recognises. Desktop Defender found nothing in that file, and
Microsoft passed the same plugin inside both 1.0.2 archives. Every release
since has been clean, 1.0.4 to 1.0.7 with a third hook in them and 1.0.8
with a fourth. 1.0.9 came back clean as well, and so did 1.0.10 and 1.0.11
with their tables for the DLC and its hotfixes.

The plugin imports kernel32 and nothing else, reads and writes no registry key
and no game file, and is signed under Microsoft's identity-verified chain as
Seth Walker. A model looking at a DLL that writes jumps over four of a game's
own functions has something to object to. Every line of it is here so you can
check the objection yourself.

## Licence

MIT. Third party notices are in THIRD_PARTY_NOTICES.md.
