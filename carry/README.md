# Bounty Teleportation

Fast travel while carrying a bounty target. He rides along on your back and is
still worth turning in at the other end. For Crimson Desert exe 1.0.0.2944,
1.0.0.2949, 1.0.0.2976, 1.0.0.3392, 1.0.0.3424, 1.0.0.3446, 1.0.0.3460,
1.0.0.3462 or 1.0.0.3479. 3392 is the DLC update and 3424 and 3446 its
hotfixes. 3460 came out on 31 October, and 3462 and 3479 on 1 November.

In the unmodded game the teleport happens and he does not. You arrive alone.

## Install

1. Ultimate ASI Loader in `bin64`, next to CrimsonDesert.exe. If it is named
   version.dll and nothing loads, rename it to winmm.dll.
2. With the game closed, copy `BountyTeleportation.asi` into bin64. The
   first time the game starts with it, it writes `BountyTeleportation.ini`
   beside itself with both settings on. An ini from an earlier version is
   kept as it is.

Uninstalling is deleting the BountyTeleportation files from bin64.

## Settings

Both are on out of the box and neither normally needs touching. The ini is
read once, when the game starts.

- **KeepCatch** (1) Keeps hold of the catch through the teleport. Four places
  let go of one and all four are skipped, but only from the moment a map
  teleport starts with you holding someone until that carry ends, and only
  for you and the one you carry. Everyone else, and you the rest of the time,
  lets go of things exactly as the game always has.
- **KeepCarried** (1) Keeps the man himself. Leaving a field removes every
  actor spawned in it unless something says it still holds him, and this says
  so. On its own it does nothing, because the release runs first and clears
  the flag it reads.

## Stuck carrying something

1.0.0 skipped the four releases for the whole session. They are also how the
game finishes petting an animal, puts away a note you have read and drops a
bounty when a grab is interrupted, so players got frozen over dogs, stuck
holding notes they had stored, and wearing half-grabbed outlaws. 1.0.1 only
skips them during a teleport carry.

If you are ever stuck anyway, set `KeepCatch=0`, start the game once, and it
clears. Then send the log.

## If something is wrong, send the log

Nothing can be fixed without it. `BountyTeleportation.log` is written beside
the plugin in bin64 and is a few dozen lines, so attach the whole file. It
says every time a teleport armed the four releases and every time they came
back out, and if a problem happened with no teleport line near it, that shows
this mod was not involved. When a carry ends, and when you teleport holding
nothing, it also lists which of the game's releases let go of whatever was
being carried, which is how a conflict with another mod gets pinned down.

The log from the session before is `BountyTeleportation.01.log`, and older
ones go up to `.24`, so if you have already restarted the game, attach the one
from the session where it happened. Post it on the bugs tab or as a GitHub
issue.

Eight addresses are written or hooked and each is checked against the bytes
that should be there first. The plugin carries a set of them for each game
build it knows, 1.0.0.2944, 1.0.0.2949, 1.0.0.2976, 1.0.0.3392, 1.0.0.3424,
1.0.0.3446, 1.0.0.3460, 1.0.0.3462 and 1.0.0.3479, and uses whichever the game matches. On a game update matching none
of them it writes nothing, hooks nothing, and the log says so. Everything it
wrote is put back if it is unloaded.

The 21 September 2026 game patch moved every one of those addresses, which is
why 1.0.0 and 1.0.1 stopped doing anything on it. The 23 September patch moved
them again, and 1.0.2 stops the same way on it. The DLC update of 29 October,
exe 1.0.0.3392, moved them all once more, and 1.0.9 stops on that one. The
hotfix of 30 October, exe 1.0.0.3424, moved them again, and a second hotfix
the same day, exe 1.0.0.3446, moved them once more. 1.0.10 has a set for 3392
and 3424 and stops on 3446. 1.0.11 adds a set for 3446. The patch of 31
October, exe 1.0.0.3460, moved them all again without changing the code
behind them. 1.0.11 stops on it, and 1.0.12 adds a set for 3460. The patch
of 1 November, exe 1.0.0.3462, moved four of them. 1.0.12 stops on it, and
1.0.13 adds a set for 3462. The second patch that day, exe 1.0.0.3479,
moved all of them again. 1.0.13 stops on it, and 1.0.14 adds a set for 3479.

Do not run this alongside Bounty Probe, the research plugin it came out of.
They patch the same bytes and hook the same function, and the second one
loaded refuses and says so.

## Known conflict

Even Faster Vanilla Animations Trimmer by kuiye123, part of Skip All Loading
Scene, left the bounty behind up to 1.0.4. Its KLIFF TELEPORT category cuts
the start and end of Kliff's teleport sequence to almost nothing, and the game
then let go of the bounty about 60 ms before this mod started holding the
carry. 1.0.5 starts holding at that earlier moment, so the trimmer can stay on.
zx3691 played it with KLIFF TELEPORT on and the bounty came through. zx3691
found the conflict, hansdepaula narrowed it to that category, and zx3691's
logs named the release and confirmed the fix.

A different part of the game can let go early too. thatswedishdad's log had
the client's character control doing it, where 1.0.5 only watched the state
transition. 1.0.6 starts holding early from either one, and thatswedishdad
carried their bounty through with it. If the bounty is left behind, send the
log.

## Crashes on 1.0.6

1.0.6 could crash the game in quest cutscenes, such as Chapter 6 when Yann
enters or "Find William in Ivynook". It mistook an NPC letting go of someone
for the start of a teleport and kept that grip on, and while a bounty was
being carried it held every character's grip in the game along with yours.
1.0.7 reacts only to your own character and the one you carry.

## Stuck carries after cutscenes on 1.0.7

On 1.0.7, carrying someone into a quest cutscene could leave them stuck to
Kliff, such as the sheep you bring back to the child or the man you carry out
of the burning house. The scene lets go of them the way a shortened teleport
does, and 1.0.7 held on and never let go when no teleport came. 1.0.8 lets go
the way the game asked if no teleport follows within half a second. If someone
is still stuck to you, send the log.

## The bounty as Damiane or Oongka

kuodo20's logs showed the bounty being left behind when the trimmer's KLIFF
TELEPORT was on and the character was Damiane or Oongka. Those two have their
own body in the world, and the early hold only recognised Kliff's. 1.0.9
learns the body from each map teleport and holds for it too. The first trimmed
teleport of a session as Damiane or Oongka can still lose the bounty, since
nothing has been learned yet. If it is left behind, send the log. 1.0.9 was not
tested in play.

## The DLC update

1.0.11 runs on the DLC update, exe 1.0.0.3392, and on both of its hotfixes,
1.0.0.3424 and 1.0.0.3446. Seth carried an outlaw through a map teleport as
Kliff on each. 1.0.12 adds the 31 October patch, 1.0.0.3460, and was not
tested in play on it. The DLC also added a new way for the game to let go of
a carry, which this mod leaves alone. If your log has a `[release]` line
returning to +0x227A2B8, +0x227B4F8, +0x227C6A8 or +0x227FA68, send it,
because what sets that one off is not known yet.

## Antivirus

The VirusTotal results for each release are on the Nexus page, with links to
the reports. They are not here because this file travels inside one of the
archives it would be reporting on, and quoting a count here changes the
archive it describes.

A scanner may still flag `BountyTeleportation.asi` one day, because the shape
of what it does looks like a trainer to a model: it is a DLL loaded into the
game that writes jumps over four of the game's own functions and hooks four
more. It imports kernel32 and nothing else, so there is no network code and
no window in it, and it reads and writes no registry key and no game file. It
is code signed, and Properties, Digital Signatures shows Seth Walker under
Microsoft's identity-verified chain.

## Licence

MIT. See LICENSE, and THIRD_PARTY_NOTICES.md for MinHook.

Source and the full account of how it was found:
https://github.com/shin2344234/bounty-teleportation
