# Bounty Teleportation

Fast travel while carrying a bounty target. He rides along on your back and is
still worth turning in at the other end. For Crimson Desert exe 1.0.0.2944,
1.0.0.2949 or 1.0.0.2976.

In the unmodded game the teleport happens and he does not. You arrive alone.

## Install

1. Ultimate ASI Loader in `bin64`, next to CrimsonDesert.exe. If it is named
   version.dll and nothing loads, rename it to winmm.dll.
2. With the game closed, copy `BountyTeleportation.asi` and `BountyTeleportation.ini` into
   bin64. If you only copy the plugin it writes the same ini itself the first
   time you run it.

Uninstalling is deleting those files.

## Settings

Both are on out of the box and neither normally needs touching. The ini is
read once, when the game starts.

- **KeepCatch** (1) Keeps hold of the catch through the teleport. Four places
  let go of one and all four are skipped, but only from the moment a map
  teleport starts with you holding someone until that carry ends. The rest of
  the time the game lets go of things exactly as it always has.
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

Seven addresses are written or hooked and each is checked against the bytes
that should be there first. The plugin carries a set of them for each game
build it knows, 1.0.0.2944, 1.0.0.2949 and 1.0.0.2976, and uses whichever
the game matches. On a game update matching none of them it writes nothing,
hooks nothing, and the log says so. Everything it wrote is put back if it is
unloaded.

The 21 September 2026 game patch moved every one of those addresses, which is
why 1.0.0 and 1.0.1 stopped doing anything on it. The 23 September patch moved
them again, and 1.0.2 stops the same way on it.

Do not run this alongside Bounty Probe, the research plugin it came out of.
They patch the same bytes and hook the same function, and the second one
loaded refuses and says so.

## Antivirus

The VirusTotal results for each release are on the Nexus page, with links to
the reports. They are not here because this file travels inside one of the
archives it would be reporting on, and quoting a count here changes the
archive it describes.

A scanner may still flag `BountyTeleportation.asi` one day, because the shape
of what it does looks like a trainer to a model: it is a DLL loaded into the
game that writes jumps over four of the game's own functions and hooks three
more. It imports kernel32 and nothing else, so there is no network code and
no window in it, and it reads and writes no registry key and no game file. It
is code signed, and Properties, Digital Signatures shows Seth Walker under
Microsoft's identity-verified chain.

## Licence

MIT. See LICENSE, and THIRD_PARTY_NOTICES.md for MinHook.

Source and the full account of how it was found:
https://github.com/shin2344234/bounty-teleportation
