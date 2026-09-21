# Bounty Teleportation

Fast travel while carrying a bounty target. He rides along on your back and is
still worth turning in at the other end. For Crimson Desert 2.03.00, exe
1.0.0.2944.

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
  let go of one and all four are skipped.
- **KeepCarried** (1) Keeps the man himself. Leaving a field removes every
  actor spawned in it unless something says it still holds him, and this says
  so. On its own it does nothing, because the release runs first and clears
  the flag it reads.

## Before you report a stuck carry

KeepCatch's fourth patch is the game's own cleanup for a catch that has gone
stale, and it is off for every catch in the world rather than only yours. It
exists to unstick a carry whose animation died. If a pickup ever breaks
halfway and leaves you stuck carrying nothing, set `KeepCatch=0`, start the
game, and it clears.

## If something is wrong

`BountyTeleportation.log` is written beside the plugin and is about twenty lines a
session. It names every address it wrote and every time it told the game to
keep somebody. Attach it to a post on the bugs tab or a GitHub issue.

Five addresses are written or hooked and each is checked against the bytes
that should be there first. On a game update they will not match, and the
plugin then writes nothing and says in the log which check failed. Everything
it wrote is put back if it is unloaded.

Do not run this alongside Bounty Probe, the research plugin it came out of.
They patch the same bytes and hook the same function, and the second one
loaded refuses and says so.

## Antivirus

VirusTotal counts 1.0.0 at 0/70 for the plugin, and both archives come back
clean as well. The Nexus page carries the per-archive numbers and links to
the reports; they are left out here because this file travels inside one of
the archives it would be reporting on.

A scanner may still flag `BountyTeleportation.asi` one day, because the shape
of what it does looks like a trainer to a model: it is a DLL loaded into the
game that writes jumps over four of the game's own functions and hooks a
fifth. It imports kernel32 and nothing else, so there is no network code and
no window in it, and it reads and writes no registry key and no game file. It
is code signed, and Properties, Digital Signatures shows Seth Walker under
Microsoft's identity-verified chain.

## Licence

MIT. See LICENSE, and THIRD_PARTY_NOTICES.md for MinHook.

Source and the full account of how it was found:
https://github.com/shin2344234/bounty-teleportation
