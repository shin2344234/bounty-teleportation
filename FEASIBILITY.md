# Teleporting while carrying a bounty target

Static analysis only, 20 September 2026. Game build 2.03.00, exe 1.0.0.2944, at
`D:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert.exe`. The
game was never launched for any of this. Every RVA is relative to image base
`0x140000000`. Table work reads `master looter\extracted`, which is the 2.03.00
extraction. Scripts are in `research\` and all of them import `cdimage.py` from
`No more flight restrictions\private\research`.

## Short answer

**It works.** Two settings do it, `KeepCatch` and `KeepCarried`, and the
18:51 run of 20 September 2026 carried a live bounty outlaw through a map
teleport and set him down at the destination still on the player's back.
Seth's word on that trial was that it worked perfectly.

Four patches and one hook are the whole mod. `KeepCarried` answers the
departure sweep's "does anyone else hold this actor" with yes for a carried
one, which is what stops the outlaw being torn down with the field being
left. `KeepCatch` skips the four places that let a catch go: three on the
teleport path, and a watchdog on the catch component that drops any catch
the carry animation no longer backs, which a teleport is enough to trip.
Six trials went into finding the fourth, because the first three were each
found by reading the last call before the state changed, and the fourth
only gave itself up to an instrument that watched the bytes.

The shipping plugin is `carry\`, which applies those five addresses and does
nothing else: no sites, no dumps, no watchers, a log of about twenty lines a
session. `research\verify_carry.py` reads every one of them out of the exe
and checks it. `mod\` stays what it was, the probe that found them.

The rest of this file is how it was found, oldest reading first, including
the readings that were wrong.

The first gate is a policy check and a one-byte patch removes it cleanly.
Behind it is a second refusal that is not a policy check at all: a pointer the
field move needs is null while the player is carrying, and the code that
follows dereferences it. Skipping that one crashes. Fast travel empty-handed
still works with the patch in, so the carry is what makes the pointer missing.

**Both of those readings were wrong about whose refusal it was.** Every
`eErrNoFieldMoveHolding` and `eErrNoCantEnterToField` the probe ever caught,
across seventeen kept sessions including the ones with the first gate patched
out, sits on a component whose actor is a `ServerNormalInGameActor`. The
player character is a `ServerChildOnlyInGameActor`, a child of the
`ServerUserActor`, and no refusal was ever on it. The field-move handler is
per actor and runs for every actor that streams in; what it refused was NPCs
being created before they had a field. With a live, tied outlaw on his back
the player is not refused at all: the map teleport goes through and the
outlaw stays behind. There is no gate to remove.

What the teleport does about the catch is the question now, and session
eight's log put the order of events on the table. At the map confirm the
field-move handler `+0x2BCD820` runs for the outlaw, not the player, and four
milliseconds later the outlaw holds no field; three seconds after that the
destination's sector reload begins; seven seconds after the confirm the same
handler runs for the player, three times, and the player never loses his
field at all. The reload re-creates nothing of the player's (his class is
spawned twice a session, both at the first load), so nothing that hangs off a
spawn descriptor can bring the outlaw along, and the re-catch at the
destination is the game's own path for NPCs whose spawn data says they are
born carrying a prop. Whatever moved the outlaw away at the confirm, and
whatever moves the player seven seconds later, are the two calls the mod has
to change, and session nine's probe traces both actors through them. The
position-warp route on Nexus stays as the fallback.

## What the block actually is

The on-screen wording is "Cannot teleport in the current state." Players quote
it verbatim, including a reddit thread titled with that sentence, so the string
is the right one to chase. It is `localstringinfo` row key `0x6599F0AD`
(1704587437), pointing at `localstringinfo.paloc` entry 7321147295087460528.
That key appears nowhere in the exe as an immediate, which is expected: this
game resolves string and error identifiers at startup instead of baking them
in, the same finding A2 recorded for the `eErrNoCallVehicle*` family.

The error behind it is `eErrNoFieldMoveHolding`. "Field move" is this game's
name for fast travel, which rides `TrMoveFieldAck`, `TrSetMoveFieldAck` and
`TrMoveFieldCompleteAck`. The name string sits at RVA `+0x5932780` and is unique
in the binary, as is the word "Holding" anywhere in the symbol set.

Running A2's derivation on it, `Z_lea = name_lea - 0x1C`, gives the global that
holds its hash: `+0x6CF6B5C` in `.sbss`. **Three instructions read that global**,
and they are in three different functions. The scan covered `8B` and its REX
forms across both executable sections:

| reader | section | handler | size | branch |
|---|---|---|---|---|
| `+0x2BCD88A` | `.code` | `+0x2BCD820` | 5,324 | `75` jne |
| `+0x10C71204` | `.didata` | `+0x10C71160` | 430 | `74` je |
| `+0x10C7826F` | `.didata` | `+0x10C78190` | 668 | `74` je |

An earlier pass here said there was one, because it scanned only the section
named `.code`. That was wrong, and the section names are why: this exe has two
executable sections and neither name means what it says. `.code` holds 218,224
functions and `.didata` holds 26,218 and the process entry point. Both carry
unwind entries, both are marked executable, and calls cross between them. Any
scan of this binary that stops at `.code` is reading two thirds of the code.

The first of the three is the one worked through below. The other two raise
neighbouring errors that say what they are: `+0x10C71160` also raises
`eErrNoInvalidField`, and `+0x10C78190` also raises `eErrNoInvalidUserActor`
and `eErrNoInvalidFieldInfoKey`, which reads like a second request path. Which
of the three refuses a map teleport is not decidable from the file, and it is
the first thing a probe session settles.

The `.code` site:

    +0x2BCD876  mov   r14, [rcx+8]
    +0x2BCD87A  lea   rdx, [rbp-8]
    +0x2BCD87E  call  +0x2BC4200              ; this+0x4F0, locks something out to [rbp-8]
    +0x2BCD884  cmp   byte [rbp+8], sil       ; 40 38 75 08     sil is zero here
    +0x2BCD888  jne   +0x2BCD8D8              ; 75 4E           the whole gate
    +0x2BCD88A  mov   eax, [rip+0x41292CC]    ; eErrNoFieldMoveHolding
    +0x2BCD890  mov   [rbx], eax              ; *out_err = it
    ...                                       ; tears the frame down and returns

So the refusal is the first thing the handler does, before any work. The patch
that removes it is `75` to `EB` at `+0x2BCD888`, two bytes read and one written,
which is the same edit Flight Freedom makes for `AbyssSummon` and
`PlatformSummon`. The other two handlers take the same edit on a `74` rather
than a `75`: the polarity is reversed there, so the opcode has to be read
rather than assumed.

The containing function starts at `+0x2BCD820`, runs 5,324 bytes, and has three
callers. No RTTI name came back for it. Its
neighbourhood names it well enough: within `+0x2BC6000..+0x2BD2000` the other
errors are `eErrNoInvalidField`, `eErrNoInvalidFieldInfoKey`, `eErrNoClosedField`,
`eErrNotFoundFocusActor`, `eErrNoInvalidTransformSyncActorComponent` and
`eErrNoInvalidCharacterControlActorComponent`, and a little further out the
region is full of `Tr` request handlers ending in `eErrNoInvalidTrData`. This is
the field-transition handler, on the server side of the in-process split.

## What the carry is

Carrying a bounty target is a catch. The classes are
`CommonCarryCatchInteractionProcessor`, `CommonCatchActorComponent` and
`ClientCatchActorComponent`. `conditioninfo` row 1000077 reads
`IsSpawnOwner() && CheckSpawnReason(CatchSpawn) && !CheckCatched()`, so the
target stays a live actor for the whole carry, spawned with reason `CatchSpawn`
and owned by the player.
The error set around it is large and specific: `eErrNoForceReleaseCatch`,
`eErrNoSpawnParentCatcherLogout`, `eErrNoLogoutBySummonForceReleaseCatch`,
`eErrNoRequestLogoutByReleaseCatch`, `eErrNoCantDoWhileCatchingOrCatched`. The
game has named, deliberate handling for what happens to a catch when its owner
leaves, which is a hint that the designers thought about this case and chose the
refusal.

## Why that matters more than the patch

Glint Spotter's own session logs say what a teleport does to the actor set. Five
access violations landed inside `actors.cpp` across three sessions on 16
September, all within half a minute of a teleport, all on objects that had been
freed and their memory reused. The same notes record the player read flipping
between his real position and a point near the origin while a world loads, by
10.7 to 12.5 km, sometimes every pass for minutes. A field move is a full world
unload and reload, and client-side actors do not survive it.

That fits what players report when they get round the block another way: the
prisoner is gone at the destination and turns up back at the spawn point the
bounty started from. Removing the gate gets the handler to run. It does not by
itself make the server re-create a `CatchSpawn` actor at the far end and hand
the catch relationship back.

So the honest reading is that the patch is cheap and the outcome is a coin toss
that only a live test settles. Three things it could do, and nothing in the file
picks between them:

- the target rides through, because the catch is server state and the reload
  restores it
- the target is dropped and respawns at its bounty origin, which is the current
  behaviour by another road, so it wastes the player's time without breaking
  anything
- the handler proceeds with a dangling child actor and the process faults

## Open questions

Answered by session three, kept because the reasoning behind each was wrong in
a way worth remembering:

- ~~The sense of the branch is inferred.~~ The handler does reach the error
  store, so falling through the `jne` at `+0x2BCD888` is the refusing path and
  turning it into a `jmp` is the edit.
- ~~There may be a second gate on the client.~~ There is not. The request
  reaches the server-side handler and is refused there.
- ~~Which of the three handlers refuses is unknown.~~ `+0x2BCD820`. The other
  two ran and refused nothing.

Still open:

1. **What happens to the carried target once the handler runs.** This is the
   whole remaining risk and only turning `Unblock` on answers it. Back the save
   up first.
2. **Nothing here has been checked against 2.02.00.** All addresses are 2.03.00.

## What the probe has shown so far

Three sessions on 20 September 2026, all with `Unblock=0`.

**The refusal was caught, twice, and it comes from `+0x2BCD820`.**

    fieldmove1 call 6748 returned 2615297641 (0x9BE24669) = eErrNoFieldMoveHolding,
      called from +0x2BCCE78 with rcx=<ServerTransformSyncActorComponent>

Both refusals came through the same caller, `+0x2BCCE78` inside `+0x2BCCE30`,
with a `ServerTransformSyncActorComponent` as `this`, whose `+0x008` is the
player's `ServerNormalInGameActor`. The two handlers in `.didata` were called
1,984 and 6 times across the session and refused nothing, so the one the static
analysis started from is the gate after all. The doubt recorded below, that a
function called 36,675 times cannot be a request handler, was wrong: it is hot
and it refuses.

**The client does not refuse first.** The request reaches a server-side handler
and is turned down there, so the world map is not quietly greying anything out.
That closes the second open question, which was the one that could have made
the patch look like it did nothing.

`+0x2BC4200`, the call the branch follows, hands back a `FieldAttacherForActor`
rather than an error, so reading its out pointer as an error code counted all
533,705 of its calls as refusals. It is not the predicate either: that is the
comparison between the call and the jump, reading a local. The hook is off by
default now.

**Session four turned the first gate off and found a second behind it.**

    [patch] Unblock1 at +0x2BCD888: was 75 4E, now EB 4E
    fieldmove1 call 7001 returned 2692856268 (0xA081B9CC) = eErrNoCantEnterToField,
      called from +0x2BCCE78 with rcx=<ServerTransformSyncActorComponent>

The patch applied to the bytes it expected and `eErrNoFieldMoveHolding` stopped
appearing. Both attempts then died in the same handler, from the same caller,
with `eErrNoCantEnterToField`: twice in 22,013 calls, so it is still firing on
the attempts and not in ordinary play.

Nothing inside `+0x2BCD820` raises that error. A callee does and the handler
passes it up through the same out pointer. Four functions in the image raise
it, and all four are hooked by name in the ini now:

| function | section | size | callers | also raises |
|---|---|---|---|---|
| `+0x2827CD0` | `.code` | 8,458 | 2 | `eErrNoInvalidSceneObjectUUID` |
| `+0x2AF8010` | `.code` | 1,527 | 1 | |
| `+0x2AF8660` | `.code` | 1,025 | 1 | raises it twice |
| `+0x10BB9790` | `.didata` | 725 | 1 | |

The name reads like a check on the destination rather than on what is being
carried, which would mean either that the carried actor makes the destination
refuse, or that this refusal was always there and the holding check simply
reached it first. A teleport attempt with empty hands separates the two: if
this never fires without a target on the player's shoulder it is about the
carry.

**Session five: the patch does not break ordinary fast travel.** With
`Unblock=1` and empty hands, a map teleport works normally. So
`eErrNoCantEnterToField` is carry-dependent, and the first patch is behaviourally
neutral everywhere else.

**Session six: the second refusal is a missing object.** `fieldlookup`
(`+0x2AF99D0`) was called 23,178 times and never once returned null, while
`enterfield2` refused twice in the same session. The error store is reached by
a second path, and the first guess at "the two bytes before the load are the
branch" was wrong here: that rule held for the first gate and does not
generalise. Disassembling `+0x2AF8010` from its own entry rather than from an
offset shows both paths, and the live one is 104 bytes earlier:

    +0x2AF8119  mov  rax, [rsi + 0x68]        ; rsi is arg3, the player's ServerNormalInGameActor
    +0x2AF811D  mov  rcx, [rax + 0x1a0]
    +0x2AF8124  mov  r12, [rcx + 0x540]
    +0x2AF812B  test r12, r12
    +0x2AF812E  je   +0x2AF8196               ; eErrNoCantEnterToField

So the refusal is that `[[[actor+0x68]+0x1a0]+0x540]` is null while carrying.
`r12` is the object it wanted, and it is not optional:

    +0x2AF81FA  cmp  r12, r13
    +0x2AF81FD  je   +0x2AF82CC
    +0x2AF8203  mov  r8b, 1
    +0x2AF8206  mov  rdx, [r12 + 8]           ; dereferences it

Turning that `je` into a `jmp` reaches `[r12+8]` with `r12` null and faults.
**The second gate cannot be patched the way the first one was.** The game is
not refusing here, it is failing: the field move wants an object that does not
exist in the carrying state, and making it exist is a different order of work
from flipping a branch.

That also reads as the reason the first gate exists. `eErrNoFieldMoveHolding`
is not an arbitrary rule keeping the player honest; it stops the request before
it reaches code that cannot run while something is being carried.

**Session seven: what players do, and what the first gate actually reads.**

Three workarounds are in circulation on r/CrimsonDesert, and they are not
equal.

- Bonfire wait (March 2026, thread 1rzf6xa). Put the target on the horse and
  wait six hours at a bonfire; one player had the target turn up in the
  Hernand cells. Three others tried it and got a failed bounty and the target
  back at its spawn. A twelve-hour wait times the bounty out. That is a bug
  that happened once.
- Wyvern and companion horse (10 September 2026, thread 1wc5d2j, SaGhax,
  tested on 2.01). Load the target on the companion's horse, park your own
  horse at the jail beforehand, fly there, glide off the wyvern straight onto
  your horse without touching the ground, and the companion is teleported to
  you with the target still loaded. "Not 100% reliable, and positioning and
  timing matter a lot." That is companion catch-up carrying a loaded horse
  along, and no field move is involved.
- Kill, drop, pick up again, fast travel (19 September 2026, threads 1wkt3v3
  and 1wkwo6p, Dehavol). Kill the outlaw during the interrogation, pick the
  body up, fly up so the character drops it, pick it up again, then fast
  travel. "Tested it with 15+ bounties now, works every time." Half the
  reward, because the target is dead. One player reports it fails on a target
  that was already dead when found.

The third one is the one that matters, because it goes through the field move
this document is about and passes. The same body, carried twice, is refused
the first time and allowed the second. So neither gate tests whether the
player is carrying something. Each tests some state that the first pickup
sets and the second does not, or that the drop clears.

Reading `+0x2BBF2C0` from its entry says what the first gate's byte depends
on. `+0x2BC4200` is a wrapper. It adds `0x4F0` to the component and calls
`+0x2BBF2C0(sub, &result)`, and the gate tests `result+0x10`. That byte is zero
when any of four things holds:

    cmp  byte [rsi+0x58], 0      ; jne fail       a blocked flag on the sub-object
    cmp  qword [rsi+0x10], 0     ; je  fail       nothing to hold
    call [[[rsi]+8]->vt+0x1d8]   ; test al; je fail   the actor's own answer
    call +0x1434420([rsi+0x10])  ; test al        the held thing is not valid

and on success it increments `word [rsi+0x5a]`, a hold count. So
`eErrNoFieldMoveHolding` reads as "could not take the field-move hold", and
the "Holding" in the name is that hold. It has nothing to do with the carry.

Following the two calls takes each down to one byte. The actor's virtual at
`vt+0x1d8` on `ServerNormalInGameActor` is `movzx eax, byte [this+0xC2]; ret`.
That byte is written to 1 in `+0x2BC1A30` and `+0x2AFDDF0` right after a
successful `+0x2AF7D40` (a field enter), and to 0 in `+0x10BBB950` and
`+0x9D5C8A0` beside a loop over the actor's component array calling
`vt+0x110` on each, so it means "the actor is in a field". The validity call
`+0x1434420` is a weak-reference lock: it tests `byte [ref+0x4a]` and bumps a
count. So `[sub+0x10]` is a weak reference to the field the actor is attached
to, and the result the wrapper fills is a `FieldAttacherForActor` over
`ScopeAttacherBase` (RTTI on the three vtables it writes). The sub-object's
own family sits at `+0x2BBDF50..+0x2BC2C80`. Its state byte at `+0x58` takes
values 0 to 3: the hold needs 0, `+0x2BBF0C0` is the release (it decrements
the count at `+0x5a` and moves 1 to 2 when the count reaches zero), and
`+0x2BBFA00` writes 3 after computing a transform. Nothing in the family is
called from the catch code, and what writes 1 is not in the family.

So the four inputs are: state byte `[sub+0x58]`, field reference `[sub+0x10]`
with its alive byte at `+0x4a`, and the in-field byte `[actor+0xC2]`. Which of
them the carry trips is still a runtime question, but the probe can now name
the one that refused instead of reporting a bare refusal.

`holdwatch` hooks `+0x2BBF2C0` itself, found through the wrapper's one `call`
so a game update cannot move it. After each call it reads the state byte, the hold
count, the field reference and its alive byte, the actor through `[[sub]+8]`
and its in-field byte, the result byte, and the second gate's chain
`[[[actor+0x68]+0x1a0]+0x540]` from the same actor, with an RTTI name on every
pointer, and it names which input refused. The acquirer runs for every actor
with a transform component, so samples are kept per sub-object: one line on a
sub-object's first sight, one on each change in a deciding field, and every
call whose caller is inside `+0x2BCD820` (found by walking the wrapper's frame
to its return address), because that call is the teleport request and its
sample belongs next to the refusal in the log. `catch_gimmick` (`+0x211FA30`,
every picked-up object) is on for the same session, to see whether the second
pickup goes through the catch functions at all or through the generic carry,
and the two writers of state 2 and 3 are hooked so a successful teleport
shows what the sub-object goes through.

The session that settles it: kill the outlaw during the interrogation, pick
the body up, try to fast travel (refused), fly up, let it drop, pick it up
again, try again (allowed), close the game. The `[hold]` line between the two
attempts is the diff, and the mod is whatever writes it.

**Session seven, first run: the refusal is not the player's, and the game
does not show one.** With the body on his back the player was never told
"Cannot teleport in the current state". The map teleport went through and
the body stayed where it was. The log has two `eErrNoFieldMoveHolding`
refusals, at 13:46:36 and 13:47:23, and both are on components whose actor
is not the player's: the player's server actor in the catch lines is
`0x415A8D5A000`, the refused components belong to `0x415A8682300` and
`0x415C84F5F00`. The second one came 2 ms after `catch_able` was asked, from
`+0x105EEA30`, on two other `ServerCatchActorComponent`s whose actors sit
next to the refused one in memory. So the field move is per actor, the
handler runs for every actor that has to move (27,359 calls in this session,
not one per teleport), and when one of the actors that should come with the
player cannot take its hold, that actor is left behind and the player goes.
The client shows nothing because the player's own move succeeded.

That also reads the earlier sessions differently. With a live, tied target
the refusal was on the player's own component and the map said so. With a
dead one it is on another actor, presumably the body's, and the map says
nothing. Whatever Dehavol's drop-and-pick-up does, it puts the body in a
state whose hold succeeds, and then it moves with the player like any other
attached actor.

The caller at `+0x2BCCE30` is thin: it calls the handler, hands an error
straight back, and on success marks a bit in a 0x400000-bit table indexed
from the destination and calls `+0x21A16F0` on the component. It has fifteen
callers, and which of them asks for the body's move is what the stack unwind
at the next refusal is for.

Neither refusal was described in this run, because every budget was gone
inside the loading screen: 200 changes by 13:46:15, and the 60 handler lines
by 13:46:08, since the handler asks the acquirer on every call. The `this`
dump at the refusal stops at 0x400, short of the sub-object at `+0x4F0`, so
that did not show it either.

What the load did show is worth keeping. Every actor's first sample refuses
with `actor flag 0` and the next succeeds with the flag at 1 and `p50` filled
with a `ServerFieldSector`, which is the actor entering its field; the second
gate's `+0x540` is that same sector pointer, so the second gate is "the actor
has a sector" and goes null with the first gate's inputs. The body
(`ServerChildOnlyInGameActor`) goes through state 2 and state 3 on its way
in, with `attach_state3` called from `+0x10C7B5CB`. `attach_state2` is the
per-frame release, 509,848 calls, and is off the list.

The sampler now writes only what the load cannot produce: a handler call
that refuses, with a stack unwind and a 0x600 dump of the owning component,
and a sub-object that had the hold and lost it, or got it back, as two lines
with the sample before and after.

**Session seven, second run (14:00): the refused actor holds no field.** Both
refusals were described this time:

    [hold] the field-move handler was refused at call 301697: ok=0 (no field held,
      actor flag 0) blocked=0 holds=0 field=null alive=0 p50=null
      actor=<ServerNormalInGameActor>@0x37119340700 flag=0 ... from +0x2BCD883

One at 14:01:32, a second before the first `catch_able`, so around the kill,
and one at 14:02:02, the teleport, twenty seconds after the pickup
(`catch_match` at 14:01:41). The refused actor is a `ServerNormalInGameActor`
that is attached to no field at all: `[sub+0x10]` null and the in-field byte
0. The first gate needs nothing more than that to refuse; the second gate's
`+0x540` is null for the same reason. The player again saw no refusal.

The stack under the second refusal, read against the file, is a loop. The
.didata function `+0x10BBA080` walks an array of actors and, for each one,
calls `+0x2AFA090`, then `+0x2792F80` (the `actor_spawn` site: creation from
an `ICreateServerActorDesc`), then `+0x2AFE180`, which reaches `+0x105E8B10`
(a rider or vehicle path, it raises `eErrNoIsNotVehicle`) and, through the
31-byte wrapper `+0x2BCB290`, the field-move handler for that actor. So on a
teleport the game does try to bring attached actors along, by creating each
one again at the destination and moving it, and the fresh actor holds no
field when its move is asked for, so the move is refused and the loop goes
on without it. Whether the loop's array holds the carried body, and what the
handler is being asked for on an actor that has just been created, are the
next questions; all four functions in the loop are hooked now, and the
refusal line comes with a real unwind instead of a raw stack scan. Budgets
refill a few lines a second, because the 14:00 run spent the 200 loss lines
on world streaming by 14:01:12 and the pickup at 14:01:41 went unwritten.

**Session seven, third run (14:10): the outlaw is never asked, and the
destination asks a question instead.** This run had one handler refusal, at
14:11:21, and it was an unrelated NPC streaming in: it turns up sixteen
seconds later with its field and the hold. The outlaw, `ServerNormalInGameActor
0x5179034FD00`, appears at the pickup (`catch_able` 14:11:25, `catch_match`
14:11:31, `catch_able` 14:11:35) and then never again: no lost hold, no
refusal at the teleport, no mention at the destination. The pickup dump also
settles who is who: `catch_match(this, &err, actor)` runs on the player's
`ServerCatchActorComponent`, whose owner is the `ServerChildOnlyInGameActor`
(the player character is a child of the `ServerUserActor`), and the actor
argument is the outlaw.

The teleport's reload runs 14:11:51 to 14:11:53 (320 `fm_children` calls,
346 `actor_spawn`, 3,453 `enterfield1`). Two seconds later, at 14:11:55.018,
`+0x105EE940` builds a catch request from a block saved at `owner+0x460` and
asks `catch_able` about a component and an actor that exist nowhere else in
the log (`0x517A70BE460`, `0x517A7E8C300`), gets no error back, writes two
ids from that block into the two actors, and returns. No `catch_match`
follows and no body is there. The same call, from the same place, came 2 ms
before the refusal in the first run (13:47:23). That function has no direct
caller and no vtable slot in the file, which is the .didata section's habit,
so the site on it carries a stack unwind.

So the two earlier readings were both partly wrong. The refusals in the
first two runs belonged to other actors that happened to be re-created
around the teleport, and the body is not refused a move: it is simply not
in the set the reload re-creates, and the one thing the destination does
about the catch is `+0x105EE940`, which stops after its check. That is where
to look next: what it expects to find, and why the check's yes leads
nowhere.

Probe changes for the next run: `only=Name` on a site writes per-call lines
only when an argument's class name contains `Name`, so `fm_prepare` and
`actor_spawn` now log the `CreateChild*` re-creations alone instead of
spending their budgets on the load; `recatch` (`+0x105EE940`) is a site with
a stack unwind; and the refusal unwind consults sites' shadow stack for the
real return address, because a hooked function returns into a leave thunk
and the walk stopped there.

**Session seven, correction: the target was alive.** The runs above were
made with a tied, living outlaw, not a body, and the player teleported without
a refusal every time. Going back through every kept log settles the rest: all
seventeen refusals the probe has ever described, in sessions with `Unblock=0`
and with `Unblock=1`, are on components whose actor is a
`ServerNormalInGameActor`, and the player character is a
`ServerChildOnlyInGameActor`. The refusals were NPCs streaming in. Sessions
three to six read them as the player's because nothing had yet named the
player's class, and the wccftech claim that fast travel is locked while
carrying is not true on 2.03.00: it goes, and the target is left where it
was, which is what the March reddit thread reported as "mission failed and
the NPC teleported back to its spawn".

So the mod is not a patch on any gate. It has to make the carried actor come
along through a reload that re-creates only the player's children, and the
one hook the game already has for that is `+0x105EE940`, the destination
re-catch, which gets as far as a yes from `catch_able`. The probe is
uncapped now and hooks that function with dumps and an unwind, and filters
`actor_spawn` and `fm_prepare` to `CreateChild*` descriptors, so the next
run says what the reload re-creates and what the re-catch is asked about.

**Session eight (14:30, uncapped): what the reload does with a carried
actor.** With every cap off and thirty seconds at the destination, the
re-catch fired and named itself:

    recatch call 1 from +0x2AFE2A9 rcx=<CreateChildServerActorDesc_CatchTarget>
      r8=<ServerNormalInGameActor>@0x240C51F0300
    catch_able call 5 from +0x105EEA30 rcx=<ServerCatchActorComponent> (owner 0x240C51F0300)
      r8=<ServerNormalInGameActor>@0x24012509800   ... out 0

`+0x105EE940` is a method of `CreateChildServerActorDesc_CatchTarget`, called
from `fm_place`. The reload had just spawned an NPC (`0x240C51F0300`) from
its descriptor, and that descriptor carried a child descriptor for the prop
the NPC was holding (`0x24012509800`, a `StaticMeshServer` gimmick). The
method spawned the child, asked `catch_able` on the NPC's catch component,
and wrote the saved catch ids into both. The NPC arrived carrying its prop.
The player arrived carrying nothing because no descriptor said he was.

The function that would have said so is `+0x2793C20`, the site session one
hooked as `spawn_unused` because it never fired. It adds a
`CreateChildServerActorDesc_CatchTarget` to a parent's spawn descriptor,
wrapping the carried actor's own descriptor, after three checks: the parent
has no child descriptor of type 3 yet; and either the carried actor's
descriptor has `0xFFFF` at `+0xD0` or its actor-info row (looked up through
`+0x389570` from the descriptor's key at `+0x8`) has a flag at `+0x148`. Any
other carried actor gets `eErrNoInvalidCatcherSpawnData` and no child. Its
three callers (`+0x2798CF0`, `+0x288C0C0`, `+0x288CCA0`) each fill the
catch-preset block at `+0x460` on the descriptor first, from a preset row
(`eErrNoInvalidCatchPreset` when there is none), which is the block the
re-catch reads at the destination.

That is the mechanism behind the drop-and-pick-up glitch. A bounty target is
a scheduled NPC (`CreateServerActorDesc_NPCSchedule`, seen at its spawn),
with a schedule key at `+0xD0` and, presumably, no flag at `+0x148`; a prop
is a gimmick and passes; a dropped body picked up again is presumably a
gimmick by then. Whether the check is what refuses the outlaw, and which of
the three callers asks at the teleport, is the next run: `+0x2793C20` and
its callers are hooked with full dumps, so the descriptor, the `+0xD0` word
and the error are in the log.

If the check is the refusal, the mod candidate is the branch at `+0x2793C81`
(a short `jne`, `75 29`, to `+0x2793CAC`): taken means "build the child", so making
it unconditional makes every carried actor a re-creatable child. Whether a
scheduled NPC survives being spawned as a child from its own descriptor is
what the run after that will show, and the save backup is for it.

**Session nine (from the 14:39 log): the child-descriptor route is the wrong
one, and the order of events is the right one.** `+0x2793C20` ran once in the
whole session, from `+0x2798CF0`, for an NPC at the destination, and passed:
its descriptor had `0xFFFF` at `+0xD0`. `+0x2798CF0` runs for every actor the
reload places (2,814 times), looks the actor's type up in the actor-info
table, and only when that row has a "catchspawn" block at `+0x480` does it
build a descriptor for the prop the type is born holding, fill the catch
preset, and add the `CatchTarget` child. That is spawn data, not state: an
NPC type that carries a basket. The player is never placed by the reload
(`actor_spawn` produced his class twice, both at 14:41:52, the first load),
so no descriptor of his is ever asked about, and the branch at `+0x2793C81`
would change nothing. The `+0x460` block session eight read as "on the
catcher" is on the carried prop's descriptor.

What the log does say is when things happen. The outlaw, `0x5B1BF349400`,
went through the field-move handler at 14:42:34.220 (its sample from inside
`+0x2BCD820` says ok, holds the field) and at 14:42:34.224 the next sample
had no field, no sector, and nothing mentions the outlaw again. No hooked
site fired in that second: not `catch_update`, which is silent unless it
errs, not `catch_match`, nothing. The sequencer stage manager spawned the
loading sequence's gimmick actors at 14:42:37.768 and the sector reload ran
to 14:42:42. The player's actor, `0x5B1760E0200`, was asked about by the
handler three times, at 14:42:41.151, .284 and .662, all with the hold, and
his sub-object never lost its field in the whole session except at the first
load and at exit. So the teleport is: release and move the carried actor
away, then load, then move the player. The March thread's "the NPC
teleported back to its spawn" is the first step seen from outside.

The handler's own text says what a move does with a catch. For an actor of
kind 1 whose last move was more than three seconds ago, `+0x2BCD820` lists
the actors in its company (`+0x21D8920` on the component at `+0x108`) and,
for each one farther than a threshold from the destination, releases that
actor's catch if its catch component holds one (`+0x20AD3A0`, mode 2), tells
its owner (`+0x29652A0`) and moves it to the destination (`+0x2BCD0A0`). The
game already brings company along on a teleport, and it drops what the
company carries first. The outlaw is not company, and what handled him at
14:42:34 is what the next run has to name.

The probe for that run follows two actors and nothing else. `catch_match` at
the pickup marks the outlaw and the player's catch component, and through
the component its owner, the player (`mark=13` with `only=ServerCatch`).
Every site that runs thousands of times a session, the three handlers and
their callers, `catch_update`, the per-frame hold release `+0x2BBF0C0`, and
the handler's internals listed above, is quiet except about a marked actor
or a component of one (`onlymarked=1`), and then writes the arguments, the
dumps and a 24-frame unwind. The handler's `r8` is the request, with the
destination at `+0`, and the dump has it. The hold watcher writes every call
about a marked actor, or about the player's class, with its caller, and
unwinds when such an actor loses or regains its field. One teleport with the
outlaw on your back, thirty seconds at the destination, and the log has who
asked for the outlaw's move, from where, to what destination, and the same
for the player seven seconds later.

Two more nets, because nothing hooked fired in the second the outlaw was
released. Every other function beside the three catch methods in the file
(twenty-one, at +0x20AA000 to +0x20AF000) and every own entry of the
ServerCatchActorComponent vtable (fifteen) are hooked behind the same marked
filter, so whichever method of the player's component did the release is in
the log with its arguments and unwind. And `marks=0x180` on the field-move
sites dumps every marked object after each written call, which is the
player's catch component as it stands at the moment the outlaw is moved.
**Session nine's logs (15:33 and 15:47): the calls, named.** The pickup marked the
outlaw (`0x28E81541E00`) and the player's catch component at 15:34:23, and
the map confirm at 15:34:37.710 then reads, in order, all inside one server
message handler (`+0x29C5950` to `+0x2BC9180` to `+0x2BCA350` to
`+0x2BC9640`):

- 15:34:37.711: the field-move wrapper `+0x2BCCE30` on the player's transform
  component, from `+0x2BC9918`, with a request whose destination is
  (-10626.4, 621.2, -3813.3). The handler `+0x2BCD820` runs for the player.
- 15:34:37.714: the same wrapper on the outlaw's transform component, with
  the same request. The wrapper's tail, `+0x21A16F0`, calls `+0x2BCB960`,
  which asks the catcher's catch component for what it is catching
  (`+0x20ABA10`) and moves that actor with the same request. The game
  already brings the caught actor along on every field move.
- 15:34:37.723: back in the message handler, `+0x2BC9928` calls slot 0x200
  of the player's `ServerCharacterControlActorComponent`, `+0x23290D0`. That
  function reads the catch component at `+0x70` of the actor's table and, if
  `+0x38` or `+0x28` is set, calls `catch_update` with reason 9 and a force
  byte: the release. Inside it the hold code runs for both subs and the
  outlaw's field goes at 15:34:37.740.
- 15:34:37.739: a second server message (`+0x10DC8D90`) runs the
  departure sweep, below, and it reaches the outlaw's own catch component
  (`catch_update` 1463 and 1464 from inside his "leave field" virtual). His
  field goes at 15:34:37.740.
- 15:34:44.77: the reload's `fm_place` has `0x28E81541E00` in r9 again, but
  that is a new NPC in the outlaw's old memory: the component table at
  `+0x68` is `0x28DC8641C00` where his was `0x28E7E940400`, and the hold
  watcher's first sight of the address has flag 0. The outlaw did not
  travel. He was removed from the world at the confirm.

The release is real and `KeepCatch=1` skips it: the `je` at `+0x2329124`
that jumps over the release when there is no catch, made unconditional
(`74 22` to `EB 22`), after checking the bytes, that the skipped call is
`catch_update`, and that the vtable slot still holds the function.

**The 15:47 log, KeepCatch on.** The release was skipped and the outlaw
(`0x28C433A8C00`) arrived at the destination coordinates caught, moved by
the wrapper's tail at 15:49:18.414. Eight milliseconds later the sweep
removed him anyway (`catch_update` 1662 at .422 and 1669 at .435, both on
his own catch component, from inside his "leave field" virtual), his field
went at .435 and he was never placed again. The player's catch component
kept its target handle until something cleared it before 15:50:05.

**The departure sweep.** At every map confirm the server message handler
`+0x10DC8D90` calls `+0x287DB30` on the player's session object, about
seventy times per confirm. That function holds the field, and when byte
`+0x6a0` of the session is 1 calls `+0x287D440`, which builds one list from
three arrays of spawn records (the session's own at `+0x28`, a manager's at
`[+0x148]+0x30`, and `[+0x10]+0x20`), skipping any key in an exclusion
list at `+0xc8` and any record of type 3, and removes every entry: a key
whose top three bits are 1 goes to `+0x2808D00`, a thunk to `+0x107313E0`,
which finds the record, calls `+0x2817E00` on it, and takes it out of the
manager's array. `+0x2817E00` walks the record's actors (0x168-byte entries
from `+0x138`) and for each one asks

    +0x1F53D10([[actor+0x68]+0xb0], record key)

a thunk to `+0xE1478D0`: does anyone other than this record still hold the
actor? It walks a holder list on that component (`+0x18`, count `+0x1c`,
each entry a key at `+8` and a state at `[+0x10]+0xac`), then compares the
actor's own key at `+0x2e0` with the record's, then a flag at `+0x210`. On
a yes the actor is left in the world. On a no, `+0x20682E0` (a thunk to
`+0xE44B050`) marks the actor with the reason and calls its virtual `0x110`,
which is where the catch was cleaned up (`+0x28F2640` to `+0x17E9680` to
`+0xE44B97E` to `catch_update`, and `+0x28F2B2B` to `+0x2BBEA30` to
`catch_update`) and the field released. The outlaw's frames in both logs
run through `+0x287D855`, `+0x1073144E`, `+0x281819F` and `+0xE44B0E9`,
which is exactly that path with the check answering no.

**KeepCarried.** The mod hooks `+0xE1478D0` and answers yes for an actor
whose own catch component (`[[actor+0x68]+0x70]`) has a carrier handle at
`+0x28`; every other actor gets the original answer. It needs `KeepCatch`,
because the release clears that handle before the sweep asks. The hook goes
in only if the check's first bytes, the thunk's jump and the sweep's call
all read as they do on 2.03.00. With both on, the confirm should go: player
moved, outlaw moved with him by the wrapper's tail, release skipped, sweep
asks and is told he is held, outlaw stays in the world at the destination
with the catch intact. What the trial has to show is the client side: the
client reloads its actors at the destination and has to get the outlaw and
the attachment back from the server. The probe's sweep sites (`sweep`,
`sweep_lists`, `sweep_record`, `leave_field`) and the keepcarried lines say
which of those steps happened.

**Two symptoms during session ten came from the Flight Freedom binary.**
The first was a slowdown, below. The second was a bounty target missing
from his normal location in every save, one from 5 September included,
with the quest still active in the journal and a marker on the map.

The evidence that settles the second one is a pair of runs, read out of
the plugins' own logs, since Stamina Master writes one on every launch
whatever else is loaded. At 17:54 the game ran with Stamina Master and
Flight Freedom and the target was missing. At 17:59 it ran with Stamina
Master alone and the target was there. This plugin was out of the folder
for both and its patches had been zero for longer than that, so the only
change between them was Flight Freedom.

Not the shipped mod, though. That session's own probe was running a
research lever from 17:17 that forced every buff-tag condition in the game
to answer no, on every actor rather than on a mount, which is the sort of
thing that stops a scheduled NPC appearing. Its settings file was last
written at 17:32 and Seth's first report came after 17:17.

One claim of mine did not survive contact with the evidence. I reported
that the target stayed missing with all seven plugins removed, and treated
that as established. A run with nothing loaded leaves no log at all, the
window where everything was parked was about two and a half minutes, and
neither the save nor the spot was recorded. Park every `.asi` and add them
back in groups before suspecting code, and write down the time of each
step while doing it.

**A slowdown during session ten was another mod.** Four runs of 0.8.x
(16:26 to 16:36) lost most of their frame rate a minute after the world
loaded, and Flight Freedom turned out to be the cause. Two builds were
spent chasing it inside this plugin and both are reverted: 0.8.1 moved the
`KeepCarried` detour off the check and onto the `.code` thunk that reaches
it, and 0.8.2 turned `KeepCarried` and the sweep sites off to bisect.
0.8.3 is 0.8.0's arrangement again, with the hook on the check itself at
`+0xE1478D0` and all four sweep sites on.

Worth keeping from the measurements, because they bound what this plugin
costs. Every object dump in a two-minute run adds up to 462 ms of wall
clock. The mod thread's summary line lands every 2,008 ms through the
worst of the stalls, so the log's mutex never held anything up. A 0.7.0 run
wrote 1.2 million lines and stayed smooth where a 0.8.1 run wrote 675,000
and did not. The hold acquirer's call count, which the plugin already
reports every two seconds, is the frame-rate proxy to use next time: it
runs per actor per frame and does not depend on how much is being written.

The 0.8.x runs also named the object the sweep runs on: a
`ServerSequencerStageManager`, which spawns a quest stage's actors, and
that is what a bounty outlaw is. It also runs every five seconds outside a
teleport.

**Session ten's trial (the 16:50 log) worked.** One teleport, carrying a
live outlaw, with `KeepCatch=1` and `KeepCarried=1`:

- 16:51:46.511 the pickup marks the outlaw (`0x337F829E500`), the player
  (`0x337B60E0200`) and the player's catch component (`0x337B61E26F0`).
- 16:52:07.778 the confirm moves the player to the destination through the
  field-move wrapper, as it always did.
- 16:52:07.782 four milliseconds later the wrapper's tail asks the player's
  catch component what he is carrying and moves the outlaw with the same
  request. The catch release that used to follow is skipped.
- 16:52:07.794 the departure sweep reaches the outlaw and asks whether
  anyone other than his spawn record still holds him. The plugin answers
  yes, because his own catch component names a carrier, and he stays in the
  world. The question came from `+0x2818165`, the sweep's own call site,
  and his record key and his actor key were the same value, so the game's
  answer would have been no. One actor was kept in the whole session.
- 16:52:22 to 16:52:51 the player walks around the destination and the move
  path carries the outlaw with him 1,463 times, asking both catch
  components on every step. This is the catch surviving the teleport, not
  an actor standing where he landed.
- 16:52:51.324 a `catch_update` on the player's catch component from
  `+0x20AE60E` ends the carry, the ordinary release rather than anything
  the teardown did.
- 16:53:14.6 the outlaw leaves the field through the normal path, twenty
  seconds after the release and a minute after the teleport.

**The client's half was a second copy of the release.** On screen the
outlaw was on the ground at the destination, not on the player's back,
while the server was carrying him. The reason is not that the client lost
its actors: the outlaw's client actor `0x4F8AD513300` lived through the
whole run, and afterwards the client kept offering him as something to
interact with, twelve times a second, the way it treats a body on the
ground.

Slot 0x200 of the character-control component has two implementations. The
server and common classes share `+0x23290D0`, the one `KeepCatch` patched.
`ClientCharacterControlActorComponent` has its own, a thunk at `+0x860F90`
to `+0x99B6CB0`, and that function is the same code instruction for
instruction: the catch component at `[[actor+0x68]+0x70]`, a test of `+0x38`
then `+0x28`, and `catch_update` with reason 9 behind a `je` at
`+0x99B6D0F` whose bytes are the same `74 22`. So the teleport released the
catch on the client while the server kept it, and the two sides disagreed
for the next forty-four seconds: the server moved him with the player,
nothing drew him as carried.

The 18:05 trial with that patch in put him on the ground again, and the
log named a third copy. One `catch_update` reached the client's catch
component at 18:06:26.265, a second after the confirm, from `+0x156F26F`.
That is inside `+0x156EF40`, a client state transition that is in no vtable
and is reached from two call sites, and its last thirty bytes are the same
release again: the same test of `+0x38` and `+0x28`, the same reason 9, the
same short jump over the call, differing only in the jump's displacement.
It fired exactly once in the whole run.

0.9.2 patches all three, each behind the same checks, and the trial after
it put him on the ground again. That is where guessing from the call log
stopped paying, so 0.9.3 added a byte watcher on the marked catch
components, polled ten times a second from the mod thread.

The 18:16 trial was the first one where the drop could be watched instead
of inferred. The pickup at 18:17:51.032 set `+0x38` to the same handle on both the player's
server and client catch components, along with `+0x50`, `+0x54` and
`+0x58`. The confirm ran at 18:18:00.288 and the sweep was told to keep the
outlaw eleven milliseconds later. Then at 18:18:01.304 a `catch_update`
reached the client component and at .322 the server one, both from
`+0x20AE60E`, and by .338 every one of those fields was zero on both sides.

That call is not on the teleport path at all. `+0x20AE540` runs on the
catch component itself. It reads the carrier handle at `+0x28` and the held
handle at `+0x38`, and unless the state object behind
`[[[actor+0x68]+0x40]+0x88]+0x10` still has the flags that say the carry
animation is live, it calls `catch_update` with reason 1. A teleport resets
those flags, so a second after arrival it decides the catch is stale and
drops it.

0.9.4 aimed at the wrong branch. The entry is a pair:

    +0x20AE5C8  test edi,edi        ; the held handle
    +0x20AE5CA  jne  +0x20AE5D0     ; something is held, go and check it
    +0x20AE5CC  test ebx,ebx        ; the carrier handle
    +0x20AE5CE  je   +0x20AE60E     ; nothing held, nothing to do

Making the second jump unconditional only helps when nothing is being
carried, because with a live catch the first jump has already gone past it.
The 18:32 trial wrote the patch, logged it, and lost both handles a second
after arrival from the same `+0x20AE60E` as before. 0.9.5 writes `EB 44`
over the first test instead, which reaches `+0x20AE60E` from the top of the
pair and covers both ways in.

**That one held.** In the 18:41 run the pickup set `+0x38` on both catch
components at 18:42:49.592, the confirm ran at about 18:43:06.9, the sweep
was told to keep the outlaw at .982, and the handles were still set when
the game closed at 18:43:45. Thirty-nine seconds at the destination with
both sides agreeing, against a second and a half in every run before it.
`catch_update` was never called from `+0x20AE60E` again.

Two things came with it. The frame rate fell away and NPCs ran from the
player. The second may be the game reacting correctly to a man walking into
town with a tied outlaw on his back, and it may be Flight Freedom, which
was running its AI probe in the same session and replaced the answer to
`AICondition_CheckBuffTag` 4,122 times in two minutes. That override is the
same one that emptied a bounty spawn earlier the same day. Its probe is off
for the next run, which separates the two. The catch
component itself needs nothing: `catch_match` at `+0x20ABAE0` is slot 0x150
of both the client and server catch vtables, it writes `+0x28` and `+0x38`
on both components, and it already ran once at the pickup for each side.
Nothing has to be replayed at the destination if neither side ever lets
go.

**The 16:57 run repeats it.** Same two settings, same shape: the confirm
at 16:59:32.170, the outlaw kept from the sweep fourteen milliseconds later
at 16:59:32.184, and 787 carries at the destination from 16:59:32.174 to
17:00:07.912. Two trials, same result, so it is the mechanism and not a
fluke.

**The 16:50 log was destroyed, and the logger did it.** No other process
touched it; the Flight Freedom session was asked and has never written
anything matching `BountyProbe*`. What the directory showed afterwards was
the tell: no `.01` at all, and `.02` holding the 16:36 run, which a plain
shift cannot produce. The game was restarted twice inside three minutes.
The exiting process still had the 1.9 GB log open, so `MoveFileEx` of the
live log to `.01` lost to a sharing violation, and nothing checked the
result: the next line opened the same path with `fopen(L"w")` and emptied
it. The 0.9.0 logger fixes both halves.

- A rename that fails is retried for a second, and if it still fails the
  new session appends to the old file and says so in an error line. Nothing
  is ever emptied because a rename did not work.
- A session that marks a bounty target calls `Log::Keep("pickup")`, which
  takes its log out of the numbered rotation for good: at shutdown
  `BountyProbe.log` becomes `BountyProbe.trial-MMDD-HHMM-pickup.log`, a
  name rotation never renames and never deletes. The intent is written to
  `BountyProbe.keep` the moment the pickup happens, so a session that
  crashes before shutdown still has its log saved by the next launch.

Against the two earlier trials: with neither change the outlaw was released
on arrival and then removed; with `KeepCatch` alone he arrived caught and
was removed eight milliseconds later; with both he arrived caught and
stayed. The thing that was missing all along was not the move and not the
release, it was the sweep's question about who holds him.

The error's runtime value is 2615297641 (`0x9BE24669`). All 1,353 error
globals read zero at plugin load and fill in before the first frame: the ASI
loader gets the plugin in ahead of the game's own static initialisers, so
anything reading those globals has to wait and retry.

There are three readers, not the four a first scan reported. `+0x2BCD889` and
`+0x2BCD88A` are one byte apart and a mov-from-rip is six bytes at its
shortest, so they cannot both be instructions. The earlier one is the jne's
displacement byte `0x4E` read as a REX prefix.

**`+0x2BCD820` is not a request handler.** It ran 36,675 times in two and a
half minutes, and `+0x2BC4200`, the call its branch follows, ran 380,069
times. Whatever it is, it runs every frame and can refuse as one of its
outcomes. `+0x10C71160` ran 1,206 times and `+0x10C78190` twice, which is much
more the shape of a request. That reverses the guess above: the small ones in
`.didata` are the better candidates for the handler behind a map teleport.

No refusal has been caught yet, and the reason was the logging rather than the
game. A per-call budget of 60 lines was spent 50 seconds in, during the
loading screen, and the bounty target was picked up at 10:24:52. Every site
counts non-zero out values regardless of budget now, and the busy ones stay
silent until one of them returns an error.

The catch hooks did work, and RTTI corrected three guesses of six:
`+0x20ABAE0`, `+0x20AC2D0` and `+0x20AD3A0` all run on a `Server` or
`ClientCatchActorComponent`, but `+0x20AD3A0` ran 4,209 times and is not the
release it was taken for. `+0x2792F80` takes an `ICreateServerActorDesc` and
is generic actor creation. `+0x21DE0D0` runs on a `ProjectileActorComponent`
and has nothing to do with catching.

## The other route

Nexus already carries position-warp mods for this game: Teleporter Tool (713)
drops a marker on the map and moves you to it on a hotkey, and the Inventory
Editor trainer (3209) does the same. Neither goes through `MoveField`, so
neither triggers the field unload, and neither is subject to
`eErrNoFieldMoveHolding`.

That suggests a mod that writes the player's transform and the caught actor's
transform in the same tick, leaving fast travel untouched. It avoids every
question above, and it is precisely what the Nexus mod-ideas thread asked for on
7 April 2026: a hotkey that moves the player and whatever they are carrying to
the town bounty office. Nobody has built it.

The cost is that it needs the catchee's actor pointer. Master Looter already
reads entities, positions and parents in `mod\src\loot\game.cpp`, and
`CheckSpawnReason(CatchSpawn)` plus owner identity is enough to pick the right
actor out of the set. Whether the game re-syncs a teleported actor or snaps it
back is the equivalent unknown on this route, and it is a cheaper one to test
because a bad result is a visual glitch rather than a lost quest target.

## Suggested order of work

1. Run session seven as described above, with `Unblock=0`. It costs one dead
   outlaw and two fast travel attempts.
2. Read the diff. If it is the blocked flag or a null `[sub+0x10]`, the mod is
   a write to the sub-object before the request, or a hook on whatever sets
   it at the first pickup. If it is the actor's virtual answer, hook that
   virtual on the player's actor and return what the second pickup returns.
   The second gate's chain on the same line says whether the pointer at
   `+0x540` follows or needs its own fix.
3. Test with `Unblock=0`. The mod should make the game's own check pass
   instead of skipping it. Back the save up before any session that carries a quest target
   through a field move; `C:\working\cd mods\save-backups` has the 20
   September copy.
4. If the diff is in something the drop creates rather than something the
   first pickup sets, drop this route and build the position warp instead.

Find the patch sites again after a game update the way Flight Freedom does,
from the error name rather than the address: `research\wide.py` walks
`eErrNoFieldMoveHolding` to its global and to every reader across both
executable sections, and it does not depend on any address staying put. The
probe in `mod\` does the same walk at runtime and logs what it found next to
the numbers above, so the first line of any session says whether this document
is still current.
