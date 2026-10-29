"""Check every address Bounty Teleportation writes to, straight off the exe on
disk, for each game build the plugin knows.

The probe has SitesTest for its hooking core; the lean plugin has no logic of
its own worth a harness, only a table of addresses, and this is what checks
that table. `py -3 verify_carry.py`, exit 0 when the installed game matches
one of the builds. `py -3 verify_carry.py <path to CrimsonDesert.exe>` checks
another copy, such as one kept under patch-baseline.

When a game patch moves everything, as 1.0.0.2949 did on 21 September 2026
and 1.0.0.2976 did on 23 September, `derive_2949.py` finds the new addresses
and `derive_2976b.py` names the class behind each vtable and picks out the
sweep's call. The DLC build 1.0.0.3392 of 29 October moved the character
control release from vtable slot 0x200 to 0x1F8 and changed the teleport
handler's prologue; patch-dlc\workounty-teleportation92 has the scripts
that found its addresses.
"""
import sys, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image

BASE, img, pe = load_image(*sys.argv[1:2])
b = bytes(img)

TELEPORT_GUARD = "83 79 38 00 74 04 B3 01 EB 07 83 79 28 00 0F 95"
WATCHDOG_GUARD = "85 FF 75 04 85 DB 74 3E"
HOLDER_HEAD    = "48 89 5C 24 08 44 8B 41 1C"
TELEPORT_HEAD  = "48 8B C4 48 89 58 10 48 89 70 18 48 89 78 20"
TELEPORT_HEAD_3392 = "48 89 5C 24 10 4C 89 44 24 18 48 89 4C 24 08"
TICK_HEAD      = "48 89 5C 24 08 48 89 6C 24 18 48 89 74 24 20 57 41 56 41 57 48 83 EC 40 48 8B F1"

# Each build: catch_update, then the four releases as
# (label, patch rva, orig, guard, guard shape, call, vtable, slot target, thunk to),
# then the holder check, its thunk and the sweep's call, then the teleport
# handler and its two callers, then the catch component's tick, which holds
# the watchdog release and is where 1.0.8 makes a skipped release again, then
# the vtable slot the release is in and the handler's first 15 bytes.
BUILDS = {
    "1.0.0.3392": dict(
        catch_update=0x22656B0,
        releases=[
            ("keepcatch",          0x250FDD4, "74 22", 0x250FDB4, TELEPORT_GUARD, 0x250FDF3, 0x5EDD4B8, 0x250FD80, None),
            ("keepcatch_client",   0x967143F, "74 22", 0x967141F, TELEPORT_GUARD, 0x967145E, 0x5934850, 0x9441D0, 0x96713E0),
            ("keepcatch_state",    0x178393D, "74 20", 0x178391B, TELEPORT_GUARD, 0x178395A, None, None, None),
            ("keepcatch_watchdog", 0x22668D8, "85 FF", 0x22668D8, WATCHDOG_GUARD, 0x2266919, None, None, None),
        ],
        holder=0xC91E0F0, thunk=0x2136620, sweep=0x2A5274C,
        teleport=0x2E60CA0, calls=(0x2E61A4A, 0x2E6201C),
        tick=0x2266850, slot=0x1F8, teleport_head=TELEPORT_HEAD_3392,
    ),
    "1.0.0.2976": dict(
        catch_update=0x20AD400,
        releases=[
            ("keepcatch",          0x2329184, "74 22", 0x2329164, TELEPORT_GUARD, 0x23291A3, 0x5B25468, 0x2329130, None),
            ("keepcatch_client",   0x9857044, "74 22", 0x9857024, TELEPORT_GUARD, 0x9857063, 0x55B5460, 0x860FF0, 0x9856FF0),
            ("keepcatch_state",    0x156F1CD, "74 20", 0x156F1AB, TELEPORT_GUARD, 0x156F1EA, None, None, None),
            ("keepcatch_watchdog", 0x20AE628, "85 FF", 0x20AE628, WATCHDOG_GUARD, 0x20AE669, None, None, None),
        ],
        holder=0xDD9D1E0, thunk=0x1F53D50, sweep=0x28181E0,
        teleport=0x2BC96C0, calls=(0x2BCA5DD, 0x2BCAB80),
        tick=0x20AE5A0, slot=0x200, teleport_head=TELEPORT_HEAD,
    ),
    "1.0.0.2949": dict(
        catch_update=0x20AD3B0,
        releases=[
            ("keepcatch",          0x2329134, "74 22", 0x2329114, TELEPORT_GUARD, 0x2329153, 0x5B25260, 0x23290E0, None),
            ("keepcatch_client",   0x983EDC4, "74 22", 0x983EDA4, TELEPORT_GUARD, 0x983EDE3, 0x55B53C8, 0x860F90, 0x983ED70),
            ("keepcatch_state",    0x156F25D, "74 20", 0x156F23B, TELEPORT_GUARD, 0x156F27A, None, None, None),
            ("keepcatch_watchdog", 0x20AE5D8, "85 FF", 0x20AE5D8, WATCHDOG_GUARD, 0x20AE619, None, None, None),
        ],
        holder=0xDD526C0, thunk=0x1F53D20, sweep=0x2818170,
        teleport=0x2BC9650, calls=(0x2BCA56D, 0x2BCAB10),
        tick=0x20AE550, slot=0x200, teleport_head=TELEPORT_HEAD,
    ),
    "1.0.0.2944": dict(
        catch_update=0x20AD3A0,
        releases=[
            ("keepcatch",          0x2329124, "74 22", 0x2329104, TELEPORT_GUARD, 0x2329143, 0x5B25260, 0x23290D0, None),
            ("keepcatch_client",   0x99B6D0F, "74 22", 0x99B6CEF, TELEPORT_GUARD, 0x99B6D2E, 0x55B53C8, 0x860F90, 0x99B6CB0),
            ("keepcatch_state",    0x156F24D, "74 20", 0x156F22B, TELEPORT_GUARD, 0x156F26A, None, None, None),
            ("keepcatch_watchdog", 0x20AE5C8, "85 FF", 0x20AE5C8, WATCHDOG_GUARD, 0x20AE609, None, None, None),
        ],
        holder=0xE1478D0, thunk=0x1F53D10, sweep=0x2818160,
        teleport=0x2BC9640, calls=(0x2BCA55D, 0x2BCAB00),
        tick=0x20AE540, slot=0x200, teleport_head=TELEPORT_HEAD,
    ),
}


def hexs(rva, n):
    return " ".join(f"{x:02X}" for x in b[rva:rva + n])


def rel32(rva, op):
    if rva + 5 > len(b) or b[rva] != op:
        return None
    return rva + 5 + struct.unpack_from("<i", b, rva + 1)[0]


def qword(rva):
    return struct.unpack_from("<Q", b, rva)[0]


def check_build(name, spec, loud):
    bad = []

    def want(label, got, expect):
        if got != expect:
            bad.append(f"{label}: {got}, expected {expect}")

    for (label, at, orig, guard, shape, call, vt, slot, thunk) in spec["releases"]:
        want(f"{label} patch bytes", hexs(at, len(orig.split())), orig)
        want(f"{label} guard", hexs(guard, len(shape.split())), shape)
        t = rel32(call, 0xE8)
        want(f"{label} call target", f"+0x{t:X}" if t else "not a call",
             f"+0x{spec['catch_update']:X}")
        if vt is not None:
            want(f"{label} vtable slot 0x{spec['slot']:X}", f"0x{qword(vt + spec['slot']):X}", f"0x{BASE + slot:X}")
        if thunk is not None:
            t = rel32(slot, 0xE9)
            want(f"{label} thunk", f"+0x{t:X}" if t else "not a jmp", f"+0x{thunk:X}")

    want("holder check prologue", hexs(spec["holder"], 9), HOLDER_HEAD)
    t = rel32(spec["thunk"], 0xE9)
    want("thunk jumps to the check", f"+0x{t:X}" if t else "not a jmp", f"+0x{spec['holder']:X}")
    t = rel32(spec["sweep"], 0xE8)
    want("sweep calls the thunk", f"+0x{t:X}" if t else "not a call", f"+0x{spec['thunk']:X}")

    want("teleport prologue", hexs(spec["teleport"], 15), spec["teleport_head"])
    for c in spec["calls"]:
        t = rel32(c, 0xE8)
        want(f"caller +0x{c:X}", f"+0x{t:X}" if t else "not a call", f"+0x{spec['teleport']:X}")

    want("catch tick prologue", hexs(spec["tick"], 27), TICK_HEAD)
    # The watchdog's guard sits 0x88 into the tick on every build.
    want("watchdog inside the tick", f"+0x{spec['releases'][3][1] - 0x88:X}", f"+0x{spec['tick']:X}")

    if loud:
        print(f"\n{name}: {'every address matches' if not bad else str(len(bad)) + ' mismatched'}")
        for line in bad:
            print(f"  BAD  {line}")
    return not bad


print(f"image base 0x{BASE:X}, SizeOfImage {pe.OPTIONAL_HEADER.SizeOfImage}")
matched = [n for n, s in BUILDS.items() if check_build(n, s, False)]
for name, spec in BUILDS.items():
    check_build(name, spec, True)

print()
if len(matched) == 1:
    print(f"ALL MATCH for {matched[0]}, which is " + (sys.argv[1] if len(sys.argv) > 1 else "the installed game"))
    sys.exit(0)
if not matched:
    print("NO BUILD MATCHES the installed game. Run derive_2949.py to find the new addresses.")
    sys.exit(1)
print("MORE THAN ONE BUILD MATCHES, which should be impossible: " + ", ".join(matched))
sys.exit(1)
