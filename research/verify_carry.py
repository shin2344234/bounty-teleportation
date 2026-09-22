"""Check every address Bounty Teleportation writes to, straight off the exe on
disk, for each game build the plugin knows.

The probe has SitesTest for its hooking core; the lean plugin has no logic of
its own worth a harness, only a table of addresses, and this is what checks
that table. `py -3 verify_carry.py`, exit 0 when the installed game matches
one of the builds.

When a game patch moves everything, as 1.0.0.2949 did on 21 September 2026,
`derive_2949.py` and `derive_2949b.py` are what find the new addresses.
"""
import sys, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image

BASE, img, pe = load_image()
b = bytes(img)

TELEPORT_GUARD = "83 79 38 00 74 04 B3 01 EB 07 83 79 28 00 0F 95"
WATCHDOG_GUARD = "85 FF 75 04 85 DB 74 3E"
HOLDER_HEAD    = "48 89 5C 24 08 44 8B 41 1C"
TELEPORT_HEAD  = "48 8B C4 48 89 58 10 48 89 70 18 48 89 78 20"

# Each build: catch_update, then the four releases as
# (label, patch rva, orig, guard, guard shape, call, vtable, slot target, thunk to),
# then the holder check, its thunk and the sweep's call, then the teleport
# handler and its two callers.
BUILDS = {
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
            want(f"{label} vtable slot 0x200", f"0x{qword(vt + 0x200):X}", f"0x{BASE + slot:X}")
        if thunk is not None:
            t = rel32(slot, 0xE9)
            want(f"{label} thunk", f"+0x{t:X}" if t else "not a jmp", f"+0x{thunk:X}")

    want("holder check prologue", hexs(spec["holder"], 9), HOLDER_HEAD)
    t = rel32(spec["thunk"], 0xE9)
    want("thunk jumps to the check", f"+0x{t:X}" if t else "not a jmp", f"+0x{spec['holder']:X}")
    t = rel32(spec["sweep"], 0xE8)
    want("sweep calls the thunk", f"+0x{t:X}" if t else "not a call", f"+0x{spec['thunk']:X}")

    want("teleport prologue", hexs(spec["teleport"], 15), TELEPORT_HEAD)
    for c in spec["calls"]:
        t = rel32(c, 0xE8)
        want(f"caller +0x{c:X}", f"+0x{t:X}" if t else "not a call", f"+0x{spec['teleport']:X}")

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
    print(f"ALL MATCH for {matched[0]}, which is the installed game")
    sys.exit(0)
if not matched:
    print("NO BUILD MATCHES the installed game. Run derive_2949.py to find the new addresses.")
    sys.exit(1)
print("MORE THAN ONE BUILD MATCHES, which should be impossible: " + ", ".join(matched))
sys.exit(1)
