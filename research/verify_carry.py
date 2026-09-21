"""Check every address Bounty Teleportation writes to, straight off the exe on disk.

The probe has SitesTest for its hooking core; the lean plugin has no logic of
its own worth a harness, only a table of addresses, and this is what checks
that table. `py -3 verify_carry.py`, exit 0 when all of it matches.
"""
import sys, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image

BASE, img, pe = load_image()
b = bytes(img)

ok = True
def check(label, got, want):
    global ok
    same = got == want
    if not same:
        ok = False
    print(f"  {'ok ' if same else 'BAD'}  {label}: {got}" + ("" if same else f", expected {want}"))

def rd(rva, n):
    return b[rva:rva + n]

def hexs(bs):
    return " ".join(f"{x:02X}" for x in bs)

def rel32(rva, op):
    """Target of a 5-byte E8/E9 at rva."""
    if b[rva] != op:
        return None
    return rva + 5 + struct.unpack_from("<i", b, rva + 1)[0]

def short(rva):
    """Target of a 2-byte EB/74/75 at rva."""
    return rva + 2 + struct.unpack_from("<b", b, rva + 1)[0]

CATCH_UPDATE = 0x20AD3A0

TELEPORT_GUARD = bytes([0x83, 0x79, 0x38, 0x00, 0x74, 0x04, 0xB3, 0x01,
                        0xEB, 0x07, 0x83, 0x79, 0x28, 0x00, 0x0F, 0x95])
WATCHDOG_GUARD = bytes([0x85, 0xFF, 0x75, 0x04, 0x85, 0xDB, 0x74, 0x3E])

# label, patch rva, orig, repl, call, guard, shape, vtable, slot target, thunk to
RELEASES = [
    ("keepcatch",          0x2329124, "74 22", "EB 22", 0x2329143, 0x2329104, TELEPORT_GUARD,
     0x5B25260, 0x23290D0, None),
    ("keepcatch_client",   0x99B6D0F, "74 22", "EB 22", 0x99B6D2E, 0x99B6CEF, TELEPORT_GUARD,
     0x55B53C8, 0x860F90, 0x99B6CB0),
    ("keepcatch_state",    0x156F24D, "74 20", "EB 20", 0x156F26A, 0x156F22B, TELEPORT_GUARD,
     None, None, None),
    ("keepcatch_watchdog", 0x20AE5C8, "85 FF", "EB 44", 0x20AE609, 0x20AE5C8, WATCHDOG_GUARD,
     None, None, None),
]

print(f"image base 0x{BASE:X}, {len(b)} bytes")
print("the four catch releases")
for (label, at, orig, repl, call, guard, shape, vt, slot, thunk) in RELEASES:
    print(f" {label}")
    check("patch bytes", hexs(rd(at, 2)), orig)
    check("call target", f"+0x{rel32(call, 0xE8):X}", f"+0x{CATCH_UPDATE:X}")
    check("guard shape", hexs(rd(guard, len(shape))), hexs(shape))
    # The replacement must land where the branch it stands in for lands.
    want_to = short(at) if orig.startswith("74") else 0x20AE60E
    got_to = at + 2 + struct.unpack_from("<b", bytes([0, int(repl.split()[1], 16)]), 1)[0]
    check("jump lands at", f"+0x{got_to:X}", f"+0x{want_to:X}")
    if vt is not None:
        got = struct.unpack_from("<Q", b, vt + 0x200)[0]
        check("vtable slot 0x200", f"0x{got:X}", f"0x{BASE + slot:X}")
    if thunk is not None:
        check("thunk jumps to", f"+0x{rel32(slot, 0xE9):X}", f"+0x{thunk:X}")

print("the departure sweep's holder check")
CHECK, THUNK, SWEEP = 0xE1478D0, 0x1F53D10, 0x2818160
check("check prologue", hexs(rd(CHECK, 9)), "48 89 5C 24 08 44 8B 41 1C")
check("thunk jumps to", f"+0x{rel32(THUNK, 0xE9):X}", f"+0x{CHECK:X}")
check("sweep calls", f"+0x{rel32(SWEEP, 0xE8):X}", f"+0x{THUNK:X}")

print("ALL MATCH" if ok else "MISMATCHES ABOVE")
sys.exit(0 if ok else 1)
