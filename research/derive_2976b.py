"""Second half of the 2976 derivation, after derive_2949.py has found the
release functions, the holder check and the teleport handler on the
23 September 2026 patch.

On 2949 the vtables and the client thunk had not moved, and that was the
evidence each release was the same function in its new place. On 2976 they
all moved, so this reads the RTTI name behind each vtable instead, and picks
the departure sweep's call out of the holder thunk's eleven callers by its
offset inside its function, which is 0x360 on every build so far.

    py -3 derive_2976b.py
"""
import sys, re, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image

BASE, img, pe = load_image()
b = bytes(img)

pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
ends, starts = {}, []
for off in range(d.VirtualAddress, d.VirtualAddress + d.Size, 12):
    s, e, _ = struct.unpack_from('<III', b, off)
    if s:
        ends[s] = e
        starts.append(s)
starts.sort()

def func_of(rva):
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0 and starts[i] <= rva < ends[starts[i]]:
        return starts[i]
    return None

def rel32(rva, op):
    return rva + 5 + struct.unpack_from('<i', b, rva + 1)[0] if b[rva] == op else None

def refs_to(rva):
    """Every aligned qword in the image holding base+rva."""
    want = struct.pack('<Q', BASE + rva)
    return [m.start() for m in re.finditer(re.escape(want), b) if m.start() % 8 == 0]

def callers(target, op=0xE8):
    out = []
    for m in re.finditer(bytes([op]), b):
        r = m.start()
        if rel32(r, op) == target:
            out.append(r)
    return out

def rtti(vtable):
    """The mangled class name from the complete object locator at vtable-8."""
    col = struct.unpack_from('<Q', b, vtable - 8)[0] - BASE
    td = struct.unpack_from('<I', b, col + 12)[0]
    name = b[td + 16:td + 256]
    return name[:name.index(0)].decode()

SERVER  = 0x2329130     # was +0x23290E0 on 2949, slot 0x200 of Server/Common CharacterControl
CLIENT  = 0x9856FF0     # was +0x983ED70, reached through a thunk
STATE   = 0x156EEC0     # was +0x156EF50, in no vtable
THUNK   = 0x1F53D50     # was +0x1F53D20, the jmp to the holder check

print("the server and common character control release")
for r in refs_to(SERVER):
    print(f"  vtable +0x{r - 0x200:X} slot 0x200   {rtti(r - 0x200)}")

print("\nthe client release")
for t in callers(CLIENT, 0xE9):
    print(f"  thunk +0x{t:X}   (was +0x860F90)")
    for r in refs_to(t):
        print(f"    vtable +0x{r - 0x200:X} slot 0x200   {rtti(r - 0x200)}")

print("\nthe client state transition")
print("  callers: " + ", ".join(f"+0x{c:X}" for c in callers(STATE)) + "   (was +0x9F19F7, +0x1F58C26)")

print("\nthe departure sweep's call to the holder thunk")
for c in callers(THUNK):
    f = func_of(c)
    mark = "   <- the sweep" if f and c - f == 0x360 else ""
    print(f"  +0x{c:X} in +0x{f:X} at +0x{c - f:X}{mark}")
