"""Second half of the 2949 derivation: the vtable slots and the client thunk
that the plugin checks before it writes anything, and the callers that say
which release is which.

    py -3 derive_2949b.py
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

SERVER  = 0x23290E0     # was +0x23290D0, slot 0x200 of Server/Common CharacterControl
CLIENT  = 0x983ED70     # was +0x99B6CB0, reached through a thunk
STATE   = 0x156EF50     # was +0x156EF40, in no vtable

print("the server and common character control release")
for r in refs_to(SERVER):
    print(f"  referenced at +0x{r:X}" + (f"   vtable +0x{r - 0x200:X} slot 0x200" if r >= 0x200 else ""))

print("\nthe client release")
th = callers(CLIENT, 0xE9)
print("  thunks to it: " + ", ".join(f"+0x{t:X}" for t in th) + "   (was +0x860F90)")
for t in th:
    for r in refs_to(t):
        print(f"    thunk +0x{t:X} referenced at +0x{r:X}"
              + (f"   vtable +0x{r - 0x200:X} slot 0x200" if r >= 0x200 else ""))
for r in refs_to(CLIENT):
    print(f"  the function itself referenced at +0x{r:X}")

print("\nthe client state transition")
print("  callers: " + ", ".join(f"+0x{c:X}" for c in callers(STATE)) + "   (was +0x9F19F7, +0x1F58C26)")
print("  refs:    " + ", ".join(f"+0x{r:X}" for r in refs_to(STATE)))

print("\nthe two releases the mod does not patch, for the record")
for f in (0x156F5E0, 0x20C05C0):
    print(f"  +0x{f:X}  callers " + ", ".join(f"+0x{c:X}" for c in callers(f))
          + "  refs " + ", ".join(f"+0x{r:X}" for r in refs_to(f)))
