"""Find Bounty Teleportation's six addresses again after a game patch.

Every address the mod uses is anchored to a byte pattern that is distinctive
on 2.03.00, so the same patterns are the way to find where they went. Run it
against whatever CrimsonDesert.exe is installed:

    py -3 find_2949.py
"""
import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image

BASE, img, pe = load_image()
b = bytes(img)
print("SizeOfImage %d" % pe.OPTIONAL_HEADER.SizeOfImage)

def find(pattern, label, expect=None):
    hits = [m.start() for m in re.finditer(re.escape(pattern), b)]
    print(f"\n{label}: {len(hits)} hit(s)" + (f", {expect} expected" if expect else ""))
    for h in hits:
        print(f"    +0x{h:X}")
    return hits

# The three teleport-path releases share this test of the catch component.
TELEPORT_GUARD = bytes([0x83, 0x79, 0x38, 0x00, 0x74, 0x04, 0xB3, 0x01,
                        0xEB, 0x07, 0x83, 0x79, 0x28, 0x00, 0x0F, 0x95])
find(TELEPORT_GUARD, "the teleport-path release guard", 3)

# The watchdog reads both handles into registers first.
WATCHDOG_GUARD = bytes([0x85, 0xFF, 0x75, 0x04, 0x85, 0xDB, 0x74, 0x3E])
find(WATCHDOG_GUARD, "the watchdog's guard", 1)

# The departure sweep's holder check, by its prologue.
HOLDER = bytes([0x48, 0x89, 0x5C, 0x24, 0x08, 0x44, 0x8B, 0x41, 0x1C])
find(HOLDER, "the holder check prologue", 1)

# Inside the teleport handler: the field-move wrapper call, then the release
# through slot 0x200 of the character control component.
RELEASE_CALL = bytes([0xFF, 0x90, 0x00, 0x02, 0x00, 0x00])   # call [rax+0x200]
SEQ = bytes([0x48, 0x8B, 0x41, 0x40,          # mov rax,[rcx+0x40]   (varies)
             ])
hits = [m.start() for m in re.finditer(re.escape(RELEASE_CALL), b)]
print(f"\ncall [rax+0x200]: {len(hits)} hit(s) (too common to identify alone)")

# The teleport handler is the one whose release call is preceded by
# mov rax,[r13+0x68] / mov rcx,[rax+0x40] / mov rax,[rcx] / call [rax+0x200].
TAIL = bytes([0x49, 0x8B, 0x45, 0x68,         # mov rax,[r13+0x68]
              0x48, 0x8B, 0x48, 0x40,         # mov rcx,[rax+0x40]
              0x48, 0x8B, 0x01,               # mov rax,[rcx]
              0xFF, 0x90, 0x00, 0x02, 0x00, 0x00])
t = find(TAIL, "the teleport handler's release call", 1)
for h in t:
    print(f"    the call itself is at +0x{h + 11:X}")
