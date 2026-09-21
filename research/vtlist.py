"""Every slot of a class's vtable(s): rva, size, and whether the slot is
the same function as in a second class (inherited). py -3 vtlist.py Derived [Base]"""
import sys, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image(); imgb = bytes(img); sec = sections(pe)
pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
ends = {}
for off in range(d.VirtualAddress, d.VirtualAddress+d.Size, 12):
    s, e, u = struct.unpack_from('<III', imgb, off)
    if s: ends[s] = e
def code(r):
    for n, (a, b) in sec.items():
        if a <= r < b and n in (".code", ".didata", ".text1"): return True
    return False
def vtables(name):
    pat = (".?AV" + name + "@pa@@").encode() + b"\x00"
    out = []
    i = imgb.find(pat)
    while i >= 0:
        td = i - 0x10
        tgt = struct.pack("<I", td); j = imgb.find(tgt)
        while j >= 0:
            col = j - 12
            if col >= 0 and struct.unpack_from("<I", imgb, col)[0] == 1:
                off = struct.unpack_from("<I", imgb, col+4)[0]
                k = imgb.find(struct.pack("<Q", base+col))
                while k >= 0:
                    out.append((k+8, off)); k = imgb.find(struct.pack("<Q", base+col), k+1)
            j = imgb.find(tgt, j+1)
        i = imgb.find(pat, i+1)
    return sorted(set(out))
def slots(vt):
    out = []
    p = vt
    while True:
        fn, = struct.unpack_from("<Q", imgb, p); fn -= base
        if not (0 < fn < len(imgb)) or not code(fn): break
        out.append(fn); p += 8
        if len(out) > 400: break
    return out
der = vtables(sys.argv[1]); bas = vtables(sys.argv[2]) if len(sys.argv) > 2 else []
bslots = set()
for vt, off in bas: bslots.update(slots(vt))
for vt, off in der:
    ss = slots(vt)
    print(f"vt +0x{vt:X} (this offset {off}): {len(ss)} slots")
    for i, fn in enumerate(ss):
        print(f"  slot 0x{i*8:03X} +0x{fn:X} {ends.get(fn,0)-fn:5d} b {'inherited' if fn in bslots else 'own'}")
