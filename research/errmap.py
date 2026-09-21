import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
# 1. all eErr* name strings and their RVAs
name_at = {}
for m in re.finditer(rb'eErr[A-Za-z0-9_]{3,70}\x00', imgb):
    i = m.start()
    if i and imgb[i-1] != 0: continue
    name_at[i] = m.group()[:-1].decode()
print("eErr names:", len(name_at))
# 2. lea index
leas = {}
for m in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', imgb):
    i = m.start(); d = struct.unpack_from('<i', imgb, i+3)[0]
    leas.setdefault(i+7+d, []).append(i)
# 3. global for each name via Z = name_lea - 0x1C
g2n = {}
for sr, nm in name_at.items():
    for r in leas.get(sr, []):
        zl = r - 0x1C
        if imgb[zl+1] == 0x8d and 0x40 <= imgb[zl] <= 0x4f:
            d = struct.unpack_from('<i', imgb, zl+3)[0]
            g = zl + 7 + d
            if sec_of(g) in (".sbss", ".debug$P"):
                g2n.setdefault(g, set()).add(nm)
print("globals mapped:", len(g2n))
# 4. reads inside the function
LO, HI = 0x2BC6000, 0x2BD2000
hits = []
for pat, opl, do in ((rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                     (rb'[\x44\x45\x4c\x4d]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',7,3)):
    for m in re.finditer(pat, imgb[LO:HI]):
        i = LO + m.start(); d = struct.unpack_from('<i', imgb, i+do)[0]
        g = i + opl + d
        if g in g2n: hits.append((i, g, sorted(g2n[g])))
print(f"\nerror codes returned by function +0x{LO:X}:")
for i, g, nms in sorted(set((a,b,tuple(c)) for a,b,c in hits)):
    print(f"   +0x{i:X}  global +0x{g:X}  {', '.join(nms)}")
