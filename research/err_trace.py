import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img)
sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"

NAMES = ["eErrNoFieldMoveHolding", "eErrCantMoveSomeWhereType", "eErrNoCantMoveSubLevel",
         "eErrNoForceReleaseCatch", "eErrNoLogoutBySummonForceReleaseCatch"]

# pre-index all rip-relative lea
lea_pat = re.compile(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
leas = {}   # target_rva -> [instr_rva]
for m in lea_pat.finditer(imgb):
    i = m.start()
    disp = struct.unpack_from('<i', img, i+3)[0]
    leas.setdefault(i + 7 + disp, []).append(i)
print("indexed lea targets:", len(leas))

for nm in NAMES:
    b = nm.encode()
    locs = []
    off = 0
    while True:
        i = imgb.find(b + b"\x00", off)
        if i < 0: break
        # must be start of string (preceded by NUL)
        if i == 0 or img[i-1] == 0: locs.append(i)
        off = i + 1
    print(f"\n=== {nm}  string rva(s): {[hex(x) for x in locs]}")
    for sr in locs:
        refs = leas.get(sr, [])
        print(f"   name-lea xrefs: {[hex(x) for x in refs]}")
        for r in refs:
            zl = r - 0x1C
            # expect lea rcx,[rip+disp] at zl
            if img[zl+1] == 0x8d:
                d = struct.unpack_from('<i', img, zl+3)[0]
                g = zl + 7 + d
                print(f"     Z-lea at +0x{zl:X} -> global +0x{g:X} ({sec_of(g)})")
                # find readers of that global: mov r32,[rip+disp] (8B) and cmp etc
                readers = []
                for op_len, pat in ((6, re.compile(rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')),):
                    for m in pat.finditer(imgb):
                        i = m.start()
                        dd = struct.unpack_from('<i', img, i+2)[0]
                        if i + 6 + dd == g and sec_of(i) == ".code":
                            readers.append(i)
                print(f"     readers (mov r32,[rip+x]): {len(readers)} -> {[hex(x) for x in readers[:20]]}")
