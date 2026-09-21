import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
def fstart(rva, limit=0x8000):
    p = rva
    while p > rva - limit:
        if imgb[p-1]==0xCC and imgb[p-2]==0xCC and imgb[p-3]==0xCC: return p
        p -= 1
    return None
def fend(rva, limit=0x8000):
    p = rva
    while p < rva + limit:
        if imgb[p]==0xCC and imgb[p+1]==0xCC and imgb[p+2]==0xCC: return p
        p += 1
    return None

print("=== function starts for the two callers of the gate ===")
for r in (0x2BCCE73, 0x2BCD69F):
    s = fstart(r); e = fend(r)
    print(f"  ref +0x{r:X} -> function +0x{s:X} .. +0x{e:X} (size {e-s})")

# movzx r32, word [reg+disp32] = 0F B7 /r ; check the NonTeleportable id offsets
print("\n=== movzx reads of the worldmap refusal id fields ===")
offs = {0xBC:"MainPlayer",0xBE:"PlayableTrigger",0xC2:"State"}
for m in re.finditer(rb'\x0f\xb7[\x80-\x8f]', imgb):
    i=m.start(); d=struct.unpack_from('<i',imgb,i+3)[0]
    if d in offs and sec_of(i)==".code":
        print(f"  +0x{i:X} movzx ...,[reg+0x{d:X}] {offs[d]}  func +0x{fstart(i):X}")
for m in re.finditer(rb'[\x44\x45\x4c\x4d]\x0f\xb7[\x80-\x8f]', imgb):
    i=m.start(); d=struct.unpack_from('<i',imgb,i+4)[0]
    if d in offs and sec_of(i)==".code":
        print(f"  +0x{i:X} movzx(rex) ...,[reg+0x{d:X}] {offs[d]}  func +0x{fstart(i):X}")
