import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
tgt = int(sys.argv[1], 16)
hits = []
for m in re.finditer(rb'[\xe8\xe9]', imgb):
    i = m.start()
    if i + 5 > len(imgb): continue
    d = struct.unpack_from('<i', imgb, i+1)[0]
    if i + 5 + d == tgt and sec_of(i) == ".code":
        hits.append((i, imgb[i]))
print(f"callers of +0x{tgt:X}: {len(hits)}")
for h, op in hits[:40]:
    print(f"   {'call' if op==0xe8 else 'jmp '} at +0x{h:X}")
# also find function start of target and nearby marker strings within the function
p = tgt
while p < tgt + 0x6000:
    if imgb[p] == 0xCC and imgb[p+1] == 0xCC and imgb[p+2] == 0xCC:
        break
    p += 1
print(f"function +0x{tgt:X} .. +0x{p:X}  (size {p-tgt})")
# strings referenced inside
leap = re.compile(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
seen = set()
for m in leap.finditer(imgb[tgt:p]):
    i = tgt + m.start()
    d = struct.unpack_from('<i', imgb, i+3)[0]
    t = i + 7 + d
    e = imgb.find(b"\x00", t, t+120)
    if e > t:
        try:
            s = imgb[t:e].decode('ascii')
            if s.isprintable() and len(s) > 4 and s not in seen:
                seen.add(s); print(f"   str +0x{i:X} -> \"{s}\"")
        except: pass
