import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
print("patch site bytes:")
for a,n in [(0x2BCD884, 0x14)]:
    print(f"  +0x{a:X}: {imgb[a:a+n].hex(' ')}")
# 66 8B /r disp32 reads of +0xBC,+0xBE,+0xC2 (the three NonTeleportable ids)
offs = {0xBC:"MainPlayer",0xBE:"PlayableTrigger",0xC2:"State"}
found = {}
pat = re.compile(rb'\x66[\x44\x45]?\x8b[\x80-\x8f\x90-\x9f]', re.S)
for m in re.finditer(rb'\x66\x8b[\x80-\x8f]', imgb):
    i = m.start()
    d = struct.unpack_from('<i', imgb, i+3)[0]
    if d in offs and sec_of(i) == ".code":
        found.setdefault(d, []).append(i)
for d, lst in sorted(found.items()):
    print(f"  word [reg+0x{d:X}] ({offs[d]}): {len(lst)} sites -> {[hex(x) for x in lst[:12]]}")
# cluster: sites where all three appear within 0x800
allsites = sorted((i,d) for d,l in found.items() for i in l)
print("\nclusters containing all three:")
for k in range(len(allsites)):
    win = [x for x in allsites if allsites[k][0] <= x[0] < allsites[k][0]+0x800]
    if len({d for _,d in win}) == 3:
        print("   ", [(hex(i), offs[d]) for i,d in win])
        break
