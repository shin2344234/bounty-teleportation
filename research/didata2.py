import sys, re, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
starts=[]; ends={}
for off in range(d.VirtualAddress, d.VirtualAddress+d.Size, 12):
    s,e,u = struct.unpack_from('<III', imgb, off)
    if s: starts.append(s); ends[s]=e
starts.sort()
def covered(rva):
    i = bisect.bisect_right(starts, rva)-1
    return i >= 0 and rva < ends[starts[i]]
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
GLOB=0x6CF6B5C
hits=[]
for pat,opl,do in ((rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                   (rb'[\x44\x45\x4c\x4d]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',7,3)):
    for m in re.finditer(pat, imgb):
        i=m.start(); dd=struct.unpack_from('<i',imgb,i+do)[0]
        if i+opl+dd==GLOB: hits.append(i)
print("all readers of the gate global, anywhere in the image:")
for h in sorted(set(hits)):
    print(f"  +0x{h:X}  section={sec_of(h)}  pdata-covered={covered(h)}")
print()
print("pdata coverage of the two executable sections:")
for nm, lo, hi in [(".code", 0x1000, 0x1000+0x51EA000), (".didata", 0x75C9000, 0x75C9000+0x105682EE)]:
    n = sum(1 for s in starts if lo <= s < hi)
    print(f"  {nm}: {n} function entries")
