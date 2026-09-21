import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
# executable sections by characteristics
execs = [(s.Name.rstrip(b'\0').decode(), s.VirtualAddress, s.VirtualAddress+s.Misc_VirtualSize)
         for s in pe.sections if s.Characteristics & 0x20000000]
print("executable sections:", [(n, hex(a), hex(b-a)) for n,a,b in execs])

STR = 0x5932780      # eErrNoFieldMoveHolding
GLOB = 0x6CF6B5C
def scan(lo, hi, kind):
    hits=[]
    if kind=="lea":
        for m in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', imgb[lo:hi]):
            i=lo+m.start(); d=struct.unpack_from('<i',imgb,i+3)[0]
            if i+7+d==STR: hits.append(i)
    else:
        for pat,opl,do in ((rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                           (rb'[\x44\x45\x4c\x4d]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',7,3)):
            for m in re.finditer(pat, imgb[lo:hi]):
                i=lo+m.start(); d=struct.unpack_from('<i',imgb,i+do)[0]
                if i+opl+d==GLOB: hits.append(i)
    return hits
for n, a, b in execs:
    print(f"  {n}: lea->name {len(scan(a,b,'lea'))}, reads global {len(scan(a,b,'r'))}")
# also: does the string appear anywhere else (exec sections included)?
occ=[]
off=0
while True:
    i=imgb.find(b"eErrNoFieldMoveHolding\x00", off)
    if i<0: break
    occ.append((i, sec_of(i), imgb[i-1]))
    off=i+1
print("name string occurrences:", [(hex(a),s,prev) for a,s,prev in occ])
