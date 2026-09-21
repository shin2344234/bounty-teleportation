import sys, re, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
starts=[]; ends={}
for off in range(d.VirtualAddress, d.VirtualAddress+d.Size, 12):
    s,e,u = struct.unpack_from('<III', imgb, off)
    if s: starts.append(s); ends[s]=e
starts.sort()
def bounds(r):
    i=bisect.bisect_right(starts,r)-1
    return (starts[i], ends[starts[i]]) if i>=0 and r<ends[starts[i]] else None

# name -> global, for annotating
names={}
for m in re.finditer(rb'eErr[A-Za-z0-9_]{3,70}\x00', imgb):
    i=m.start()
    if i and imgb[i-1]!=0: continue
    names[i]=m.group()[:-1].decode()
leas={}
for m in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', imgb):
    i=m.start(); dd=struct.unpack_from('<i',imgb,i+3)[0]
    leas.setdefault(i+7+dd,[]).append(i)
g2n={}
for sr,nm in names.items():
    for r in leas.get(sr,[]):
        zl=r-0x1C
        if 0x40<=imgb[zl]<=0x4F and imgb[zl+1]==0x8D and (imgb[zl+2]&0xC7)==0x05:
            g2n.setdefault(zl+7+struct.unpack_from('<i',imgb,zl+3)[0], set()).add(nm)

def errs_in(lo,hi):
    out={}
    for pat,opl,do in ((rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                       (rb'[\x44\x45\x4c\x4d]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',7,3)):
        for m in re.finditer(pat, imgb[lo:hi]):
            i=lo+m.start(); dd=struct.unpack_from('<i',imgb,i+do)[0]
            g=i+opl+dd
            if g in g2n:
                for n in g2n[g]: out[n]=out.get(n,0)+1
    return out

def callers(t):
    n=0
    for m in re.finditer(rb'[\xe8\xe9]', imgb):
        i=m.start()
        if i+5>len(imgb): continue
        dd=struct.unpack_from('<i',imgb,i+1)[0]
        if i+5+dd==t: n+=1
    return n

for f in (0x2827CD0, 0x2AF8010, 0x2AF8660, 0x10BB9790):
    lo,hi = bounds(f)
    print(f"+0x{f:X} ({sec_of(f)}) size {hi-lo}, {callers(f)} callers, first10 {imgb[f:f+10].hex(' ')}")
    for n,c in sorted(errs_in(lo,hi).items()):
        print(f"    {c}x  {n}")
    print()
