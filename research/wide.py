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
def fn(r):
    i=bisect.bisect_right(starts,r)-1
    if i<0: return None
    s=starts[i]
    return s if r < ends[s] else None

names={}
for m in re.finditer(rb'eErr[A-Za-z0-9_]{3,70}\x00', imgb):
    i=m.start()
    if i and imgb[i-1]!=0: continue
    names[i]=m.group()[:-1].decode()
leas={}
for m in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', imgb):
    i=m.start(); dd=struct.unpack_from('<i',imgb,i+3)[0]
    leas.setdefault(i+7+dd,[]).append(i)
n2g={}
for sr,nm in names.items():
    for r in leas.get(sr,[]):
        zl=r-0x1C
        if imgb[zl+1]==0x8d and 0x40<=imgb[zl]<=0x4f:
            dd=struct.unpack_from('<i',imgb,zl+3)[0]
            n2g.setdefault(nm,set()).add(zl+7+dd)
def readers(g):
    out=[]
    for pat,opl,do in ((rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                       (rb'[\x44\x45\x4c\x4d]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',7,3)):
        for m in re.finditer(pat, imgb):
            i=m.start(); dd=struct.unpack_from('<i',imgb,i+do)[0]
            if i+opl+dd==g: out.append(i)
    return sorted(set(out))

for nm in ["eErrNoFieldMoveHolding","eErrNoCantMoveSubLevel","eErrCantMoveSomeWhereType",
           "eErrNoCantDoWhileCatchingOrCatched","eErrNoForceReleaseCatch","eErrNoNotCatchableActor",
           "eErrNoInvalidCatcherSpawnData","eErrNoInvalidMatchingCatcherCatchee",
           "eErrNoNotExistCatchTargetActor"]:
    gs=n2g.get(nm)
    if not gs: print(f"{nm}: no global"); continue
    g=sorted(gs)[0]
    rs=readers(g)
    fns=[]
    for r in rs:
        f=fn(r)
        fns.append((r, f, sec_of(r)))
    print(f"\n{nm}  global +0x{g:X} ({sec_of(g)})  readers={len(rs)}")
    for r,f,s in fns:
        print(f"    +0x{r:X} in {s}, function +0x{f:X}" if f else f"    +0x{r:X} in {s}, no pdata entry")
