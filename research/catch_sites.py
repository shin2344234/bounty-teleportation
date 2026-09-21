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
leas = {}
for m in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', imgb):
    i=m.start(); d=struct.unpack_from('<i',imgb,i+3)[0]
    leas.setdefault(i+7+d, []).append(i)
name_at={}
for m in re.finditer(rb'eErr[A-Za-z0-9_]{3,70}\x00', imgb):
    i=m.start()
    if i and imgb[i-1]!=0: continue
    name_at[i]=m.group()[:-1].decode()
n2g={}
for sr,nm in name_at.items():
    for r in leas.get(sr,[]):
        zl=r-0x1C
        if imgb[zl+1]==0x8d and 0x40<=imgb[zl]<=0x4f:
            d=struct.unpack_from('<i',imgb,zl+3)[0]
            g=zl+7+d
            if sec_of(g) in (".sbss",".debug$P"): n2g.setdefault(nm,set()).add(g)
def readers(g):
    out=[]
    for pat,opl,do in ((rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                       (rb'[\x44\x45\x4c\x4d]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',7,3)):
        for m in re.finditer(pat, imgb):
            i=m.start(); d=struct.unpack_from('<i',imgb,i+do)[0]
            if i+opl+d==g and sec_of(i)==".code": out.append(i)
    return sorted(set(out))
for nm in ["eErrNoCantDoWhileCatchingOrCatched","eErrNoForceReleaseCatch","eErrNoNotCatchableActor",
           "eErrNoNotExistCatchTargetActor","eErrNoInvalidMatchingCatcherCatchee",
           "eErrNoSpawnParentCatcherLogout","eErrNoAIEventWhileCatchingOrCatched",
           "eErrNoDockingOrCatchedGimmickNotInteractable","eErrNoInvalidCatcherSpawnData"]:
    gs = n2g.get(nm)
    if not gs: print(f"{nm}: no global derived"); continue
    for g in sorted(gs):
        rs = readers(g)
        fs = sorted({fstart(r) for r in rs if fstart(r)})
        print(f"{nm}  global +0x{g:X}  readers={len(rs)}  funcs={[hex(x) for x in fs[:10]]}")
