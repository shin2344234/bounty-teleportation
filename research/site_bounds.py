import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img)
import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
def fstart(r, lim=0x8000):
    p=r
    while p>r-lim:
        if imgb[p-1]==0xCC and imgb[p-2]==0xCC and imgb[p-3]==0xCC: return p
        p-=1
    return None
def fend(r, lim=0x9000):
    p=r
    while p<r+lim:
        if imgb[p]==0xCC and imgb[p+1]==0xCC and imgb[p+2]==0xCC: return p
        p+=1
    return None
print("=== extra readers -> function starts ===")
for lbl, r in [("eErrNoCantMoveSubLevel", 0x21F8EA3), ("eErrCantMoveSomeWhereType", 0x27B5546)]:
    s=fstart(r); print(f"  {lbl}: reader +0x{r:X} -> func +0x{s:X} .. +0x{fend(s):X}")
print("\n=== chosen sites: bounds and first bytes (hookability) ===")
sites = [("fieldmove",0x2BCD820),("holdcheck",0x2BC4200),("fm_request",0x2BCCE30),("fm_move",0x2BCD393),
         ("catch_match",0x20ABAE0),("catch_able",0x20AC2D0),("catch_release",0x20AD3A0),
         ("catch_spawn",0x2792F80),("catch_spawn2",0x2793C20),("catch_target",0x21276F0),
         ("catch_gimmick",0x211FA30),("sublevel_move",0x21F8EA3),("move_type",0x27B5546)]
for nm, a in sites:
    st = fstart(a) if a not in (x[1] for x in sites[:11]) else a
    st = fstart(a+1) if imgb[a-1]!=0xCC and False else a
    e = fend(a)
    n=0; bad=""
    for ins in md.disasm(imgb[a:a+32], base+a):
        if "rip" in ins.op_str and not bad: bad = f"rip-rel at +{n}"
        n += ins.size
        if n >= 14: break
    print(f"  {nm:<14} +0x{a:07X} size {e-a:<6} first14={imgb[a:a+14].hex(' ')} {bad}")
