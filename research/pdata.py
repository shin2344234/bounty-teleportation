import sys, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image
base, img, pe = load_image()
imgb = bytes(img)
pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]   # IMAGE_DIRECTORY_ENTRY_EXCEPTION
print(f"pdata rva=0x{d.VirtualAddress:X} size=0x{d.Size:X}  entries={d.Size//12}")
starts=[]; ends={}
for off in range(d.VirtualAddress, d.VirtualAddress + d.Size, 12):
    s, e, u = struct.unpack_from('<III', imgb, off)
    if not s: continue
    starts.append(s); ends[s]=e
starts.sort()
def fn(rva):
    i = bisect.bisect_right(starts, rva) - 1
    if i < 0: return None
    s = starts[i]
    return (s, ends[s]) if rva < ends[s] else None
print()
for nm, r in [("gate reader",0x2BCD88A),("gate func",0x2BCD820),("holdcheck",0x2BC4200),
              ("caller A ref",0x2BCCE73),("caller B ref",0x2BCD69F),
              ("transformsync err",0x2BCD761),("charctrl err",0x2BCD7D7),
              ("catch_match",0x20ABAE0),("catch_able",0x20AC2D0),("catch_release",0x20AD3A0),
              ("catch_spawn",0x2792F80),("catch_spawn2",0x2793C20),("catch_target",0x21276F0),
              ("sublevel err",0x21F8EA3),("movetype err",0x27B5546),("uistr bind",0x23E103B)]:
    f = fn(r)
    if f: print(f"  {nm:<20} +0x{r:07X} -> func +0x{f[0]:07X} .. +0x{f[1]:07X}  size {f[1]-f[0]:<6} first14={imgb[f[0]:f[0]+14].hex(' ')}")
    else: print(f"  {nm:<20} +0x{r:07X} -> no pdata entry")
