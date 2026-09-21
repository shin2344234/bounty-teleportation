import sys, re, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
import capstone
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
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
    return s if r<ends[s] else None

NAME = "eErrNoCantEnterToField"
b = NAME.encode()
strs=[]; off=0
while True:
    i=imgb.find(b+b"\x00",off)
    if i<0: break
    if i and imgb[i-1]==0: strs.append(i)
    off=i+1
print(f"{NAME}: string at {[hex(x) for x in strs]} ({sec_of(strs[0])})")
leas=[]
for m in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', imgb):
    p=m.start()
    if p+7+struct.unpack_from('<i',imgb,p+3)[0]==strs[0]: leas.append(p)
glob=None
for p in leas:
    zl=p-0x1C
    if 0x40<=imgb[zl]<=0x4F and imgb[zl+1]==0x8D and (imgb[zl+2]&0xC7)==0x05:
        glob = zl+7+struct.unpack_from('<i',imgb,zl+3)[0]
print(f"  global +0x{glob:X} ({sec_of(glob)})")
readers=[]
prev=None
for pat,opl,do in ((rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                   (rb'[\x44\x45\x4c\x4d]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',7,3)):
    for m in re.finditer(pat, imgb):
        i=m.start(); dd=struct.unpack_from('<i',imgb,i+do)[0]
        if i+opl+dd==glob: readers.append(i)
readers=sorted(set(readers))
# collapse adjacent (REX false positives)
clean=[]
for r in readers:
    if clean and r == clean[-1]+1: clean[-1]=r
    else: clean.append(r)
print(f"  readers: {len(clean)}")
for r in clean:
    f=fn(r)
    inside = " <-- INSIDE THE GATE HANDLER" if f==0x2BCD820 else ""
    print(f"    +0x{r:X} ({sec_of(r)}) in function +0x{f:X}{inside}")
    if f==0x2BCD820:
        print(f"      16 bytes before: {imgb[r-16:r].hex(' ')}")
        for ins in md.disasm(imgb[r-32:r+16], base+r-32):
            mark = "   <<<< error load" if ins.address-base==r else ""
            print(f"        +0x{ins.address-base:X}  {ins.mnemonic:<8} {ins.op_str}{mark}")
