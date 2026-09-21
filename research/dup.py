import sys, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image
base, img, pe = load_image()
imgb = bytes(img)
pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
starts=[]; ends={}
for off in range(d.VirtualAddress, d.VirtualAddress+d.Size, 12):
    s,e,u = struct.unpack_from('<III', imgb, off)
    if s: starts.append(s); ends[s]=e
starts.sort()
def fn(rva):
    i=bisect.bisect_right(starts,rva)-1
    if i<0: return None
    s=starts[i]
    return (s, ends[s]) if rva < ends[s] else None
GATE=(0x2BCD820, 0x2BCECEC)
for r in (0x2BCD88A, 0x10C71204, 0x10C7826F):
    f=fn(r)
    print(f"reader +0x{r:X}: func +0x{f[0]:X}..+0x{f[1]:X} size {f[1]-f[0]}, reader at +{r-f[0]:#x} into it")
    print(f"   first16 {imgb[f[0]:f[0]+16].hex(' ')}")
print()
g0 = imgb[GATE[0]:GATE[0]+64]
for r in (0x10C71204, 0x10C7826F):
    f=fn(r)
    g1 = imgb[f[0]:f[0]+64]
    same = sum(1 for a,b in zip(g0,g1) if a==b)
    print(f"func at +0x{f[0]:X} vs the gate: {same}/64 first bytes identical")
print()
# is .didata reachable? any call from .code into .didata, and vice versa
import re
def crosscalls(lo,hi,tlo,thi,limit=5):
    out=[]
    for m in re.finditer(rb'\xe8', imgb[lo:hi]):
        i=lo+m.start()
        if i+5>hi: continue
        t=i+5+struct.unpack_from('<i',imgb,i+1)[0]
        if tlo<=t<thi:
            out.append((i,t))
            if len(out)>=limit: break
    return out
CODE=(0x1000,0x51EB000); DID=(0x75C9000,0x75C9000+0x105682EE)
print("calls from .code into .didata:", [(hex(a),hex(b)) for a,b in crosscalls(*CODE,*DID)])
print("calls from .didata into .code:", [(hex(a),hex(b)) for a,b in crosscalls(*DID,*CODE)])
