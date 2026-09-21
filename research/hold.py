import sys, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image
import capstone
base, img, pe = load_image()
imgb = bytes(img)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
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
    return (s, ends[s]) if r<ends[s] else None
def strat(rva):
    e = imgb.find(b"\x00", rva, rva+120)
    if e < 0: return None
    try:
        t = imgb[rva:e].decode("ascii")
        return t if t.isprintable() and len(t) > 3 else None
    except: return None
def dis(lo, hi, label):
    print(f"\n===== {label} +0x{lo:X}..+0x{hi:X} ({hi-lo} bytes)")
    for i in md.disasm(imgb[lo:hi], base+lo):
        r = i.address-base; note=""
        if "rip + " in i.op_str or "rip - " in i.op_str:
            try:
                frag=i.op_str.split("rip ")[1]; sign=1 if frag[0]=='+' else -1
                val=int(frag[2:].split("]")[0],16)*sign; t=i.address+i.size+val-base
                sv=strat(t); note=f"   ; [+0x{t:X}]"+(f' "{sv}"' if sv else "")
            except Exception: pass
        if i.mnemonic=="call" and i.op_str.startswith("0x"):
            t=int(i.op_str,16)-base; f=fn(t); note+=f"   ; -> +0x{t:X}" + (f" (fn +0x{f[0]:X}, {f[1]-f[0]}b)" if f else "")
        print(f"+0x{r:X}  {i.mnemonic:<9} {i.op_str}{note}")
for a in (0x2BC4200, 0x2BBF2C0):
    f = fn(a)
    if f: dis(f[0], min(f[1], f[0]+0x600), f"function")
    else: print("no pdata for", hex(a))
