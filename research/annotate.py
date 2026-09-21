"""For each function: section, size, and the strings and eErr names it
references through rip-relative leas. `py -3 annotate.py 0xRVA ...`"""
import sys, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
import capstone
base, img, pe = load_image(); imgb = bytes(img); sec = sections(pe)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
ends={}
for off in range(d.VirtualAddress, d.VirtualAddress+d.Size, 12):
    s,e,u = struct.unpack_from('<III', imgb, off)
    if s: ends[s]=e
def sec_of(r):
    for n,(a,b) in sec.items():
        if a<=r<b: return n
    return "?"
def strat(rva):
    e = imgb.find(b"\x00", rva, rva+200)
    if e < 0: return None
    try:
        t = imgb[rva:e].decode("ascii"); return t if t.isprintable() and len(t)>3 else None
    except: return None
def wstrat(rva):
    out = []
    p = rva
    while p+1 < len(imgb) and len(out) < 120:
        c = struct.unpack_from("<H", imgb, p)[0]
        if c == 0: break
        if c < 0x20 or c > 0x7e: return None
        out.append(chr(c)); p += 2
    return "".join(out) if len(out) > 3 else None
for a in [int(x,16) for x in sys.argv[1:]]:
    e = ends.get(a, a+0x400)
    strs = []; calls = 0; errs = set()
    for i in md.disasm(imgb[a:e], base+a):
        if i.mnemonic == "call": calls += 1
        if "rip + " in i.op_str or "rip - " in i.op_str:
            frag=i.op_str.split("rip ")[1]; sign=1 if frag[0]=='+' else -1
            t=i.address+i.size+int(frag[2:].split("]")[0],16)*sign-base
            if i.mnemonic == "lea":
                sv = strat(t) or wstrat(t)
                if sv and sv not in strs: strs.append(sv)
            elif i.mnemonic == "mov" and sec_of(t) == ".sbss":
                errs.add(t)
    print(f"+0x{a:X}  {e-a:5d} b  {sec_of(a):8s} {calls:3d} calls  sbss reads {len(errs)}")
    for s in strs[:10]: print(f"      {s[:110]!r}")
