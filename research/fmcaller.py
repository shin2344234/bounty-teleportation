"""+0x2BCCE30, the function that calls the field-move handler at +0x2BCCE78:
full disassembly with strings, error names and call targets, and its callers."""
import sys, struct, bisect, re
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
import capstone
base, img, pe = load_image(); imgb = bytes(img); sec = sections(pe)
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
    return starts[i] if i>=0 and r<ends[starts[i]] else None
tbl = open(r"C:\working\cd mods\Bounty Teleportation\mod\src\game\errors_table.h").read()
g2n = {int(m.group(1),16): m.group(2) for m in re.finditer(r'\{\s*0x([0-9A-Fa-f]+)u?,\s*"([^"]+)"', tbl)}
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
def rtti_of_vt(vt):
    try:
        col, = struct.unpack_from("<Q", imgb, vt-8); col -= base
        if not (0 < col < len(imgb)): return None
        sig, off, cd, tdoff = struct.unpack_from("<IIII", imgb, col)
        if sig != 1: return None
        n = strat(tdoff+0x10)
        return n[4:-2] if n and n.startswith(".?AV") else None
    except Exception: return None
A = 0x2BCCE30; E = ends[A]
print(f"===== +0x{A:X} ({E-A} b, {sec_of(A)})")
for i in md.disasm(imgb[A:E], base+A):
    note=""
    if "rip + " in i.op_str or "rip - " in i.op_str:
        frag=i.op_str.split("rip ")[1]; sign=1 if frag[0]=='+' else -1
        t=i.address+i.size+int(frag[2:].split("]")[0],16)*sign-base
        sv=strat(t); rt = rtti_of_vt(t) if i.mnemonic=="lea" else None
        note=f"   ; [+0x{t:X}]"+(f' "{sv}"' if sv else "")+(f" {g2n[t]}" if t in g2n else "")+(f" vtable {rt}" if rt else "")
    if i.mnemonic in ("call","jmp") and i.op_str.startswith("0x"):
        t=int(i.op_str,16)-base; f=fn(t); note += f"   ; -> +0x{t:X}" + (f" ({ends[f]-f} b)" if f else "")
    print(f"+0x{i.address-base:X}  {i.mnemonic:<8} {i.op_str}{note}")
print("\n===== callers of +0x2BCCE30")
calls=[]
for m in re.finditer(rb"\xe8", imgb):
    p=m.start()
    if sec_of(p) not in (".code",".didata"): continue
    if p+5+struct.unpack_from("<i",imgb,p+1)[0]==A: calls.append(p)
for p in calls: print(f"  +0x{p:X} in +0x{fn(p):X} ({ends[fn(p)]-fn(p)} b)" if fn(p) else f"  +0x{p:X}")
