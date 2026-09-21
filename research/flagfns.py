"""The three most suspicious writers of byte [actor+0xC2]: which eErr names
each reads, and the disassembly around each write."""
import sys, struct, re
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
tbl = io = open(r"C:\working\cd mods\Bounty Teleportation\mod\src\game\errors_table.h").read()
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
def show(a, window):
    e = ends.get(a, a+0x400)
    ins = list(md.disasm(imgb[a:e], base+a))
    errs = []
    for i in ins:
        if "rip + " in i.op_str or "rip - " in i.op_str:
            frag=i.op_str.split("rip ")[1]; sign=1 if frag[0]=='+' else -1
            t=i.address+i.size+int(frag[2:].split("]")[0],16)*sign-base
            if i.mnemonic=="mov" and sec_of(t)==".sbss": errs.append(g2n.get(t, f"+0x{t:X}"))
    print(f"\n##### +0x{a:X} ({e-a} b, {sec_of(a)}) errors: {errs}")
    idx = [k for k,i in enumerate(ins) if "0xc2]" in i.op_str and i.op_str.startswith("byte")]
    for k in idx:
        lo, hi = max(0,k-window), min(len(ins), k+6)
        print(f"  --- around +0x{ins[k].address-base:X}")
        for i in ins[lo:hi]:
            note=""
            if "rip + " in i.op_str or "rip - " in i.op_str:
                frag=i.op_str.split("rip ")[1]; sign=1 if frag[0]=='+' else -1
                t=i.address+i.size+int(frag[2:].split("]")[0],16)*sign-base
                sv=strat(t); note=f"   ; [+0x{t:X}]"+(f' "{sv}"' if sv else "")+(f" {g2n[t]}" if t in g2n else "")
            if i.mnemonic in ("call","jmp") and i.op_str.startswith("0x"): note += f"   ; -> +0x{int(i.op_str,16)-base:X}"
            print(f"  +0x{i.address-base:X}  {i.mnemonic:<8} {i.op_str}{note}")
for a, w in ((0x2BC1A30, 28), (0x10BBB950, 24), (0x2AFDDF0, 24), (0x21E3390, 16), (0x9D5C8A0, 16), (0x77A9E0, 14)):
    show(a, w)
