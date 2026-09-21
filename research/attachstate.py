"""The attacher sub-object's state byte: every value the family compares it
against or writes, and the two writers of 2 and 3 in full."""
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
def note_for(i):
    note=""
    if "rip + " in i.op_str or "rip - " in i.op_str:
        frag=i.op_str.split("rip ")[1]; sign=1 if frag[0]=='+' else -1
        t=i.address+i.size+int(frag[2:].split("]")[0],16)*sign-base
        sv=strat(t); note=f"   ; [+0x{t:X}]"+(f' "{sv}"' if sv else "")+(f" {g2n[t]}" if t in g2n else "")
    if i.mnemonic in ("call","jmp") and i.op_str.startswith("0x"): note += f"   ; -> +0x{int(i.op_str,16)-base:X}"
    return note
def dis(a, lo=None, hi=None):
    e = ends.get(a, a+0x400)
    for i in md.disasm(imgb[a:e], base+a):
        r = i.address-base
        if lo is not None and (r < lo or r >= hi): continue
        print(f"+0x{r:X}  {i.mnemonic:<8} {i.op_str}{note_for(i)}")
i0 = bisect.bisect_left(starts, 0x2BBDF50); i1 = bisect.bisect_left(starts, 0x2BC2C80)
print("=== state byte [+0x58]: values written or compared, per family function ===")
for s in starts[i0:i1+1]:
    vals = []
    for i in md.disasm(imgb[s:ends[s]], base+s):
        m = re.match(r"byte ptr \[(r\w+) \+ 0x58\], (0x[0-9a-f]+|\d+)$", i.op_str)
        if m and i.mnemonic in ("cmp","mov"):
            vals.append(f"{i.mnemonic}={int(m.group(2),0)}")
    if vals: print(f"+0x{s:X}  ({ends[s]-s:5d} b)  {' '.join(vals)}")
print("\n=== +0x2BBF0C0 (writes 2) ===")
dis(0x2BBF0C0)
print("\n=== +0x2BBFA00 (writes 3): entry and around the write ===")
dis(0x2BBFA00, 0x2BBFA00, 0x2BBFA90)
print("   ...")
dis(0x2BBFA00, 0x2BC0200, 0x2BC02F0)
print("\n=== callers of +0x10C7B5A0 (which calls the writer of 3) ===")
calls=[]
for m in re.finditer(rb"\xe8", imgb):
    p=m.start()
    if not any(a<=p<b for n,(a,b) in sec.items() if n in (".code",".didata")): continue
    if p+5+struct.unpack_from("<i",imgb,p+1)[0]==0x10C7B5A0: calls.append(p)
def fn(r):
    i=bisect.bisect_right(starts,r)-1
    return starts[i] if i>=0 and r<ends[starts[i]] else None
print(sorted({f"+0x{fn(p):X}" for p in calls if fn(p)}), len(calls), "sites")
