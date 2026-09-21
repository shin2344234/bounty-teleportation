"""The +0x4F0 sub-object's API: every function that forms its address
(lea [reg+0x4F0]) or touches its fields through the component
(+0x500 = held thing, +0x540 = p50, +0x548 = blocked byte, +0x54A = hold
count), plus the neighbours of +0x2BBF2C0 in pdata, which is where a
class's methods sit. For each: what it writes to +0x58 / +0x10 of the
sub-object, whether addressed through the component or through a sub
pointer."""
import sys, struct, bisect, re
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
import capstone
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
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
    return s if r<ends[s] else None
def sec_of(r):
    for n,(a,b) in sec.items():
        if a<=r<b: return n
    return "?"
exec_lo_hi = [(a,b) for n,(a,b) in sec.items() if n in (".code",".didata")]
def in_exec(r): return any(a<=r<b for a,b in exec_lo_hi)

# lea reg,[reg+0x4F0]: 48/4C 8D /r with disp32 = 0x4F0
hits = {}
for m in re.finditer(rb'[\x48\x49\x4c\x4d]\x8d[\x80-\xbf]\xf0\x04\x00\x00', imgb):
    r = m.start()
    if not in_exec(r): continue
    f = fn(r)
    if f: hits.setdefault(f, []).append(("lea +0x4F0", r))
# byte/word/qword accesses at +0x548, +0x54A, +0x500, +0x540 with disp32
for disp, what in ((0x548, "+0x548 blocked"), (0x54A, "+0x54A holds"), (0x500, "+0x500 held"), (0x540, "+0x540 p50")):
    pat = struct.pack('<I', disp)
    for m in re.finditer(re.escape(pat), imgb):
        r = m.start() - 2   # modrm at r+1 for 2-byte opcode forms; check a few shapes
        for back in (2, 3, 4):
            p = m.start() - back
            if p < 0 or not in_exec(p): continue
            try:
                ins = next(md.disasm(imgb[p:p+16], base+p))
            except StopIteration:
                continue
            if ins.size == back + 4 and f"0x{disp:x}]" in ins.op_str:
                f = fn(p)
                if f: hits.setdefault(f, []).append((what, p, ins.mnemonic + " " + ins.op_str))
                break

print(f"{len(hits)} functions touch the sub-object through the component\n")
for f in sorted(hits):
    kinds = sorted(set(h[0] for h in hits[f]))
    print(f"+0x{f:X}  ({ends[f]-f:5d} b, {sec_of(f)})  {', '.join(kinds)}")
    for h in hits[f][:6]:
        if len(h) == 3: print(f"      +0x{h[1]:X}  {h[2]}")

print("\n=== pdata neighbours of +0x2BBF2C0 (the sub-object's own methods) ===")
i = bisect.bisect_left(starts, 0x2BBF2C0)
for s in starts[max(0,i-14):i+14]:
    size = ends[s]-s
    body = list(md.disasm(imgb[s:ends[s]], base+s))
    w58 = [x for x in body if x.mnemonic.startswith("mov") and re.search(r"byte ptr \[r\w+ \+ 0x58\]", x.op_str) and x.op_str.startswith("byte")]
    w10 = [x for x in body if x.mnemonic.startswith("mov") and re.search(r"qword ptr \[r\w+ \+ 0x10\]", x.op_str) and x.op_str.startswith("qword")]
    r58 = [x for x in body if "0x58]" in x.op_str]
    mark = " <== hold acquirer" if s == 0x2BBF2C0 else ""
    print(f"+0x{s:X}  {size:5d} b  writes+0x58:{len(w58):2d} writes+0x10:{len(w10):2d} reads+0x58:{len(r58):2d}{mark}")
    for x in w58[:3]: print(f"      +0x{x.address-base:X}  {x.mnemonic} {x.op_str}")
