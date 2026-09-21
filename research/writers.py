"""Who writes byte [actor+0xC2], and who calls the sub-object's blocked-byte
writers. Writes: C6 /0 disp32 imm8 (mov byte [r+disp], imm) and 88 /r disp32
(mov byte [r+disp], reg), any REX. Calls: E8 rel32 to the target."""
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
    if i<0: return None
    s=starts[i]; return s if r<ends[s] else None
ex = [(a,b) for n,(a,b) in sec.items() if n in (".code",".didata")]
def in_exec(r): return any(a<=r<b for a,b in ex)
def strat(rva):
    e = imgb.find(b"\x00", rva, rva+160)
    if e < 0: return None
    try:
        t = imgb[rva:e].decode("ascii"); return t if t.isprintable() and len(t)>3 else None
    except: return None
def dis(a, cap):
    for i in md.disasm(imgb[a:a+cap], base+a):
        note=""
        if "rip + " in i.op_str or "rip - " in i.op_str:
            frag=i.op_str.split("rip ")[1]; sign=1 if frag[0]=='+' else -1
            t=i.address+i.size+int(frag[2:].split("]")[0],16)*sign-base
            sv=strat(t); note=f"   ; [+0x{t:X}]"+(f' "{sv}"' if sv else "")
        if i.mnemonic in ("call","jmp") and i.op_str.startswith("0x"):
            note += f"   ; -> +0x{int(i.op_str,16)-base:X}"
        print(f"+0x{i.address-base:X}  {i.mnemonic:<8} {i.op_str}{note}")
        if i.mnemonic == "ret": break

print("=== byte writes to [reg+0xC2] ===")
disp = b"\xc2\x00\x00\x00"
found = {}
for m in re.finditer(re.escape(disp), imgb):
    for back in (2, 3):
        p = m.start() - back
        if p < 0 or not in_exec(p): continue
        op = imgb[p:p+back]
        # C6 modrm(disp32, /0) | 88 modrm | REX + either
        if not (op[-2] in (0xC6, 0x88) and (op[-1] & 0xC7) in (0x80,0x81,0x82,0x83,0x85,0x86,0x87) and (op[-2] != 0xC6 or (op[-1] & 0x38) == 0)):
            continue
        if back == 3 and not (0x40 <= op[0] <= 0x4F): continue
        try: ins = next(md.disasm(imgb[p:p+16], base+p))
        except StopIteration: continue
        if ins.mnemonic != "mov" or "0xc2]" not in ins.op_str or not ins.op_str.startswith("byte ptr"): continue
        f = fn(p)
        found.setdefault(f, []).append((p, ins.op_str))
        break
for f in sorted(found, key=lambda x: (x is None, x)):
    print(f"+0x{f:X} ({ends[f]-f} b)" if f else "(no pdata)")
    for p, s in found[f]: print(f"      +0x{p:X}  mov {s}")

print("\n=== callers of the blocked-byte writers ===")
targets = {0x2BBE6A0: "setter(dil)", 0x2BBF0C0: "writes 2", 0x2BBFA00: "writes 3", 0x2BC4200: "hold wrapper"}
calls = {t: [] for t in targets}
for m in re.finditer(rb"\xe8", imgb):
    p = m.start()
    if not in_exec(p): continue
    rel = struct.unpack_from("<i", imgb, p+1)[0]
    t = p + 5 + rel
    if t in calls: calls[t].append(p)
for t, why in targets.items():
    fs = sorted({fn(p) for p in calls[t] if fn(p)})
    print(f"+0x{t:X} {why}: {len(calls[t])} call sites in {len(fs)} functions: {', '.join(f'+0x{f:X}' for f in fs[:12])}")

print("\n=== +0x2BBE6A0 (setter) ===")
dis(0x2BBE6A0, 336)
print("\n=== +0x2BBF0C0 head to the write of 2 ===")
dis(0x2BBF0C0, 0xB0)
