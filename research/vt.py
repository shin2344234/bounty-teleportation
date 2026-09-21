"""Vtables by RTTI name, and the function in a given slot, disassembled.
    py -3 vt.py ServerNormalInGameActor 0x1d8 [more classes...]
"""
import sys, struct, bisect
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
def strat(rva):
    e = imgb.find(b"\x00", rva, rva+160)
    if e < 0: return None
    try:
        t = imgb[rva:e].decode("ascii"); return t if t.isprintable() and len(t)>3 else None
    except: return None
def vtables(name):
    pat = (".?AV" + name + "@pa@@").encode() + b"\x00"
    out = []
    i = imgb.find(pat)
    while i >= 0:
        td = i - 0x10
        tgt = struct.pack("<I", td); j = imgb.find(tgt)
        while j >= 0:
            col = j - 12
            if col >= 0 and struct.unpack_from("<I", imgb, col)[0] == 1:
                off = struct.unpack_from("<I", imgb, col+4)[0]
                k = imgb.find(struct.pack("<Q", base+col))
                while k >= 0:
                    out.append((k+8, off)); k = imgb.find(struct.pack("<Q", base+col), k+1)
            j = imgb.find(tgt, j+1)
        i = imgb.find(pat, i+1)
    return sorted(set(out))
def dis(a, cap=0x300):
    e = ends.get(a, a+cap)
    for i in md.disasm(imgb[a:min(e, a+cap)], base+a):
        note=""
        if "rip + " in i.op_str or "rip - " in i.op_str:
            frag=i.op_str.split("rip ")[1]; sign=1 if frag[0]=='+' else -1
            t=i.address+i.size+int(frag[2:].split("]")[0],16)*sign-base
            sv=strat(t); note=f"   ; [+0x{t:X}]"+(f' "{sv}"' if sv else "")
        if i.mnemonic in ("call","jmp") and i.op_str.startswith("0x"):
            note += f"   ; -> +0x{int(i.op_str,16)-base:X}"
        print(f"+0x{i.address-base:X}  {i.mnemonic:<8} {i.op_str}{note}")
slot = int(sys.argv[2], 16)
seen = set()
for name in [sys.argv[1]] + sys.argv[3:]:
    vts = vtables(name)
    print(f"\n##### {name}: {len(vts)} vtable(s)")
    for vt, off in vts:
        fn, = struct.unpack_from("<Q", imgb, vt + slot); fn -= base
        print(f"  vt +0x{vt:X} (this offset {off}): slot 0x{slot:X} -> +0x{fn:X}  ({ends.get(fn,0)-fn} b)")
        if off == 0 and fn not in seen:
            seen.add(fn); dis(fn)
