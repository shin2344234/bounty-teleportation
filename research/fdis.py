"""Disassemble whole functions by RVA using the exception directory for
their ends. `py -3 dis.py 0xRVA [0xRVA...]`; `--from 0xA --to 0xB` for a
range. Annotates rip-relative strings/eErr globals and call targets."""
import sys, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
import capstone
base, img, pe = load_image(); imgb = bytes(img); sec = sections(pe)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
ends = {}; starts = []
for off in range(d.VirtualAddress, d.VirtualAddress + d.Size, 12):
    s, e, u = struct.unpack_from('<III', imgb, off)
    if s: ends[s] = e; starts.append(s)
starts.sort()
import bisect
def func_of(r):
    i = bisect.bisect_right(starts, r) - 1
    if i >= 0 and starts[i] <= r < ends[starts[i]]: return starts[i]
    return None
def strat(rva):
    e = imgb.find(b"\x00", rva, rva + 200)
    if e < 0: return None
    try:
        t = imgb[rva:e].decode("ascii"); return t if t.isprintable() and len(t) > 3 else None
    except Exception: return None
def wstrat(rva):
    out = []; p = rva
    while p + 1 < len(imgb) and len(out) < 120:
        c = struct.unpack_from("<H", imgb, p)[0]
        if c == 0: break
        if c < 0x20 or c > 0x7e: return None
        out.append(chr(c)); p += 2
    return "".join(out) if len(out) > 3 else None
errnames = {}
try:
    import json, os
    p = os.path.join(os.path.dirname(__file__), "errmap.json")
    if os.path.exists(p): errnames = {int(k, 16): v for k, v in json.load(open(p)).items()}
except Exception: pass
def sec_of(r):
    for n, (a, b) in sec.items():
        if a <= r < b: return n
    return "?"
def dis(a, e):
    print(f"; +0x{a:X}..+0x{e:X} ({e-a} bytes, {sec_of(a)})")
    for i in md.disasm(imgb[a:e], base + a):
        rva = i.address - base; note = ""
        if "rip + " in i.op_str or "rip - " in i.op_str:
            frag = i.op_str.split("rip ")[1]; sign = 1 if frag[0] == '+' else -1
            val = int(frag[2:].split("]")[0], 16) * sign
            t = i.address + i.size + val - base
            sv = strat(t) or wstrat(t)
            nm = errnames.get(t)
            note = f"   ; [+0x{t:X}]" + (f' "{sv}"' if sv else "") + (f" {nm}" if nm else "")
        elif i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16) - base
            f = func_of(t)
            note = f"   ; +0x{t:X}" + ("" if f in (None, t) else f" (inside +0x{f:X})")
        print(f"+0x{rva:07X}  {i.mnemonic:<9} {i.op_str}{note}")
args = sys.argv[1:]
if args and args[0] == "--from":
    dis(int(args[1], 16), int(args[3], 16))
else:
    for x in args:
        a = int(x, 16); f = func_of(a)
        if f is None: print(f"; +0x{a:X}: no pdata entry"); continue
        dis(f, ends[f])
