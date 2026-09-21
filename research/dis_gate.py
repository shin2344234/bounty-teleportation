import sys, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
import capstone
base, img, pe = load_image()
imgb = bytes(img)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

target = int(sys.argv[1], 16)
back = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x400
fwd = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x200

p = target
while p > target - 0x4000:
    if img[p-1] == 0xCC and img[p-2] == 0xCC and img[p-3] == 0xCC:
        break
    p -= 1
print(f"; function start guess +0x{p:X} (back {target-p})")
start = max(p, target - back)
def strat(rva):
    e = imgb.find(b"\x00", rva, rva+200)
    if e < 0: return None
    s = imgb[rva:e]
    try:
        d = s.decode("ascii")
        return d if d.isprintable() and len(d) > 2 else None
    except: return None
for ins in md.disasm(imgb[start:target+fwd], base + start):
    rva = ins.address - base
    note = ""
    if "rip + " in ins.op_str or "rip - " in ins.op_str:
        try:
            frag = ins.op_str.split("rip ")[1]
            sign = 1 if frag[0] == '+' else -1
            val = int(frag[2:].split("]")[0], 16) * sign
            t = ins.address + ins.size + val - base
            sv = strat(t)
            note = f"   ; [+0x{t:X}]" + (f' "{sv}"' if sv else "")
        except Exception: pass
    mark = "  <<<< ERR READ" if rva == target else ""
    print(f"+0x{rva:07X}  {ins.mnemonic:<9} {ins.op_str}{note}{mark}")
