import sys, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image
import capstone
base, img, pe = load_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

start = 0x23E103B
p = start
while p > start - 0x3000:
    if img[p-1] == 0xCC and img[p-2] == 0xCC:
        break
    p -= 1
print(f"function start guess +0x{p:X}  (back {start-p} bytes)")
end = start + 0x200
strcache = {}
def strat(rva):
    e = img.find(b"\x00", rva)
    s = bytes(img[rva:e])
    try: return s.decode()
    except: return None
for ins in md.disasm(bytes(img[p:end]), base + p):
    rva = ins.address - base
    note = ""
    if ins.mnemonic == "lea" and "rip" in ins.op_str:
        tgt = ins.address + ins.size + int(ins.op_str.split("rip + ")[-1].rstrip("]"), 16) if "rip + " in ins.op_str else None
        if tgt:
            t = tgt - base
            sv = strat(t)
            if sv and sv.isprintable() and 2 < len(sv) < 90: note = f"   ; \"{sv}\""
    print(f"+0x{rva:07X}  {ins.mnemonic:<9} {ins.op_str}{note}")
