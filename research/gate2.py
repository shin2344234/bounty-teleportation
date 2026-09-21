import sys, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image
import capstone
base, img, pe = load_image()
imgb = bytes(img)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
LO, HI = 0x2AF8010, 0x2AF8010 + 1527
ERR = 0x2AF8196

# Disassemble linearly from the real function start so nothing is misaligned.
ins_at = {}
order = []
for ins in md.disasm(imgb[LO:HI], base + LO):
    r = ins.address - base
    ins_at[r] = ins
    order.append(r)
print(f"decoded {len(order)} instructions from the function start\n")

# Every branch that lands on the error store.
print(f"=== branches targeting the error store +0x{ERR:X} ===")
found = []
for r in order:
    ins = ins_at[r]
    if not ins.mnemonic.startswith("j"): continue
    try:
        t = int(ins.op_str, 16) - base
    except ValueError:
        continue
    if t == ERR:
        found.append(r)
        prev = [q for q in order if q < r][-3:]
        print(f"  +0x{r:X}  {ins.mnemonic} -> +0x{t:X}")
        for q in prev:
            print(f"      preceded by +0x{q:X}  {ins_at[q].mnemonic:<9} {ins_at[q].op_str}")
        print()
if not found:
    print("  none: the error store is only reached by falling through\n")

print(f"=== instructions immediately before the error store ===")
for r in [q for q in order if q < ERR][-8:]:
    print(f"  +0x{r:X}  {ins_at[r].mnemonic:<9} {ins_at[r].op_str}")
print(f"  +0x{ERR:X}  {ins_at[ERR].mnemonic:<9} {ins_at[ERR].op_str}   <<<< error store" if ERR in ins_at else "  (error store did not decode on this alignment)")
