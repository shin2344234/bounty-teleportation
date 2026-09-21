import sys
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image
import capstone
base, img, pe = load_image()
imgb = bytes(img)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
LO = 0x2BCD820; ERR = 0x2BCD88A; HI = LO + 5324
ins = list(md.disasm(imgb[LO:HI], base + LO))
print(f"decoded {len(ins)} instructions")
print("=== entry to just past the error store ===")
for i in ins:
    r = i.address - base
    if r > ERR + 0x30: break
    print(f"+0x{r:X}  {i.mnemonic:<8} {i.op_str}")
print("\n=== every instruction in the function touching [rbp+8] or [rbp-8] ===")
for i in ins:
    if "rbp + 8]" in i.op_str or "rbp - 8]" in i.op_str:
        print(f"+0x{i.address-base:X}  {i.mnemonic:<8} {i.op_str}")
print("\n=== every lea of rbp+8 / rbp-8 (out-param passing) ===")
for i in ins:
    if i.mnemonic == "lea" and ("rbp + 8]" in i.op_str or "rbp - 8]" in i.op_str):
        print(f"+0x{i.address-base:X}  {i.mnemonic:<8} {i.op_str}")
