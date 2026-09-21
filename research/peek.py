import sys
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img)
sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
for a in [int(x,16) for x in sys.argv[1:]]:
    print(f"+0x{a:X} ({sec_of(a)}):")
    print("   hex:", imgb[a:a+48].hex(' '))
    # try interpret as struct of pointers
    import struct
    for k in range(0,32,8):
        v = struct.unpack_from('<Q', imgb, a+k)[0]
        if base <= v < base + len(imgb):
            r = v - base
            e = imgb.find(b"\x00", r, r+200)
            s = imgb[r:e]
            try: s = s.decode('utf-8')
            except: s = repr(s)
            print(f"   +{k}: ptr -> +0x{r:X} {sec_of(r)}  {s[:110]!r}")
        else:
            print(f"   +{k}: 0x{v:016x}")
    e = imgb.find(b"\x00", a, a+200)
    try: print("   as str:", imgb[a:e].decode('utf-8')[:150])
    except Exception: pass
