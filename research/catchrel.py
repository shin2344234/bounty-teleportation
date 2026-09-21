import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
def sec_of(r):
    for n,(a,b) in sec.items():
        if a <= r < b: return n
    return "?"
leap = re.compile(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
leas = {}
for m in leap.finditer(imgb):
    i = m.start(); d = struct.unpack_from('<i', imgb, i+3)[0]
    leas.setdefault(i+7+d, []).append(i)

def find_str(s):
    b = s.encode(); off=0; out=[]
    while True:
        i = imgb.find(b + b"\x00", off)
        if i<0: break
        out.append(i); off=i+1
    return out

for nm in ["processForceReleaseCatch ", "processRemoteCatchReleaseForced ",
           "eErrNoRequestLogoutByReleaseCatch", "eErrNoCantDoWhileCatchingOrCatched",
           "eErrNoSpawnParentCatcherLogout"]:
    for sr in find_str(nm):
        refs = leas.get(sr, [])
        print(f"{nm!r} str+0x{sr:X} lea-xrefs={[hex(x) for x in refs[:6]]}")

# All 32-bit global reads of the error globals, any encoding (8B /r rip, 39 /r rip, 3B)
def readers(g):
    out=[]
    for pat, opl, dispoff in ((rb'\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                              (rb'\x39[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                              (rb'\x3b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',6,2),
                              (rb'[\x44\x45\x4c\x4d]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',7,3)):
        for m in re.finditer(pat, imgb):
            i=m.start(); d=struct.unpack_from('<i',imgb,i+dispoff)[0]
            if i+opl+d==g and sec_of(i)==".code": out.append(i)
    return sorted(set(out))
for label,g in [("eErrNoFieldMoveHolding",0x6CF6B5C)]:
    print(f"{label} global +0x{g:X} all readers: {[hex(x) for x in readers(g)]}")
