import sys, re, struct
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image, sections
base, img, pe = load_image()
imgb = bytes(img); sec = sections(pe)
leap = re.compile(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
leas = {}
for m in leap.finditer(imgb):
    i = m.start(); d = struct.unpack_from('<i', imgb, i+3)[0]
    leas.setdefault(i+7+d, []).append(i)
LO, HI = 0x2BC0000, 0x2BE0000
names = ["TrMoveFieldAck","TrSetMoveFieldAck","TrMoveFieldCompleteAck","MoveField",
         "SetMoveField","ClientFrameEventReleaseCatch","processForceReleaseCatch",
         ".?AVCommonCatchActorComponent@pa@@", "GimmickEventHandlerData_MoveField"]
for nm in names:
    b = nm.encode()
    off = 0; locs=[]
    while True:
        i = imgb.find(b + b"\x00", off)
        if i < 0: break
        if i==0 or imgb[i-1] in (0,0x2E) or True: locs.append(i)
        off = i+1
    for sr in locs[:6]:
        refs = leas.get(sr, [])
        near = [r for r in refs if LO <= r <= HI]
        if refs:
            print(f"{nm}  str+0x{sr:X}  xrefs={len(refs)}  in-range={[hex(x) for x in near]}  all={[hex(x) for x in refs[:8]]}")
