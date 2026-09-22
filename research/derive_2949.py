"""Re-derive every address Bounty Teleportation uses, on whatever
CrimsonDesert.exe is installed. Written for the 1.0.0.2949 patch, which moved
all of them.

Nothing here is hardcoded to an offset from the old build. Each address is
found from a byte pattern or from a reference to something already found:

    catch_update      the call the watchdog's guard is followed by
    the releases      every copy of the release test whose call goes there
    the holder check  its prologue, then the thunk that jumps to it, then the
                      call that reaches the thunk
    the teleport      the release call inside it, then its function start and
                      its callers

    py -3 derive_2949.py
"""
import sys, re, struct, bisect
sys.path.insert(0, r"C:\working\cd mods\No more flight restrictions\private\research")
from cdimage import load_image

BASE, img, pe = load_image()
b = bytes(img)

# --- function bounds from the exception directory -------------------------
pe.parse_data_directories()
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
ends, starts = {}, []
for off in range(d.VirtualAddress, d.VirtualAddress + d.Size, 12):
    s, e, _ = struct.unpack_from('<III', b, off)
    if s:
        ends[s] = e
        starts.append(s)
starts.sort()

def func_of(rva):
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0 and starts[i] <= rva < ends[starts[i]]:
        return starts[i]
    return None

def rel32(rva, op):
    if b[rva] != op:
        return None
    return rva + 5 + struct.unpack_from('<i', b, rva + 1)[0]

def find_all(pattern):
    return [m.start() for m in re.finditer(re.escape(bytes(pattern)), b)]

def calls_to(target, op=0xE8):
    """Every rel32 call or jump landing on target."""
    out = []
    for m in re.finditer(bytes([op]), b):
        r = m.start()
        try:
            if rel32(r, op) == target:
                out.append(r)
        except Exception:
            pass
    return out

print(f"SizeOfImage {pe.OPTIONAL_HEADER.SizeOfImage}\n")

# --- 1. the watchdog, and catch_update through it -------------------------
WATCHDOG_GUARD = [0x85, 0xFF, 0x75, 0x04, 0x85, 0xDB, 0x74, 0x3E]
wd = find_all(WATCHDOG_GUARD)
assert len(wd) == 1, f"watchdog guard: {len(wd)} hits, expected 1"
wd_guard = wd[0]
# The guard's own je gives the landing spot; the call sits five bytes before it.
wd_skip = wd_guard + 6 + 2 + b[wd_guard + 7]
wd_call = wd_skip - 5
catch_update = rel32(wd_call, 0xE8)
print("watchdog")
print(f"  guard        +0x{wd_guard:X}")
print(f"  its je lands +0x{wd_skip:X}")
print(f"  release call +0x{wd_call:X}")
print(f"  catch_update +0x{catch_update:X}   (was +0x20AD3A0 on 2944)")
print(f"  function     +0x{func_of(wd_guard):X}   (was +0x20AE540)")

# --- 2. every release that calls catch_update -----------------------------
TELEPORT_GUARD = [0x83, 0x79, 0x38, 0x00, 0x74, 0x04, 0xB3, 0x01,
                  0xEB, 0x07, 0x83, 0x79, 0x28, 0x00, 0x0F, 0x95]
print("\nthe release test, everywhere it appears")
releases = []
for g in find_all(TELEPORT_GUARD):
    # Within the next 0x60 bytes, a short je followed later by a call to
    # catch_update is the release. Find the call first, then the je over it.
    win = b[g:g + 0x80]
    hit = None
    for i in range(len(win) - 5):
        if win[i] == 0xE8 and rel32(g + i, 0xE8) == catch_update:
            hit = g + i
            break
    if hit is None:
        print(f"  +0x{g:X}  no catch_update call within 0x80 bytes, not a release")
        continue
    # The je that skips it lands just past the call.
    landing = hit + 5
    je = None
    for i in range(g, hit):
        if b[i] == 0x74 and i + 2 + b[i + 1] == landing:
            je = i
    if je is None:
        print(f"  +0x{g:X}  call at +0x{hit:X} but no je over it")
        continue
    f = func_of(g)
    releases.append((f, g, je, b[je + 1], hit))
    print(f"  +0x{g:X}  je +0x{je:X} (74 {b[je+1]:02X}) over call +0x{hit:X}, in function +0x{f:X}")

# --- 3. the departure sweep's holder check --------------------------------
HOLDER = [0x48, 0x89, 0x5C, 0x24, 0x08, 0x44, 0x8B, 0x41, 0x1C]
h = find_all(HOLDER)
print("\nthe holder check")
print(f"  prologue     {len(h)} hit(s): " + ", ".join(f"+0x{x:X}" for x in h))
if len(h) == 1:
    check = h[0]
    thunks = calls_to(check, 0xE9)
    print(f"  thunks to it: " + ", ".join(f"+0x{x:X}" for x in thunks))
    for t in thunks:
        callers = calls_to(t, 0xE8)
        print(f"    +0x{t:X} is called from: " + ", ".join(f"+0x{x:X}" for x in callers))

# --- 4. the map teleport handler ------------------------------------------
TAIL = [0x49, 0x8B, 0x45, 0x68, 0x48, 0x8B, 0x48, 0x40, 0x48, 0x8B, 0x01,
        0xFF, 0x90, 0x00, 0x02, 0x00, 0x00]
t = find_all(TAIL)
print("\nthe map teleport handler")
print(f"  release call {len(t)} hit(s): " + ", ".join(f"+0x{x + 11:X}" for x in t))
for x in t:
    f = func_of(x)
    print(f"  function     +0x{f:X}   (was +0x2BC9640)")
    print(f"  prologue     " + " ".join(f"{c:02X}" for c in b[f:f + 15]))
    print(f"  callers      " + ", ".join(f"+0x{c:X}" for c in calls_to(f, 0xE8)))
