import collections
import math
import mmap
import struct
import sys
from pathlib import Path

p = Path(sys.argv[1])
f = p.open("rb")
d = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
size = len(d)
pe = struct.unpack_from("<I", d, 0x3C)[0]
ns = struct.unpack_from("<H", d, pe + 6)[0]
optsize = struct.unpack_from("<H", d, pe + 20)[0]
seco = pe + 24 + optsize
secs = []
for i in range(ns):
    o = seco + 40 * i
    n = d[o:o + 8].rstrip(b"\0").decode()
    vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
    secs.append((n, rp, rs, va, vs))

def sec_of(off):
    for n, rp, rs, va, vs in secs:
        if rp <= off < rp + rs:
            return n
    return "?"

STEP = 1048576
ents = []
for off in range(0, size, STEP):
    c = d[off:off + STEP]
    if len(c) < 65536:
        break
    cnt = collections.Counter(c)
    e = -sum((n / len(c)) * math.log2(n / len(c)) for n in cnt.values())
    ents.append((off, e, sec_of(off)))

print("=== HIGH ENTROPY (>7.5) 1MiB BLOCKS ===", flush=True)
hi = [x for x in ents if x[1] > 7.5]
print(f"blocks={len(hi)} total={len(hi)*STEP/1048576:.1f} MiB; by section={collections.Counter(x[2] for x in hi)}", flush=True)
ranges = []
start = prev = None
for off, e, s in hi:
    if start is None or off != prev + STEP or s != start[2]:
        if start is not None:
            ranges.append((start, prev + STEP))
        start = (off, e, s)
    prev = off
if start is not None:
    ranges.append((start, prev + STEP))
for a, b in ranges:
    print(f"{a[2]:8s} {a[0]:>12,} .. {b:>12,}  {(b-a[0])/1048576:6.1f} MiB  ent~{a[1]:.2f}", flush=True)
    ctx = d[max(0, a[0] - 512):a[0] + 512]
    txt = "".join(chr(x) if 32 <= x < 127 else "." for x in ctx)
    print(f"   context: {txt[:400]}", flush=True)
print(flush=True)

print("=== ENTROPY HISTOGRAM BY SECTION (1MiB blocks) ===", flush=True)
by = collections.defaultdict(list)
for off, e, s in ents:
    by[s].append(e)
for s, vals in by.items():
    lo = sum(v < 6 for v in vals)
    mid = sum(6 <= v < 7.5 for v in vals)
    hig = sum(v >= 7.5 for v in vals)
    print(f"{s:10s} blocks={len(vals):>4d} <6:{lo:>4d} 6-7.5:{mid:>4d} >=7.5:{hig:>4d} "
          f"avg={sum(vals)/len(vals):.2f} min={min(vals):.2f} max={max(vals):.2f}", flush=True)
