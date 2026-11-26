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
secs = {}
for i in range(ns):
    o = seco + 40 * i
    n = d[o:o + 8].rstrip(b"\0").decode()
    vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
    secs[n] = (rp, rs)

B = 65536
def stats(c):
    cnt = collections.Counter(c)
    ent = -sum((n / len(c)) * math.log2(n / len(c)) for n in cnt.values())
    zero = c.count(0) / len(c)
    pr = sum(32 <= x < 127 or x in (9, 10, 13) for x in c) / len(c)
    hi = sum(x >= 128 for x in c) / len(c)
    qw = [struct.unpack_from("<Q", c, j)[0] for j in range(0, len(c) - 7, 8)]
    ptr = sum(0x140000000 <= x < 0x141f000000 for x in qw) / len(qw)
    return ent, zero, pr, hi, ptr

results = collections.defaultdict(lambda: collections.Counter())
ranges = collections.defaultdict(list)
for name in (".text", ".rdata", ".data", ".pdata", ".xdata", ".reloc"):
    rp, rs = secs[name]
    for off in range(rp, rp + rs, B):
        c = d[off:off + B]
        if len(c) < B // 2:
            continue
        ent, zero, pr, hi, ptr = stats(c)
        if zero > 0.6:
            cat = "padding/zeros"
        elif ent > 7.4 and pr < 0.55 and ptr < 0.03:
            cat = "opaque high-entropy blob"
        elif ptr > 0.12:
            cat = "pointer/vtable tables"
        elif pr > 0.55:
            cat = "ASCII strings / text"
        elif hi > 0.20 and pr > 0.20:
            cat = "UTF-8 localized text"
        elif ent < 6.0:
            cat = "structured low-entropy data"
        else:
            cat = "mixed binary/constants"
        results[name][cat] += len(c)
        if cat == "opaque high-entropy blob":
            ranges[name].append(off)

for name in results:
    total = sum(results[name].values())
    print(f"=== {name} ({total:,} bytes) ===")
    for cat, n in results[name].most_common():
        print(f"  {cat:28s} {n:>12,} ({100*n/total:5.1f}%)")
    print()

print("=== OPAQUE BLOB RUNS (>=1MiB contiguous, .rdata) ===")
run = []
for off in ranges[".rdata"]:
    if run and off == run[-1] + B:
        run.append(off)
    else:
        if len(run) * B >= 1048576:
            a, b = run[0], run[-1] + B
            print(f"{a:,} .. {b:,}  {(b-a)/1048576:.2f} MiB")
            before = d[max(0, a - 400):a]
            txt = "".join(chr(x) if 32 <= x < 127 else "." for x in before)
            print(f"   before: {txt[-300:]}")
        run = [off]
if len(run) * B >= 1048576:
    a, b = run[0], run[-1] + B
    print(f"{a:,} .. {b:,}  {(b-a)/1048576:.2f} MiB")
