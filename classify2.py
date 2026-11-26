import collections
import math
import mmap
import struct
import sys
from pathlib import Path

p = Path(sys.argv[1])
f = p.open("rb")
d = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
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
def classify(c):
    cnt = collections.Counter(c)
    ent = -sum((n / len(c)) * math.log2(n / len(c)) for n in cnt.values())
    pr = sum(32 <= x < 127 or x in (9, 10, 13) for x in c) / len(c)
    qw = [struct.unpack_from("<Q", c, j)[0] for j in range(0, len(c) - 7, 8)]
    ptr = sum(0x140000000 <= x < 0x141f000000 for x in qw) / len(qw)
    mp3 = c.count(b"\xff\xfb") + c.count(b"\xff\xf3") + c.count(b"\xff\xf2")
    utf8lead = sum(1 for x in c if 0xC2 <= x <= 0xF4) / len(c)
    if c.count(b"LAME3") or c.count(b"Xing") or mp3 > 200:
        return "MP3/audio media"
    if (b"\x89PNG\r\n\x1a\n" in c or b"WEBP" in c[:256] or b"JFIF" in c[:4096]):
        return "embedded images"
    if ptr > 0.12:
        return "pointer / vtable tables"
    if pr > 0.55 or (utf8lead > 0.10 and pr > 0.20):
        return "strings / localization"
    if ent > 7.4:
        return "opaque high-entropy data"
    if c.count(0) / len(c) > 0.6:
        return "zero padding"
    return "mixed constants / metadata"

for name in (".rdata", ".data"):
    rp, rs = secs[name]
    tally = collections.Counter()
    ents = collections.defaultdict(list)
    for off in range(rp, rp + rs, B):
        c = d[off:off + B]
        if len(c) < B // 2:
            continue
        cat = classify(c)
        tally[cat] += len(c)
        cnt = collections.Counter(c)
        ents[cat].append(-sum((n / len(c)) * math.log2(n / len(c)) for n in cnt.values()))
    print(f"=== {name} total {sum(tally.values()):,} ===")
    for cat, n in tally.most_common():
        print(f"  {cat:28s} {n:>12,} ({100*n/sum(tally.values()):5.1f}%) avg_entropy={sum(ents[cat])/len(ents[cat]):.2f}")
    print()
