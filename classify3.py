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
opt = pe + 24
imagebase = struct.unpack_from("<Q", d, opt + 24)[0]
imagesize = struct.unpack_from("<I", d, opt + 56)[0]
imgend = imagebase + imagesize
print(f"image base 0x{imagebase:x} end 0x{imgend:x}")
seco = opt + optsize
secs = {}
for i in range(ns):
    o = seco + 40 * i
    n = d[o:o + 8].rstrip(b"\0").decode()
    vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
    secs[n] = (rp, rs)

B = 65536
def utf8_valid(c):
    valid = 0
    i = 0
    n = len(c)
    while i < n:
        b = c[i]
        if b < 0x80:
            i += 1
        elif 0xC2 <= b <= 0xDF and i + 1 < n and 0x80 <= c[i+1] <= 0xBF:
            valid += 2; i += 2
        elif 0xE0 <= b <= 0xEF and i + 2 < n and 0x80 <= c[i+1] <= 0xBF and 0x80 <= c[i+2] <= 0xBF \
             and not (b == 0xE0 and c[i+1] < 0xA0) and not (b == 0xED and c[i+1] > 0x9F):
            valid += 3; i += 3
        elif 0xF0 <= b <= 0xF4 and i + 3 < n and all(0x80 <= c[i+j] <= 0xBF for j in (1,2,3)) \
             and not (b == 0xF0 and c[i+1] < 0x90) and not (b == 0xF4 and c[i+1] > 0x8F):
            valid += 4; i += 4
        else:
            i += 1
    return valid / n

def classify(c):
    cnt = collections.Counter(c)
    ent = -sum((n / len(c)) * math.log2(n / len(c)) for n in cnt.values())
    pr = sum(32 <= x < 127 or x in (9, 10, 13) for x in c) / len(c)
    qw = [struct.unpack_from("<Q", c, j)[0] for j in range(0, len(c) - 7, 8)]
    ptr = sum(imagebase <= x < imgend for x in qw) / len(qw)
    mp3 = c.count(b"\xff\xfb") + c.count(b"\xff\xf3") + c.count(b"\xff\xf2")
    u8 = utf8_valid(c)
    if c.count(b"LAME3") or c.count(b"Xing") or mp3 > 200:
        return "MP3/audio media"
    if (b"\x89PNG\r\n\x1a\n" in c or b"WEBP" in c[:256] or b"JFIF" in c[:4096]):
        return "embedded images"
    if ptr > 0.15:
        return "pointer / vtable tables"
    if pr > 0.55 or u8 > 0.25:
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
    total = sum(tally.values())
    print(f"=== {name} total {total:,} ===")
    for cat, n in tally.most_common():
        print(f"  {cat:28s} {n:>12,} ({100*n/total:5.1f}%) avg_entropy={sum(ents[cat])/len(ents[cat]):.2f}")
    print()
