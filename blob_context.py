import collections
import mmap
import re
import struct
import sys
from pathlib import Path

p = Path(sys.argv[1])
f = p.open("rb")
d = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
size = len(d)
runs = [(328432128, 330922496), (331053568, 332495360), (332626432, 333675008),
        (333740544, 335378944), (335444480, 341998080), (343636480, 345012736),
        (346782208, 357267968), (357988864, 359102976), (359299584, 364345856),
        (370178560, 371948032), (382761472, 383810048)]

def strings_in(lo, hi, minlen=8):
    lo = max(0, lo)
    hi = min(size, hi)
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{8,}", d[lo:hi]):
        out.append((lo + m.start(), d[lo + m.start():lo + m.end()].decode("utf-8", "replace")))
    return out

for a, b in runs:
    print(f"=== blob {a:,}..{b:,} ({(b-a)/1048576:.2f} MiB) ===")
    before = strings_in(a - 262144, a)
    after = strings_in(b, b + 262144)
    print("  preceding strings (last 6):")
    for off, s in before[-6:]:
        print(f"    {off:,}: {s[:160]}")
    print("  following strings (first 6):")
    for off, s in after[:6]:
        print(f"    {off:,}: {s[:160]}")
    blob = d[a:b]
    found = []
    for name, sig in [("zstd", b"\x28\xb5\x2f\xfd"), ("gzip", b"\x1f\x8b\x08"),
                      ("zlib", b"\x78\x9c"), ("lz4", b"\x04\x22\x4d\x18"),
                      ("brotli", b"\x8b\x07"), ("mp3", b"\xff\xfb"),
                      ("png", b"\x89PNG\r\n\x1a\n"), ("webp", b"WEBP")]:
        c = blob.count(sig)
        if c:
            found.append(f"{name}={c}")
    cnt = collections.Counter(blob[:1048576])
    top = cnt.most_common(4)
    print(f"  markers: {', '.join(found) if found else 'none'}; top bytes: {top}")
    print()
