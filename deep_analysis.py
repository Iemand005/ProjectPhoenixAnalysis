import collections
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
    secs.setdefault(n, []).append((rp, rs, va, vs))

def region(name, index=0):
    rp, rs, va, vs = secs[name][index]
    return rp, rs, va, vs

def fmt(n):
    return f"{n:,} ({n/1048576:.2f} MiB)"

text_ptr, text_size, text_va, _ = region(".text")
pdata_ptr, pdata_size, _, _ = region(".pdata")
xdata_ptr, xdata_size, _, _ = region(".xdata")
rdata_ptr, rdata_size, _, _ = region(".rdata")

print("=== UNWIND / FUNCTION TABLES ===", flush=True)
nfunc = pdata_size // 12
starts = []
sizes = []
unks = []
for o in range(pdata_ptr, pdata_ptr + pdata_size - 11, 12):
    a, b, c = struct.unpack_from("<III", d, o)
    if b > a and b - a < 0x10000000:
        starts.append(a)
        sizes.append(b - a)
        unks.append(c)
print(f".pdata raw={fmt(pdata_size)} entries(12B)={nfunc:,} valid={len(starts):,}")
if sizes:
    print(f"function code bytes covered={fmt(sum(sizes))} avg={sum(sizes)/len(sizes):.1f}B "
          f"min={min(sizes)} max={max(sizes)} median={sorted(sizes)[len(sizes)//2]}")
    print(f"unique unwind info RVAs={len(set(unks)):,} .xdata={fmt(xdata_size)} "
          f"avg .xdata per unique unwind={xdata_size/max(1,len(set(unks))):.1f}B")
print(flush=True)

print("=== .TEXT PADDING / CONTENT (8 x 1MiB samples) ===", flush=True)
cnt = collections.Counter()
for i in range(8):
    o = text_ptr + int((text_size - 1048576) * i / 7)
    c = d[o:o + 1048576]
    cnt["CC"] += c.count(b"\xcc")
    cnt["90"] += c.count(b"\x90")
    cnt["00"] += c.count(b"\x00")
    cnt["C3"] += c.count(b"\xc3")
    cnt["total"] += len(c)
for k in ("CC", "90", "00", "C3"):
    print(f"{k}: {cnt[k]:,} ({100*cnt[k]/cnt['total']:.2f}% of sampled bytes)")
print(flush=True)

print("=== .RDATA STRING / ASSET STATS ===", flush=True)
for needle in [b"/rustc/", b"external/+", b"panicked at", b"assertion failed",
               b"ld_desktop_src", b"library\\", b".rs\x00", b"serde", b"GPUI",
               b"gpui", b"deno", b"v8", b"skia"]:
    c = 0
    st = rdata_ptr
    end = rdata_ptr + rdata_size
    while True:
        i = d.find(needle, st, end)
        if i < 0:
            break
        c += 1
        st = i + 1
    print(f"{needle.decode('utf-8','replace'):20s} {c:>8,}")
print(flush=True)

print("=== LONGEST PRINTABLE RUNS IN .RDATA ===", flush=True)
runs = []
i = rdata_ptr
end = rdata_ptr + rdata_size
cur = i
while i < end:
    b = d[i]
    if 32 <= b < 127 or b in (9, 10, 13):
        i += 1
    else:
        if i - cur >= 512:
            runs.append((i - cur, cur))
        cur = i + 1
        i += 1
runs.sort(reverse=True)
print(f"runs>=512B: {len(runs):,} total bytes={fmt(sum(n for n,_ in runs))}")
for n, off in runs[:15]:
    s = d[off:off + 100].decode("utf-8", "replace")
    print(f"  {fmt(n):>20s} @ {off:,} starts {s!r}")
print(flush=True)

print("=== VALIDATED EMBEDDED IMAGES ===", flush=True)
def find_all(sig, lo, hi, cap=100000):
    out, st = [], lo
    while len(out) < cap:
        i = d.find(sig, st, hi)
        if i < 0:
            break
        out.append(i)
        st = i + 1
    return out

pngs = []
for off in find_all(b"\x89PNG\r\n\x1a\n", 0, size):
    if off + 33 > size:
        continue
    ln, typ = struct.unpack_from(">I4s", d, off + 8)
    if typ != b"IHDR" or not (8 <= ln <= 256):
        continue
    w, h = struct.unpack_from(">II", d, off + 16)
    if not (0 < w < 20000 and 0 < h < 20000):
        continue
    iend = d.find(b"\x00\x00\x00\x00IEND\xaeB`\x82", off + 8, min(off + 200_000_000, size))
    if iend < 0:
        continue
    pngs.append((off, iend + 12 - off, w, h))
print(f"valid PNG: {len(pngs):,} total={fmt(sum(x[1] for x in pngs))}")
for x in pngs[:10]:
    print(f"  off={x[0]:,} bytes={fmt(x[1])} dims={x[2]}x{x[3]}")
print(flush=True)

webps = []
for off in find_all(b"RIFF", 0, size):
    if off + 16 > size or d[off + 8:off + 12] != b"WEBP":
        continue
    ln = struct.unpack_from("<I", d, off + 4)[0]
    total = ln + 8
    if not (100 < total < 200_000_000):
        continue
    if d[off + 12:off + 16] not in (b"VP8 ", b"VP8L", b"VP8X"):
        continue
    webps.append((off, total))
print(f"valid WEBP/RIFF: {len(webps):,} total={fmt(sum(x[1] for x in webps))}")
for x in webps[:10]:
    print(f"  off={x[0]:,} bytes={fmt(x[1])}")
print(flush=True)
