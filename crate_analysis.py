import collections
import math
import mmap
import re
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
    secs[n] = (rp, rs, va, vs)
rp, rs, _, _ = secs[".rdata"]
blob = d[rp:rp + rs]

print("=== .RDATA 4MiB BLOCK PROFILE ===", flush=True)
print("offset            entropy zero% printable% ptrlike% top_byte", flush=True)
for i in range(0, rs, 4 * 1048576):
    c = blob[i:i + min(4 * 1048576, rs - i)]
    if len(c) < 1024:
        break
    counts = collections.Counter(c)
    ent = -sum((n / len(c)) * math.log2(n / len(c)) for n in counts.values())
    zero = 100 * c.count(0) / len(c)
    pr = 100 * sum(32 <= b < 127 or b in (9, 10, 13) for b in c) / len(c)
    qw = [struct.unpack_from("<Q", c, j)[0] for j in range(0, len(c) - 7, 8)]
    ptr = 100 * sum(0x140000000 <= x < 0x141f000000 for x in qw) / len(qw)
    top, topn = counts.most_common(1)[0]
    print(f"{rp+i:>12,}  {ent:5.2f}  {zero:5.1f}  {pr:6.1f}  {ptr:6.1f}  "
          f"0x{top:02x}({100*topn/len(c):.1f}%)", flush=True)
print(flush=True)

print("=== CRATE PATH FREQUENCIES FROM PANIC/LOCATION STRINGS ===", flush=True)
pat = re.compile(rb"(?:external/\+|ld_desktop_crates__|/rustc/[0-9a-f]+/library/|library\\)?"
                 rb"([A-Za-z0-9_\-+.]+(?:/[A-Za-z0-9_\-+.]+)*?)/(?:src|library)/[A-Za-z0-9_\-+./\\]+\.rs")
cnt = collections.Counter()
total = 0
for m in pat.finditer(blob):
    total += 1
    path = m.group(0).decode("utf-8", "replace")
    cnt[path.split("/src/")[0].split("/library/")[0]] += 1
print(f"matched .rs location strings: {total:,}, unique prefixes: {len(cnt):,}")
for k, v in cnt.most_common(60):
    print(f"{v:>7,}  {k[:160]}")
print(flush=True)

print("=== EXTERNAL CRATE PREFIXES ===", flush=True)
c2 = collections.Counter()
for m in re.finditer(rb"external/\+([A-Za-z0-9_\-+.]+)", blob):
    c2[m.group(1).decode()] += 1
print(f"unique external crates: {len(c2):,} total refs={sum(c2.values()):,}")
for k, v in c2.most_common(60):
    print(f"{v:>7,}  {k[:120]}")
print(flush=True)

print("=== SHADER / CONTAINER SIGNATURES ===", flush=True)
sigs = [(b"DXBC", b"DXBC"), (b"DXIL", b"DXIL"), (b"SPIRV", b"\x03\x02#\x07"),
        (b"WASM-v1", b"\x00asm\x01\x00\x00\x00"), (b"HLSL", b"HLSL"), (b"fxc", b"fxc"),
        (b"ONNX", b"ONNX"), (b"GGUF", b"GGUF"), (b"Krisp", b"krisp")]
for label, sig in sigs:
    c = 0
    st = 0
    while True:
        i = blob.find(sig, st)
        if i < 0:
            break
        c += 1
        st = i + 1
    print(f"{label:10s} {c:,}")
