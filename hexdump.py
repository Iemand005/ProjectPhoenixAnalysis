import mmap
import sys
from pathlib import Path

p = Path(sys.argv[1])
f = p.open("rb")
d = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

for off in [int(x, 0) for x in sys.argv[2:]]:
    start = max(0, off - 64)
    end = min(len(d), off + 256)
    chunk = d[start:end]
    print(f"--- offset {off:,} (hex {off:x}) ---")
    for i in range(0, len(chunk), 16):
        b = chunk[i:i + 16]
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
        print(f"{start + i:09x}  {b.hex(' '):<48s}  {asc}")
    print()
