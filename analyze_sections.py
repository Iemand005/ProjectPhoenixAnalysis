import collections
import math
import re
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
f = path.open("rb")
import mmap
data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
size = len(data)

pe_off = struct.unpack_from("<I", data, 0x3C)[0]
coff = pe_off + 4
nsections = struct.unpack_from("<H", data, coff + 2)[0]
optsize = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20
sec_off = opt + optsize
sections = []
for i in range(nsections):
    o = sec_off + 40 * i
    name = data[o:o + 8].rstrip(b"\0").decode("utf-8", "replace")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
    sections.append((name, rawptr, rawsize, va, vsize))

def which_section(off):
    for name, ptr, rsize, va, vsize in sections:
        if ptr <= off < ptr + rsize:
            return name
    if off >= sections[-1][1] + sections[-1][2]:
        return "OVERLAY"
    return "HEADERS"

def fmt(n):
    return f"{n:,} ({n / 1048576:.1f} MiB)"

print("=== SECTION CONTENT PROFILE ===")
for name, ptr, rsize, va, vsize in sections:
    step = max(1, rsize // 8 // 65536)
    sample_size = min(65536, rsize)
    entropies = []
    zeros = 0
    sampled = 0
    for o in range(ptr, ptr + rsize, max(1, rsize // 8)):
        chunk = data[o:o + sample_size]
        if not chunk:
            continue
        counts = collections.Counter(chunk)
        ent = -sum((c / len(chunk)) * math.log2(c / len(chunk)) for c in counts.values())
        entropies.append(ent)
        zeros += chunk.count(0)
        sampled += len(chunk)
    avg_ent = sum(entropies) / len(entropies) if entropies else 0
    head = data[ptr:ptr + 48]
    print(f"{name:10s} raw={fmt(rsize):>24s} entropy~{avg_ent:.2f} zero%={100*zeros/max(1,sampled):5.1f} head={head[:32].hex()}")
print()

print("=== MAGIC SIGNATURE HITS ===")
sigs = [
    ("PNG", b"\x89PNG\r\n\x1a\n"), ("JPEG", b"\xff\xd8\xff\xe0"), ("JPEG2", b"\xff\xd8\xff\xdb"),
    ("GIF", b"GIF89a"), ("RIFF", b"RIFF"), ("WEBP", b"WEBP"), ("WAVE", b"WAVE"),
    ("BMP", b"BM\x00\x00\x00\x00"), ("ICO", b"\x00\x00\x01\x00"),
    ("TrueType", b"\x00\x01\x00\x00"), ("OTF", b"OTTO"), ("WOFF", b"wOFF"), ("WOFF2", b"wOF2"),
    ("TTC", b"ttcf"), ("ZIP", b"PK\x03\x04"), ("ZIP-end", b"PK\x05\x06"),
    ("GZIP", b"\x1f\x8b\x08"), ("BZIP2", b"BZh"), ("XZ", b"\xfd7zXZ\x00"),
    ("ZSTD", b"\x28\xb5\x2f\xfd"), ("LZ4", b"\x04\x22\x4d\x18"), ("7ZIP", b"7z\xbc\xaf\x27\x1c"),
    ("OGG", b"OggS"), ("FLAC", b"fLaC"), ("MP3", b"ID3"), ("MP4", b"ftyp"),
    ("ELF", b"\x7fELF"), ("MACHO", b"\xcf\xfa\xed\xfe"), ("SQLITE", b"SQLite format 3\x00"),
    ("WASM", b"\x00asm"), ("CAB", b"MSCF\x00\x00\x00\x00"), ("OLE", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("XML", b"<?xml"), ("HTML", b"<!DOCTYPE html"), ("JSON", b"{\"version\":"),
    ("RUST-PANIC", b"panicked at"), ("RUST-PATH", b"/rustc/"), ("CARGO-REG", b"registry/src/"),
    ("PDB-PATH", b".pdb"), ("GIT-URL", b"github.com/"), ("NPM", b"node_modules"),
]
for label, sig in sigs:
    hits = []
    start = 0
    while len(hits) < 4000:
        i = data.find(sig, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    if hits:
        c = collections.Counter(which_section(x) for x in hits)
        print(f"{label:12s} count={len(hits):>6d} by_section={dict(c)} first_offsets={hits[:5]}")
print()

print("=== TECH KEYWORD COUNTS (ASCII, case-insensitive) ===")
keywords = [
    "rustc", "rust_begin_unwind", "core::panicking", "std::panicking", "alloc::", "cargo",
    "rustls", "ring::", "tokio", "hyper", "reqwest", "serde", "serde_json", "clap", "tracing",
    "skia", "icu_", "icu4c", "unicode_", "harfbuzz", "freetype", "fontconfig", "dwrite", "directwrite",
    "wgpu", "gfx-", "vulkan", "d3d12", "metal", "angle", "swiftshader", "opengl", "directx",
    "tauri", "webview", "webview2", "edgehtml", "chromium", "electron", "nodejs", "node_", "napi",
    "v8::", "v8_", "deno", "javascript", "wasmtime", "wasmer", "qljs", "boa_engine", "hermes",
    "egui", "iced", "winit", "glutin", "raw_window_handle", "leptos", "dioxus", "slint", "gtk",
    "onnx", "tract", "candle", "burn", "llama", "krisp", "symphonia", "opus", "vpx", "dav1d",
    "ffmpeg", "libav", "crashpad", "sentry", "backtrace", "addr2line", "gimli", "object::",
    "rusqlite", "sqlx", "sqlite", "websocket", "quinn", "hpack", "brotli", "flate2", "zstd",
    "miniz_oxide", "systeminformation", "windows-sys", "winapi", "mio", "parking_lot", "rayon",
    "discord", "phoenix", "applyzer", "applyzer", "protobuf", "prost", "flatbuffers", "msgpack",
]
for kw in keywords:
    needle = kw.lower().encode()
    count = 0
    first = None
    start = 0
    while True:
        i = data.lower().find(needle, start)
        if i < 0:
            break
        count += 1
        if first is None:
            first = i
        if count >= 20000:
            break
        start = i + 1
    if count:
        print(f"{kw:22s} count>={count:>6d} first={first} section={which_section(first) if first is not None else '-'}")
print()

print("=== SOURCE-FILE / PATH SAMPLES ===")
patterns = [rb"[A-Za-z0-9_\-.\\/]+[/\\]src[/\\][A-Za-z0-9_\-.\\/]+\.rs",
            rb"[A-Za-z0-9_\-.\\/]+\.rs", rb"[A-Za-z]:[/\\][A-Za-z0-9_\-.\\/ ]+",
            rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+"]
import itertools
for pat in patterns:
    found = collections.Counter()
    for m in itertools.islice(re.finditer(pat, data, re.I), 200000):
        s = data[m.start():m.end()].decode("utf-8", "replace")
        found[s] += 1
    print(f"pattern {pat.decode()[:40]!r}: unique={len(found)} total={sum(found.values())}")
    for s, c in found.most_common(30):
        print(f"   {c:>5d}  {s[:200]}")
    print()
