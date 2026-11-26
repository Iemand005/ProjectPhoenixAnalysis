import collections
import itertools
import math
import mmap
import re
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
f = path.open("rb")
data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
size = len(data)

pe_off = struct.unpack_from("<I", data, 0x3C)[0]
coff = pe_off + 4
nsections = struct.unpack_from("<H", data, coff + 2)[0]
optsize = struct.unpack_from("<H", data, coff + 16)[0]
sec_off = coff + 20 + optsize
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
    return "OVERLAY" if off >= sections[-1][1] + sections[-1][2] else "HEADERS"

def fmt(n):
    return f"{n:>12,d} ({n / 1048576:7.1f} MiB)"

CHUNK = 262144
samples = {}
print("=== SECTION CONTENT PROFILE (sampled) ===", flush=True)
for name, ptr, rsize, va, vsize in sections:
    positions = [ptr + int((rsize - 1) * i / 8) for i in range(8)] if rsize else []
    chunks = []
    for p in positions:
        if p + CHUNK <= size:
            chunks.append(data[p:p + CHUNK])
    samples[name] = b"".join(chunks)
    entropies, zero_ratios, printable = [], [], []
    for c in chunks:
        counts = collections.Counter(c)
        entropies.append(-sum((n / len(c)) * math.log2(n / len(c)) for n in counts.values()))
        zero_ratios.append(c.count(0) / len(c))
        printable.append(sum(32 <= b < 127 or b in (9, 10, 13) for b in c) / len(c))
    head = data[ptr:ptr + 32].hex()
    print(f"{name:10s} raw={fmt(rsize)} entropy={sum(entropies)/len(entropies):.2f} "
          f"zero={100*sum(zero_ratios)/len(zero_ratios):.1f}% "
          f"printable={100*sum(printable)/len(printable):.1f}% head={head}", flush=True)
print(flush=True)

print("=== MAGIC SIGNATURE HITS (full-file scan, capped) ===", flush=True)
sigs = [
    ("PNG", b"\x89PNG\r\n\x1a\n"), ("JPEG", b"\xff\xd8\xff"), ("GIF", b"GIF89a"),
    ("RIFF", b"RIFF"), ("WEBP", b"WEBP"), ("WAVE", b"WAVE"), ("BMP", b"BM\x06\x00\x00\x00"),
    ("TrueType", b"\x00\x01\x00\x00"), ("OTF", b"OTTO"), ("WOFF", b"wOFF"), ("WOFF2", b"wOF2"),
    ("TTC", b"ttcf"), ("ZIP", b"PK\x03\x04"), ("ZIP-end", b"PK\x05\x06"),
    ("GZIP", b"\x1f\x8b\x08"), ("BZIP2", b"BZh"), ("XZ", b"\xfd7zXZ\x00"),
    ("ZSTD", b"\x28\xb5\x2f\xfd"), ("LZ4", b"\x04\x22\x4d\x18"), ("7ZIP", b"7z\xbc\xaf\x27\x1c"),
    ("OGG", b"OggS"), ("FLAC", b"fLaC"), ("MP3", b"ID3"), ("MP4", b"ftyp"),
    ("ELF", b"\x7fELF"), ("SQLITE", b"SQLite format 3\x00"), ("WASM", b"\x00asm"),
    ("CAB", b"MSCF\x00\x00\x00\x00"), ("OLE", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("XML", b"<?xml"), ("HTML", b"<!DOCTYPE html"), ("RUST-PANIC", b"panicked at"),
    ("RUST-PATH", b"/rustc/"), ("CARGO-REG", b"registry/src/"), ("PDB-PATH", b".pdb"),
    ("GITHUB", b"github.com/"), ("NODE-MODULES", b"node_modules"),
]
for label, sig in sigs:
    hits, start = [], 0
    while len(hits) < 2000:
        i = data.find(sig, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    if hits:
        by = collections.Counter(which_section(x) for x in hits)
        print(f"{label:12s} count={len(hits):>5d}+ by_section={dict(by)} first={hits[:3]}", flush=True)
print(flush=True)

print("=== TECH KEYWORDS IN SAMPLED BYTES ===", flush=True)
blob = b"".join(samples.values()).lower()
keywords = [
    "rustc", "rust_begin_unwind", "core::panicking", "std::panicking", "alloc::", "cargo",
    "rustls", "tokio", "hyper", "reqwest", "serde", "clap", "tracing", "skia", "icu_",
    "icu4c", "unicode_", "harfbuzz", "freetype", "dwrite", "directwrite", "wgpu", "vulkan",
    "d3d12", "angle", "swiftshader", "opengl", "directx", "tauri", "webview", "webview2",
    "chromium", "electron", "nodejs", "napi", "v8::", "deno", "javascript", "wasmtime",
    "qljs", "boa_engine", "egui", "iced", "winit", "glutin", "leptos", "dioxus", "slint",
    "onnx", "tract", "candle", "llama", "krisp", "symphonia", "opus", "vpx", "dav1d",
    "ffmpeg", "libav", "crashpad", "sentry", "backtrace", "addr2line", "gimli", "rusqlite",
    "sqlx", "sqlite", "websocket", "quinn", "brotli", "flate2", "zstd", "miniz_oxide",
    "windows-sys", "winapi", "mio", "parking_lot", "rayon", "discord", "phoenix",
    "protobuf", "prost", "flatbuffers", "msgpack", "libstd-", "compiler_builtins",
]
for kw in keywords:
    c = blob.count(kw.encode())
    if c:
        print(f"{kw:22s} {c:>6d}", flush=True)
print(flush=True)

print("=== PATH / SOURCE STRING SAMPLES (sampled bytes) ===", flush=True)
patterns = [rb"[A-Za-z0-9_\-.\\/]+[/\\]src[/\\][A-Za-z0-9_\-.\\/]+\.rs",
            rb"[A-Za-z0-9_\-.\\/]+\.rs", rb"[A-Za-z]:[/\\][A-Za-z0-9_\-.\\/ ]+",
            rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+"]
textblob = samples[".rdata"] + samples[".text"]
for pat in patterns:
    found = collections.Counter()
    for m in itertools.islice(re.finditer(pat, textblob, re.I), 20000):
        s = textblob[m.start():m.end()].decode("utf-8", "replace")
        found[s] += 1
    print(f"pattern {pat.decode()[:40]!r}: unique={len(found)} total={sum(found.values())}", flush=True)
    for s, c in found.most_common(25):
        print(f"   {c:>5d}  {s[:180]}", flush=True)
    print(flush=True)
