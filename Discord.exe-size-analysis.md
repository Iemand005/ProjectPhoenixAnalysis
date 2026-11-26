# `Discord.exe` (Discord Phoenix) – size and technology analysis

Analysed file: `C:\Users\Lasse\AppData\Local\DiscordPhoenix\app\Discord.exe`
Size: **518,388,664 bytes (494.35 MiB / 518.4 MB)**
SHA-256: `f4186cf28cb5289c0e6764de11eef8f91cb205b72284050582aa29b3c0e5ca33`
Version resource: `Discord Phoenix` / `Discord.exe` / `0.1.0.2208`

## TL;DR

- **83.1% of the file (430.9 MB) is native x64 machine code plus Windows exception-unwind metadata.**
  `.rdata` is only ~15.3%; identified images/audio add ~13 MB, with another ~29 MB of opaque
  high-entropy data that is most likely packed resources.
- The binary contains about **2.03 million distinct functions**, with a median size of **62 bytes** and an
  average of **152 bytes**. That is the signature of an **unoptimised / development-profile Rust build** of
  a very large crate graph, not a packed or padded executable and not embedded debug symbols.
- It is a **Rust nightly 1.99.0** executable (commit `73dc9167f1cd099e525c9ade2e068d1907b78564`,
  2026-08-01) targeting `x86_64-pc-windows-msvc`, built from ~**1,006 Rust crates** with a vendored
  **GPUI** UI framework. Some web UI is hosted by **WebView2 / Edge** ("sunbird" profile), but this EXE
  is not an Electron/Chromium bundle.
- The PDB is external (`RSDS` → `discord-desktop.pdb`), so debug info is **not** inside this file.

## 1. Exact PE layout

PE32+ (`0x20b`), machine `0x8664`, 15 sections, GUI subsystem, image base `0x140000000`,
section alignment 4096, file alignment 512, `SizeOfImage` 519,266,304, 16 data directories.

| Section | Raw bytes | MiB | % of file | What it is |
|---|---:|---:|---:|---|
| `.text` | 321,680,384 | 306.8 | 62.05% | Executable x64 code |
| `.xdata` | 84,885,504 | 81.0 | 16.37% | Exception unwind information |
| `.rdata` | 79,268,352 | 75.6 | 15.29% | Read-only data: strings, vtables, embedded media |
| `.pdata` | 24,327,168 | 23.2 | 4.69% | Function table (`RUNTIME_FUNCTION`, 12 B each) |
| `.data` | 6,134,272 | 5.9 | 1.18% | Writable data |
| `.reloc` | 1,513,472 | 1.4 | 0.29% | Base relocations |
| `IPPCODE` / `IPPDATA` | 441,856 | 0.42 | 0.09% | Intel IPP code/constants |
| `.rsrc` | 63,488 | 0.06 | 0.01% | Win32 resources (version info, manifest, icons) |
| other small sections | 64,000 | 0.06 | 0.01% | `.tls`, `.itt_notify_table`, second `.pdata`, `_RDATA`, etc. |
| PE headers | 1,536 | — | — | DOS/PE/COFF/optional headers |
| Authenticode overlay | 10,680 | 0.01 | 0.00% | Embedded PKCS#7 signature (type 0x200) |

Sum: 518,388,664 bytes exactly. Largest three sections (`.text` + `.xdata` + `.pdata`) =
**430,893,056 bytes / 83.10%**.

## 2. Why `.text` is 307 MB

`.pdata` contains **2,027,231 valid 12-byte `RUNTIME_FUNCTION` entries**. Their start/end RVAs cover
**308,481,863 bytes (294.2 MiB)** of `.text`, i.e. essentially the whole executable section.
Function statistics:

- average function size: **152.2 bytes**
- median: **62 bytes**
- min 1 byte, max 338,065 bytes
- **1,795,532 unique unwind-info blocks** in `.xdata` (~47.3 bytes each)

There is very little padding: sampled byte frequencies in `.text` are only ~1.07% `0xCC` (INT3),
~1.22% `0x90` (NOP), ~12% zero. The bytes are dense x86-64 instructions. So this is genuine code volume,
not alignment filler or a compressed payload.

Evidence that this is a **dev / unoptimised build**:

- Sentry release string embedded in `.rdata`:
  `discord-desktop-phoenix@0.1.0-dev.20261123093910.gb71ec80b71ec8038fe99a85585c1846b05399c174fd7a4`
  (note `0.1.0-dev`).
- **1,870** `assertion failed` strings and `debug_assertions` markers — `debug_assert!` code survives
  only when debug assertions are enabled (dev profile).
- ~**25,135** `.rs` panic-location strings, **26,251** `external/+...` crate path strings and
  **21,843** `ld_desktop_src/...` source paths.
- Third-party notices list **1,006 Rust crates**. Without LTO/codegen-units=1 and with Rust generic
  monomorphisation, each crate's generic instantiations remain as separate tiny functions.
- Debug directory is CodeView `RSDS` pointing at an **external** `discord-desktop.pdb`; the EXE itself
  does not carry DWARF/PDB debug sections. The 307 MB is therefore *code*, not debug info.

A release build with `opt-level=2/3`, `lto="fat"`, `codegen-units=1`,
`debug-assertions=false`, `panic="abort"` (where possible) and stripping would be expected to remove
the large majority of this code and of the matching unwind tables. That is a build-configuration issue,
not an unavoidable property of Rust.

## 3. What is inside `.rdata` (75.6 MB)

Classified per 64 KiB block (heuristic; approximated values, exact section total is 79,268,352 bytes):

| Category | Approx. bytes | % of `.rdata` | Evidence |
|---|---:|---:|---|
| Opaque high-entropy blocks | ~28.5 MB | 36.0% | Entropy ~7.95, no zlib/zstd/LZ4 frame header at blob starts; interleaved with media |
| Pointer / vtable / type metadata tables | ~19.1 MB | 24.0% | Runs of image-base-relative 64-bit pointers |
| Mixed constants / metadata | ~10.9 MB | 13.8% | Import/IAT/TLS/load-config data, numeric tables |
| MP3 audio assets | ~7.9 MB | 10.0% | LAME3.99/3.100/Xing tags, many `FF FB`/`FF F3` frame syncs |
| Strings and localization | ~7.3 MB | 9.2% | Translations, emoji names, SVG/CSS/token tables, 223 KB Mana token JSON |
| Embedded images | ~4.8 MB | 6.0% | 285 validated PNGs (~5.14 MB) + 41 valid WebP/RIFF (~1.21 MB), GIFs, SVGs |
| Zero padding | ~0.8 MB | 1.0% | — |

The largest opaque runs are ~10 MiB (offset 346,782,208–357,267,968), ~6.25 MiB and ~4.81 MiB;
they sit between asset/string tables and contain no recognizable container magic. Most likely they are
packed/compressed resource payloads or binary model data (the binary also contains a
`video-effects-d3d11: MEDIA-505's inference kernels ...` comment and LAME MP3 blobs). They are not
executable code and not PE debug info.

`.data` (5.9 MB) is likewise mostly high-entropy/pointer data (4.46 MB opaque, 0.39 MB pointer tables).

## 4. Technology stack

**Toolchain / build**

- Rust **nightly 1.99.0**, rustc commit `73dc9167f1cd099e525c9ade2e068d1907b78564` (2026-08-01),
  from `/rustc/<hash>/library/...` panic paths.
- Target `x86_64-pc-windows-msvc` (PE32+, MSVC ABI, CodeView RSDS PDB). Import table lists 45 DLLs
  including `KERNEL32.dll`, `user32.dll`, `d3d11.dll`, `d3d12.dll`, `dxgi.dll`, `dcomp.dll`,
  `dwrite.dll`, `d3dcompiler_47.dll`, `icuuc.dll`, `mmdevapi.dll`, `webauthn.dll`, `winhttp.dll`.
- Cargo workspace with ~**1,006 crates**; source roots include
  `ld_desktop_src/misc/incubator/libdiscord/...`, `external/+desktop_crates+...`,
  `discord-desktop-user-settings`, `discord-desktop-features-ui`, `ops-guild-space`,
  `media-sidecar`, `discord-desktop-shared`, and vendored `gpui-pre`.

**UI / rendering**

- **GPUI** (vendored `gpui-pre`, Zed-style immediate-mode Rust UI), with `gpui-kit`-derived
  `gpui-wry`/`gpui-fps` mentioned in the notices for the macOS web view host and FPS HUD.
- Native Windows GPU/media path: DirectX 11/12, DXGI/DComposition, D3D11 inference kernels,
  DirectWrite + FreeType text rendering, system ICU (`icuuc.dll`), Intel IPP (`IPPCODE`, `IPPDATA`
  sections), `symphonia` audio decoding.
- **WebView2 / Edge** for embedded web surfaces: the user-data dir contains
  `sunbird/app-ui` with Edge/Crashpad/Dawn-WebGPU/Code-Cache/WASM profile files. The EXE itself does
  not contain an Electron or Chromium payload (no Electron/node resource bundle, no Chrome `.pak`),
  so it relies on the system WebView2 runtime for those surfaces.
- `image`, `png`, `resvg`, WebP, SVG and LAME MP3 assets are compiled into the binary.

**Services / platform crates (from `ThirdPartyNotices.html`)**

- `tokio 1.54.1`, `hyper 1.12.0`, `rustls 0.23.46`, `serde 1.0.229`, `rusqlite 0.40.2` (SQLite),
  `sentry 0.49.5`, `zstd 0.14.3`, `symphonia 0.5.5`, `rustix`, `notify-rust`,
  `windows` 0.58/0.61/0.62, multiple Unicode crates, FreeType.
- Sentry ingest: `https://...@o64374.ingest.us.sentry.io/4512273212899328`, plus an internal
  `https://phoenix-errmon.vibeyard.tools/v1/batch` endpoint.
- Companion files: `discord_media.exe` (58.7 MB), `Discord Phoenix Crash Handler.exe`,
  Krisp noise/VAD models as separate `.kef` files, `DiscordHook64.dll`, `video-codec-probe.exe`.

## 5. Bottom line

The 500 MB is **not** mostly assets, packing, or debug symbols. It is a dev-profile Rust build whose
~1,006-crate dependency graph and generic monomorphisation produced ~2 million tiny functions, and
Windows x64 exception handling stores ~47 bytes of unwind data for nearly every one of them. Code +
unwind tables alone are 83.1% of the file. Embedded media/compressed resources add roughly 15–20 MB.
The only "fix" is build configuration and optional resource externalisation; the runtime technology
(Rust/GPUI/WebView2/tokio/rustls/SQLite/etc.) is not itself the cause.

## Method and limitations

- PE headers, sections, resource/debug/certificate directories parsed directly with a small Python
  `mmap` parser (`pe_inspect.py`); all sizes are exact byte counts from the file.
- Entropy/content classification uses 64 KiB blocks (`classify3.py`) and sampled 1 MiB blocks; those
  category numbers are estimates, with the section totals exact.
- Embedded image counts use signature + header validation (`deep_analysis.py`), so random byte
  matches are excluded; many raw magic hits (e.g. `\x00\x01\x00\x00`, `\x00asm`, zstd) were verified
  to be false positives inside code or syntax-highlighting strings.
- The external PDB was not available in the install directory, so no per-symbol attribution of `.text`
  to individual crates was possible; crate attribution comes from embedded panic/source path strings.
- Supporting scripts and raw outputs are in this directory: `pe_inspect.py`, `pe_report.json`,
  `analyze_sections.py`, `content_report.txt`, `deep_analysis.py`, `deep_report.txt`,
  `entropy_map.py`, `entropy_report.txt`, `classify3.py`, `blob_context.py`, `blob_report.txt`,
  `hexdump.py`.
