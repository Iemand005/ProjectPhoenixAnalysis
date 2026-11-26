import json
import mmap
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
f = path.open("rb")
data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
size = len(data)

def u16(off): return struct.unpack_from("<H", data, off)[0]
def u32(off): return struct.unpack_from("<I", data, off)[0]
def u64(off): return struct.unpack_from("<Q", data, off)[0]

def cstr(off, limit=256):
    end = data.find(b"\0", off, min(off + limit, size))
    if end < 0:
        end = min(off + limit, size)
    return data[off:end].decode("utf-8", "replace")

pe_off = u32(0x3C)
assert data[pe_off:pe_off + 4] == b"PE\0\0", "not a PE file"
coff = pe_off + 4
machine, nsections, timestamp, symptr, nsyms, optsize, chars = struct.unpack_from("<HHIIIHH", data, coff)
opt = coff + 20
magic = u16(opt)
is64 = magic == 0x20B

if is64:
    imagebase = u64(opt + 24)
    section_align = u32(opt + 32)
    file_align = u32(opt + 36)
    osver = struct.unpack_from("<HH", data, opt + 40)
    imgver = struct.unpack_from("<HH", data, opt + 44)
    subver = struct.unpack_from("<HH", data, opt + 48)
    win32ver = u32(opt + 52)
    imagesize = u32(opt + 56)
    headersize = u32(opt + 60)
    checksum = u32(opt + 64)
    subsystem = u16(opt + 68)
    dllchars = u16(opt + 70)
    stackres, stackcomm = u64(opt + 72), u64(opt + 80)
    heapres, heapcomm = u64(opt + 88), u64(opt + 96)
    loaderflags = u32(opt + 104)
    nrva = u32(opt + 108)
    ddoff = opt + 112
else:
    imagebase = u32(opt + 28)
    section_align = u32(opt + 32)
    file_align = u32(opt + 36)
    osver = struct.unpack_from("<HH", data, opt + 40)
    imgver = struct.unpack_from("<HH", data, opt + 44)
    subver = struct.unpack_from("<HH", data, opt + 48)
    win32ver = u32(opt + 52)
    imagesize = u32(opt + 56)
    headersize = u32(opt + 60)
    checksum = u32(opt + 64)
    subsystem = u16(opt + 68)
    dllchars = u16(opt + 70)
    stackres, stackcomm = u32(opt + 72), u32(opt + 76)
    heapres, heapcomm = u32(opt + 80), u32(opt + 84)
    loaderflags = u32(opt + 88)
    nrva = u32(opt + 92)
    ddoff = opt + 96

ddnames = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG",
           "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT",
           "DELAY_IMPORT", "COM_DESCRIPTOR", "CLR_HEADER", "RESERVED"]
dirs = []
for i in range(min(nrva, 16)):
    rva, sz = struct.unpack_from("<II", data, ddoff + 8 * i)
    dirs.append({"name": ddnames[i] if i < len(ddnames) else str(i), "rva": rva, "size": sz})

sections = []
sec_off = opt + optsize
for i in range(nsections):
    o = sec_off + 40 * i
    name = data[o:o + 8].rstrip(b"\0").decode("utf-8", "replace")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
    relptr, linenum, nrel, nline, sc = struct.unpack_from("<IIHHI", data, o + 24)
    sections.append({"name": name, "vsize": vsize, "va": va, "rawsize": rawsize,
                     "rawptr": rawptr, "chars": hex(sc), "relocations": nrel})

def rva_to_off(rva):
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            return s["rawptr"] + rva - s["va"]
    return None

maxend = max((s["rawptr"] + s["rawsize"] for s in sections), default=0)
overlay = size - maxend

# Resource tree walk
resource_entries = []
res_dir_rva = dirs[2]["rva"] if len(dirs) > 2 else 0
def walk_resources(off, base, depth, path):
    if off is None or off >= size:
        return
    named, ids = struct.unpack_from("<HH", data, off)
    count = named + ids
    for i in range(count):
        e = off + 16 + 8 * i
        nameval, target = struct.unpack_from("<II", data, e)
        if nameval & 0x80000000:
            noff = base + (nameval & 0x7FFFFFFF)
            nlen = u16(noff)
            label = data[noff + 2:noff + 2 + 2 * nlen].decode("utf-16le", "replace")
        else:
            label = str(nameval)
        if target & 0x80000000:
            sub = base + (target & 0x7FFFFFFF)
            walk_resources(sub, base, depth + 1, path + [label])
        else:
            doff = base + target
            if doff + 16 <= size:
                rva, sz, codepage, reserved = struct.unpack_from("<IIII", data, doff)
                foff = rva_to_off(rva)
                resource_entries.append({"path": path + [label], "rva": rva, "offset": foff, "size": sz})

if res_dir_rva:
    walk_resources(rva_to_off(res_dir_rva), rva_to_off(res_dir_rva), 0, [])

# Debug directory
debug_entries = []
if len(dirs) > 6 and dirs[6]["rva"]:
    d = rva_to_off(dirs[6]["rva"])
    dsize = dirs[6]["size"]
    for o in range(d, min(d + dsize, size - 28), 28):
        typ, stamp, maj, minor, dtype, dobj, doff, dsize2 = struct.unpack_from("<IIHHIIII", data, o)
        entry = {"type": typ, "timestamp": stamp, "version": f"{maj}.{minor}", "size": dsize2}
        if typ == 2 and doff and dsize2:
            blob = data[doff:doff + min(dsize2, 4096)]
            entry["data"] = blob.split(b"\0")[0].decode("utf-8", "replace")
        elif typ == 16:
            entry["data"] = data[doff:doff + dsize2].hex() if dsize2 and doff else None
        debug_entries.append(entry)

# Certificate table
certs = []
if len(dirs) > 4 and dirs[4]["rva"]:
    o = dirs[4]["rva"]
    end = o + dirs[4]["size"]
    while o + 8 <= min(end, size):
        clen, ctype, crev = struct.unpack_from("<IHH", data, o)
        if clen < 8 or o + clen > size:
            break
        certs.append({"offset": o, "length": clen, "type": ctype, "revision": crev})
        o += (clen + 7) & ~7

out = {
    "path": str(path), "size": size, "pe_offset": pe_off, "machine": hex(machine),
    "sections_count": nsections, "timestamp": timestamp, "symbol_table": {"ptr": symptr, "count": nsyms},
    "optional_header": {"magic": hex(magic), "imagebase": hex(imagebase), "section_align": section_align,
                        "file_align": file_align, "osver": osver, "imgver": imgver, "subver": subver,
                        "imagesize": imagesize, "headersize": headersize, "checksum": hex(checksum),
                        "subsystem": subsystem, "dllchars": hex(dllchars), "stack": [stackres, stackcomm],
                        "heap": [heapres, heapcomm], "nrva": nrva},
    "directories": dirs, "sections": sections, "overlay": {"start": maxend, "size": overlay},
    "resources": {"count": len(resource_entries), "total_size": sum(e["size"] for e in resource_entries),
                  "entries": resource_entries},
    "debug": debug_entries, "certificates": certs,
}
print(json.dumps(out, indent=2))
