#!/usr/bin/env python3
"""synthpe - merge a memory-dumped PE image and its anonymous regions into a
single, statically analysable PE.

Packers such as Themida/WinLicense move (a part of) the program into anonymous
executable regions that only exist at runtime.  A dump of the module therefore
references code which is not part of the image, so static tools cannot follow
it.  This tool appends every dumped region to the image as an extra section and
rewrites every pointer that pointed into a region, keeping the layout
self-consistent.

Region files are expected to be named "<start>_<end>_<perms>.bin" with
hexadecimal addresses (e.g. "6ffff8f51000_6ffff8fa5000_r-xp.bin").

Example:
    synthpe.py --image dump/image.bin --regions dump --out synth.dll --map map.txt
"""

import argparse
import glob
import os
import struct
import sys

try:
    import numpy as __np          # optional accelerator
except Exception:                 # pragma: no cover
    __np = None


def align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def parse_regions(directories):
    """Collect (start, end, path), later directories fill the gaps only."""
    found = []
    for directory in directories:
        for path in sorted(glob.glob(os.path.join(directory, "*.bin"))):
            name = os.path.basename(path).split("_")
            if len(name) < 2:
                continue
            try:
                start, end = int(name[0], 16), int(name[1], 16)
            except ValueError:
                continue
            if end <= start:
                continue
            found.append((start, end, path))

    # keep the first region covering a given address, drop heavy overlaps
    accepted = []
    for start, end, path in sorted(found, key=lambda r: (r[0], -(r[1] - r[0]))):
        if any(start < a_end and a_start < end for a_start, a_end, _ in accepted):
            continue
        accepted.append((start, end, path))
    return accepted


def pe_layout(data):
    if data[:2] != b"MZ":
        raise SystemExit("image.bin does not start with MZ")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("image.bin has no PE signature")
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise SystemExit("only PE32+ images are supported")
    section_alignment = struct.unpack_from("<I", data, opt + 32)[0]
    file_alignment = struct.unpack_from("<I", data, opt + 36)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    return {
        "e_lfanew": e_lfanew, "coff": coff, "nsec": nsec, "opt": opt,
        "opt_size": opt_size, "sa": section_alignment, "fa": file_alignment,
        "soi": size_of_image, "soh": size_of_headers,
    }


def build_index(regions, base, new_rvas):
    """page -> (old_start, old_end, new_start) for O(1) containment tests."""
    index = {}
    for (start, end, _), rva in zip(regions, new_rvas):
        new_start = base + rva
        for page in range(start >> 12, ((end - 1) >> 12) + 1):
            index[page] = (start, end, new_start)
    return index


def remap_with_numpy(buffer, index, lo, hi):
    if not index:
        return buffer, 0
    starts = __np.array(sorted({v[0] for v in index.values()}), dtype=__np.uint64)
    ends = __np.array(sorted({v[1] for v in index.values()}), dtype=__np.uint64)
    news = __np.array([index[(s >> 12)][2] for s in starts], dtype=__np.uint64)

    out = bytearray(buffer)
    view = __np.frombuffer(out, dtype=__np.uint8)
    patched = 0
    for offset in range(8):
        usable = (len(out) - offset) // 8 * 8
        if usable <= 0:
            continue
        words = __np.frombuffer(out, dtype="<u8", count=usable // 8, offset=offset).copy()
        mask = (words >= lo) & (words < hi)
        if not mask.any():
            continue
        values = words[mask]
        positions = __np.nonzero(mask)[0] * 8 + offset
        slot = __np.searchsorted(starts, values, side="right") - 1
        valid = slot >= 0
        slot_clipped = __np.where(valid, slot, 0)
        inside = valid & (values < ends[slot_clipped])
        if not inside.any():
            continue
        new_values = news[slot_clipped[inside]] + (values[inside] - starts[slot_clipped[inside]])
        raw = new_values.astype("<u8").tobytes()
        for pos, chunk in zip(positions[inside].tolist(), [raw[i:i + 8] for i in range(0, len(raw), 8)]):
            out[pos:pos + 8] = chunk
        patched += int(inside.sum())
    del view
    return bytes(out), patched


def remap_python(buffer, index, lo, hi):
    out = bytearray(buffer)
    patched = 0
    for offset in range(8):
        for pos in range(offset, len(out) - 7, 8):
            value = struct.unpack_from("<Q", out, pos)[0]
            if not (lo <= value < hi):
                continue
            entry = index.get(value >> 12)
            if entry is None or not (entry[0] <= value < entry[1]):
                continue
            struct.pack_into("<Q", out, pos, entry[2] + (value - entry[0]))
            patched += 1
    return bytes(out), patched


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True, help="memory image of the module (PE)")
    ap.add_argument("--regions", action="append", default=[], metavar="DIR",
                    help="directory with <start>_<end>_<perms>.bin regions (repeatable, earlier wins)")
    ap.add_argument("--out", required=True, help="output PE")
    ap.add_argument("--map", help="write the old -> new address map here")
    ap.add_argument("--section", default=".regions", help="name of the new section")
    ap.add_argument("--no-remap", action="store_true", help="do not rewrite pointers")
    args = ap.parse_args()

    image = open(args.image, "rb").read()
    layout = pe_layout(image)
    base = struct.unpack_from("<Q", image, layout["opt"] + 24)[0]

    regions = parse_regions(args.regions)
    if not regions:
        raise SystemExit("no regions found")
    sa, fa = layout["sa"], layout["fa"]
    rva = align_up(layout["soi"], sa)
    new_rvas, total = [], 0
    for start, end, _ in regions:
        new_rvas.append(rva + total)
        total += align_up(end - start, sa)

    print("image: %s (%d bytes, base %#x)" % (args.image, len(image), base))
    print("regions: %d (%.1f MB) -> section %r at RVA %#x"
          % (len(regions), total / 1048576.0, args.section, rva))

    index = build_index(regions, base, new_rvas)
    lo = min(r[0] for r in regions)
    hi = max(r[1] for r in regions)

    data = bytearray(image)
    patched = 0
    if not args.no_remap:
        if __np is not None:
            data, patched = remap_with_numpy(bytes(data), index, lo, hi)
        else:
            print("note: numpy not available, using the slow path", file=sys.stderr)
            data, patched = remap_python(bytes(data), index, lo, hi)
        data = bytearray(data)
    print("pointers rewritten in the image: %d" % patched)

    blob = bytearray(total)
    for (start, end, path), new_rva in zip(regions, new_rvas):
        chunk = open(path, "rb").read()[:end - start]
        if not args.no_remap:
            if __np is not None:
                chunk, n = remap_with_numpy(chunk, index, lo, hi)
            else:
                chunk, n = remap_python(chunk, index, lo, hi)
            patched += n
        offset = new_rva - rva
        blob[offset:offset + len(chunk)] = chunk
    print("pointers rewritten in the regions: %d" % (patched - 0 if not args.no_remap else 0))

    raw_offset = align_up(len(data), fa)
    raw_size = align_up(total, fa)
    data += b"\0" * (raw_offset - len(data))
    data += blob
    data += b"\0" * (raw_offset + raw_size - len(data))

    section_header = layout["opt"] + layout["opt_size"] + layout["nsec"] * 40
    if section_header + 40 > layout["soh"]:
        raise SystemExit("no room for an extra section header")

    name = args.section.encode()[:8].ljust(8, b"\0")
    structure = struct.Struct("<8sIIIIIIHHI")
    data[section_header:section_header + 40] = structure.pack(
        name, total, rva, raw_size, raw_offset, 0, 0, 0, 0, 0x40000040)

    struct.pack_into("<H", data, layout["coff"] + 2, layout["nsec"] + 1)
    struct.pack_into("<I", data, layout["opt"] + 56, max(layout["soi"], rva + total))

    open(args.out, "wb").write(data)
    print("wrote %s (%.1f MB, SizeOfImage %#x)"
          % (args.out, len(data) / 1048576.0, max(layout["soi"], rva + total)))

    if args.map:
        with open(args.map, "w") as handle:
            for (start, end, path), new_rva in zip(regions, new_rvas):
                handle.write("%x-%x -> %x-%x %s\n"
                             % (start, end, base + new_rva, base + new_rva + (end - start),
                                os.path.basename(path)))
        print("map written to %s" % args.map)


if __name__ == "__main__":
    main()
