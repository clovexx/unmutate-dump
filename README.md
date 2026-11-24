# unmutate-dump

Make [`themida-unmutate`](https://github.com/ergrelet/themida-unmutate) work on
**dumps**, not just on files.

## The problem

Themida/WinLicense (and other packers of the same family) do not only mutate
code in place: at load time they copy a large part of the program into
**anonymous executable regions**, and leave indirect jumps in the image:

```
.text:3101B42   call 0x51CAC56          ; junk
                call 0x51D5AD3
                jmp  qword [0x3103FE8]  ; -> 0x6FFFF8F64430 (anonymous region!)
```

A dump of the module therefore contains the image, but the code it jumps to
lives outside of it.  Every static tool — disassemblers, decompilers,
`themida-unmutate` — fails on this: there is nothing to analyse at the target
address.  This is the usual reason why "unpack by dumping the process" does not
produce a usable file.

## What this does

Two small scripts:

* **`synthpe.py`** turns `image + dumped regions` into a single PE.  The regions
  are appended as one extra section and **every pointer that pointed into a
  region is rewritten** to the new address (including pointers stored inside
  the regions and pointers stored unaligned), so the result is internally
  consistent.
* **`run_unmutate.py`** drives `themida-unmutate` over that image, one function
  at a time.  The tool aborts the whole run as soon as one function trips an
  unsupported instruction, a broken CFG or an assertion, so the wrapper
  retries chunk members individually, chains every successful output into the
  next step and keeps a resumable JSON state file.

## Usage

```bash
# 1. merge the dump
python3 synthpe.py --image dump/image.bin \
                   --regions dump \
                   --out synth.dll \
                   --map synth.map

# 2. devirtualise the functions you care about (virtual addresses)
python3 run_unmutate.py --input synth.dll \
                        --addresses addresses.txt \
                        --out result.dll \
                        --tool /path/to/themida-unmutate
```

Region files must be named `<start>_<end>_<perms>.bin` with hexadecimal
addresses (`6ffff8f51000_6ffff8fa5000_r-xp.bin`); that is what a `maps`
driven dump naturally produces.  Several `--regions` directories may be given:
earlier directories win when ranges overlap, which lets you mix a snapshot
taken before and one taken after initialisation.

`addresses.txt` takes one virtual address per line (`0x77EB1018`).  Addresses
are addresses **in the merged image**, i.e. image base + RVA, or the mapped
address of a region function — the same numbers you see in a debugger.

## Why not `--reassemble-in-place`

`themida-unmutate --reassemble-in-place` asserts inside
`merge_cnext_constraints()` on images like this (`assert len(next_block.lines) == 1`).
The default mode (write the simplified code into a new section and jump to it)
works.  `run_unmutate.py` always uses the default mode.

## miasm limitations

Some functions cannot be lifted at all with the miasm version bundled with the
tool: 80-bit x87 memory operands (`fstp`), `retf`/`iret` with a narrowed
operand size, and CFGs with dangling blocks.  A patched miasm that lifts those
is available at <https://github.com/clovexx/miasm>; use it with a tool installed
from source (`pip install miasm themida-unmutate`).  With it a substantial part
of the functions becomes processable; the rest are skipped and listed by
`run_unmutate.py`.

## Limitations

* PE32+ only.
* The merged image gets large: it holds every dumped region (hundreds of MB are
  normal for a big DLL).  `run_unmutate.py` copies the whole file on every step,
  so keep the work directory on a fast disk.
* Pointers are rewritten by value range, not by type.  A 64-bit constant that
  happens to fall inside a dumped region is rewritten too; in practice such
  constants are rare and the gain outweighs it.  Use `--no-remap` to compare.
* This does not "de-Themida" a binary by itself: it makes the relocated code
  *analysable*.  What you do with the result — devirtualise, compare with the
  original, patch — is up to you.

## Tested on

A ~33 MB Themida-protected DLL whose `.text/.rdata/.data` are built at runtime
and whose code is relocated into 178 anonymous regions (373 MB).  The merged
image is ~487 MB; `themida-unmutate` then processes functions that it cannot
even parse on the raw dump.

## License

GPL-3.0.  `themida-unmutate` and `miasm` are GPL-3.0/GPL-2.0 respectively, and
this tool is meant to be used with them.
