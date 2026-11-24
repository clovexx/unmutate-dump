#!/usr/bin/env python3
"""run_unmutate - drive themida-unmutate over a synthetic image, one function
at a time, without losing progress.

The tool aborts the whole run when it meets a function it cannot handle (an
unimplemented miasm operation, a broken CFG, an assertion while placing code).
With dozens or hundreds of functions this is a practical problem, so this
wrapper:

  * feeds the tool a chunk of addresses and, when the chunk fails, retries
    every address of that chunk on its own;
  * chains the output of each successful step into the next one, so partial
    results are never thrown away;
  * keeps a JSON state file, making the run resumable.

Addresses passed to the tool are virtual addresses of the functions in the
synthetic image (see synthpe.py).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile


def load_state(path):
    if os.path.exists(path):
        with open(path) as handle:
            return json.load(handle)
    return {"done": [], "failed": []}


def save_state(path, state):
    with open(path, "w") as handle:
        json.dump(state, handle, indent=1)


def parse_addresses(path):
    values = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for token in line.split():
                values.append(int(token, 0))
    return values


def run_tool(tool, addresses, source, destination, timeout, extra):
    command = [tool, "--no-trampoline", "-a", *[hex(a) for a in addresses],
               "-o", destination, *extra, source]
    try:
        result = subprocess.run(command, timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    if result.returncode != 0 or not os.path.exists(destination):
        tail = result.stdout.decode("utf-8", "replace").strip().splitlines()[-3:]
        return False, " / ".join(tail)
    return True, ""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="synthetic image produced by synthpe.py")
    ap.add_argument("--addresses", required=True, help="file with one address per line")
    ap.add_argument("--out", required=True, help="resulting image")
    ap.add_argument("--tool", default="themida-unmutate", help="path to the tool")
    ap.add_argument("--chunk", type=int, default=15, help="addresses per tool invocation")
    ap.add_argument("--timeout", type=int, default=900, help="timeout per invocation (s)")
    ap.add_argument("--state", help="JSON progress file (default: <out>.state.json)")
    ap.add_argument("--extra", default="", help="extra arguments passed to the tool")
    ap.add_argument("--resume", action="store_true", help="continue a previous run")
    args = ap.parse_args()

    state_path = args.state or (args.out + ".state.json")
    work = args.out + ".work"
    state = load_state(state_path) if args.resume else {"done": [], "failed": []}

    if not args.resume or not os.path.exists(work):
        shutil.copyfile(args.input, work)
        state = {"done": [], "failed": []}

    done = set(state["done"])
    failed = set(state["failed"])
    pending = [a for a in parse_addresses(args.addresses) if a not in done and a not in failed]
    extra = [part for part in args.extra.split() if part]

    print("%d addresses, %d already done, %d failed, %d pending"
          % (len(done) + len(failed) + len(pending), len(done), len(failed), len(pending)))

    directory = tempfile.mkdtemp(prefix="unmutate-")
    try:
        index = 0
        while index < len(pending):
            chunk = pending[index:index + args.chunk]
            index += args.chunk
            candidate = os.path.join(directory, "next.dll")
            if os.path.exists(candidate):
                os.unlink(candidate)

            ok, reason = run_tool(args.tool, chunk, work, candidate, args.timeout, extra)
            if ok:
                os.replace(candidate, work)
                for address in chunk:
                    done.add(address)
                state["done"] = sorted(done)
                save_state(state_path, state)
                print("  chunk of %d: ok (%d/%d)" % (len(chunk), len(done), len(pending)))
                continue

            print("  chunk of %d failed (%s); retrying one by one" % (len(chunk), reason))
            for address in chunk:
                if os.path.exists(candidate):
                    os.unlink(candidate)
                ok, reason = run_tool(args.tool, [address], work, candidate,
                                      args.timeout, extra)
                if ok:
                    os.replace(candidate, work)
                    done.add(address)
                else:
                    failed.add(address)
                    print("    %#x: %s" % (address, reason))
                state["done"] = sorted(done)
                state["failed"] = sorted(failed)
                save_state(state_path, state)
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    shutil.copyfile(work, args.out)
    print("done: %d ok, %d failed -> %s" % (len(done), len(failed), args.out))
    if failed:
        print("failed addresses: " + " ".join(hex(a) for a in sorted(failed)))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
