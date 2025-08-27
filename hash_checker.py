#!/usr/bin/env python3
"""
Hash Checker — a tiny, reliable CLI for computing and verifying checksums.

Features
- Compute hashes: md5, sha1, sha256, sha512, blake2b (and any hashlib-supported algo).
- Verify a file against a given checksum (auto-detects algorithm by length if not provided).
- Compare two files by hash.
- Hash multiple files or whole folders (recursively), optionally emit JSON.

Examples
  # Compute sha256 for a file
  python hash_checker.py sum file.iso

  # Compute multiple algorithms
  python hash_checker.py sum file.iso --algos sha256 sha512 blake2b

  # Hash an entire directory recursively, JSON output
  python hash_checker.py sum ~/Downloads --recursive --json

  # Verify a file against a known hash (algorithm auto-detected)
  python hash_checker.py verify file.iso --hash 3a7bd3e2360a3d...

  # Force an algorithm during verify
  python hash_checker.py verify file.iso --hash 9b74c9897bac770ffc029102a200c5de --algo md5

  # Compare two files by sha256
  python hash_checker.py compare fileA.bin fileB.bin --algo sha256

Exit codes
  0 success / verified equal
  1 verification failed or not equal
  2 usage / runtime error
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

# ------- Core hashing helpers -------

SUPPORTED_DEFAULTS = ["md5", "sha1", "sha256", "sha512", "blake2b"]

HEX_ALGO_LENGTHS = {
    # common hex digest lengths by algorithm
    32: ["md5"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256"],
    96: ["sha384"],
    128: ["sha512", "blake2b"],
}

@dataclass
class HashResult:
    path: str
    algo: str
    hexdigest: str
    size: Optional[int] = None


def available_algorithms() -> List[str]:
    # Prefer stable, widely available names
    algos = sorted(set(SUPPORTED_DEFAULTS) | set(hashlib.algorithms_guaranteed))
    return algos


def chunk_reader(f, chunk_size: int = 1024 * 1024) -> Iterable[bytes]:
    while True:
        chunk = f.read(chunk_size)
        if not chunk:
            break
        yield chunk


def compute_hash(path: str, algo: str, chunk_size: int = 1024 * 1024) -> HashResult:
    algo_lower = algo.lower()
    if algo_lower not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported algorithm: {algo}")
    h = hashlib.new(algo_lower)
    size = None
    if path == "-":
        for chunk in chunk_reader(sys.stdin.buffer, chunk_size):
            h.update(chunk)
    else:
        with open(path, "rb") as f:
            try:
                st = os.fstat(f.fileno())
                size = st.st_size
            except Exception:
                size = None
            for chunk in chunk_reader(f, chunk_size):
                h.update(chunk)
    return HashResult(path=path, algo=algo_lower, hexdigest=h.hexdigest(), size=size)


def guess_algorithms_from_hash(h: str) -> List[str]:
    h = h.strip().lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        return []
    return HEX_ALGO_LENGTHS.get(len(h), [])


# ------- Actions -------

def action_sum(paths: List[str], algos: List[str], recursive: bool, json_out: bool, show_size: bool) -> int:
    targets: List[str] = []
    for p in paths:
        if p == "-":
            targets.append(p)
            continue
        if os.path.isdir(p):
            if recursive:
                for root, _, files in os.walk(p):
                    for fn in files:
                        targets.append(os.path.join(root, fn))
            else:
                print(f"[skip dir] {p} (use --recursive)", file=sys.stderr)
        elif os.path.isfile(p):
            targets.append(p)
        else:
            print(f"[missing] {p}", file=sys.stderr)

    results: List[HashResult] = []
    try:
        for t in targets:
            for algo in algos:
                results.append(compute_hash(t, algo))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if json_out:
        payload = [
            {
                "path": r.path,
                "algo": r.algo,
                "hash": r.hexdigest,
                **({"size": r.size} if show_size and r.size is not None else {}),
            }
            for r in results
        ]
        print(json.dumps(payload, indent=2))
    else:
        for r in results:
            size_str = f"  ({r.size} bytes)" if show_size and r.size is not None else ""
            print(f"{r.hexdigest}  {r.algo}  {r.path}{size_str}")
    return 0


def action_verify(path: str, expected_hash: str, algo: Optional[str]) -> int:
    expected = expected_hash.strip().lower()
    algos: List[str]
    if algo:
        algos = [algo]
    else:
        guess = guess_algorithms_from_hash(expected)
        algos = guess if guess else SUPPORTED_DEFAULTS

    try:
        for a in algos:
            actual = compute_hash(path, a).hexdigest
            if actual.lower() == expected:
                print(f"OK: {path} matches {a} : {expected}")
                return 0
        print(f"FAIL: {path} did not match provided hash with algos: {', '.join(algos)}")
        return 1
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def action_compare(path_a: str, path_b: str, algo: str) -> int:
    try:
        ha = compute_hash(path_a, algo).hexdigest
        hb = compute_hash(path_b, algo).hexdigest
        if ha == hb:
            print(f"EQUAL: {path_a} == {path_b} ({algo})\n{ha}")
            return 0
        else:
            print(f"DIFFER: {path_a} != {path_b} ({algo})\n{path_a}: {ha}\n{path_b}: {hb}")
            return 1
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


# ------- CLI parsing -------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Compute and verify file checksums.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # sum
    sp = sub.add_parser("sum", help="Compute hash(es) for files or directories")
    sp.add_argument("paths", nargs="+", help="Files/dirs to hash; use '-' for stdin")
    sp.add_argument(
        "--algos",
        nargs="+",
        metavar="ALGO",
        default=["sha256"],
        help="Algorithms to use (e.g., sha256 sha512 md5). See --list-algorithms.",
    )
    sp.add_argument("--recursive", action="store_true", help="Recurse into directories")
    sp.add_argument("--json", action="store_true", help="Emit JSON results")
    sp.add_argument("--size", action="store_true", help="Include file size in output (where available)")

    # verify
    vp = sub.add_parser("verify", help="Verify a file against a known hash")
    vp.add_argument("path", help="File to verify")
    vp.add_argument("--hash", required=True, dest="hash_", help="Expected hex digest")
    vp.add_argument("--algo", help="Algorithm to force (otherwise auto-detect/try common)")

    # compare
    cp = sub.add_parser("compare", help="Compare two files by hash")
    cp.add_argument("file_a")
    cp.add_argument("file_b")
    cp.add_argument("--algo", default="sha256", help="Algorithm to use")

    # list
    lp = sub.add_parser("list", help="List available algorithms")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    if args.cmd == "list":
        algos = available_algorithms()
        for a in algos:
            print(a)
        return 0

    if args.cmd == "sum":
        return action_sum(
            paths=args.paths,
            algos=[a.lower() for a in args.algos],
            recursive=args.recursive,
            json_out=args.json,
            show_size=args.size,
        )

    if args.cmd == "verify":
        return action_verify(args.path, args.hash_, args.algo.lower() if args.algo else None)

    if args.cmd == "compare":
        return action_compare(args.file_a, args.file_b, args.algo.lower())

    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
