# hash-checker
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
