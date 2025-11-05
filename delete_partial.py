#!/usr/bin/env python3

"""
This script removes website certificates with incomplete or broken chains
from a PEM bundle. It uses the output of show_chains.py to identify leaf
certificates whose chains cannot be fully resolved and rewrites the input
PEM file, keeping only certificates with complete chains.
"""

import subprocess
import re
import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Remove web certificates with incomplete chains from a PEM bundle.")
    parser.add_argument('web_certs', help='PEM file containing web certificates to clean (no default)')
    parser.add_argument('chain_certs', help='PEM file containing chain certificates used for validation (no default)')
    args = parser.parse_args()

    CERT_FILE = args.web_certs
    CHAIN_FILE = args.chain_certs
    TMP_FILE = CERT_FILE + ".tmp"

    # Run show_chains.py with both files and capture output
    proc = subprocess.run(
        ["./show_chains.py", CERT_FILE, CHAIN_FILE],
        capture_output=True,
        text=True
    )
    output = proc.stdout

    # Collect IDs of certificates with incomplete chains
    incomplete_ids = set()
    current_id = None
    max_chain_len = 0
    for line in output.splitlines():
        leaf_match = re.match(r"LEAF ID=([0-9a-f]+)", line)
        if leaf_match:
            current_id = leaf_match.group(1)
        if "Chain not complete" in line and current_id:
            incomplete_ids.add(current_id)
        length_match = re.search(r"Chain length:\s*(\d+)", line)
        if length_match:
            length = int(length_match.group(1))
            if length > max_chain_len:
                max_chain_len = length

    if not incomplete_ids:
        intermediates = max(0, max_chain_len - 1)
        print(f"No incomplete certificates found. Max chain length: {max_chain_len} ({intermediates} intermediates)")
        sys.exit(0)

    # Load all certificates and keep only those with complete chains
    with open(CERT_FILE, "rb") as f:
        pem_data = f.read()

    blocks = pem_data.split(b"-----END CERTIFICATE-----")
    kept_blocks = []

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes

    for block in blocks:
        block = block.strip()
        if not block:
            continue
        block += b"\n-----END CERTIFICATE-----\n"
        try:
            cert = x509.load_pem_x509_certificate(block, default_backend())
            cert_id = cert.fingerprint(hashes.SHA1()).hex()
            if cert_id not in incomplete_ids:
                kept_blocks.append(block)
        except Exception:
            kept_blocks.append(block)

    # Write updated file
    with open(TMP_FILE, "wb") as f:
        for block in kept_blocks:
            f.write(block)

    os.replace(TMP_FILE, CERT_FILE)
    intermediates = max(0, max_chain_len - 1)
    print(f"Removed {len(incomplete_ids)} certificates due to incomplete chains from {CERT_FILE}")
    print(f"Max chain length: {max_chain_len} ({intermediates} intermediates)")

if __name__ == '__main__':
    main()
