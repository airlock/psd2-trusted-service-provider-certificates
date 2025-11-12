#!/usr/bin/env python3
"""
This script merges multiple PEM-encoded certificate files into a single bundle,
removing duplicate certificates.
"""
import os
import argparse
from cert_lib import remove_duplicate_certs, load_pem_file

def main():
    parser = argparse.ArgumentParser(description="Merge PEM files into a single deduplicated bundle.")
    parser.add_argument("inputs", nargs="+", help="Input PEM files to merge (provide one or more)")
    parser.add_argument("-o", "--output", required=True, help="Output filename (no default)")
    args = parser.parse_args()

    all_certs = []
    for file in args.inputs:
        all_certs.extend(load_pem_file(file))

    unique_certs = remove_duplicate_certs(all_certs)

    with open(args.output, "wb") as f:
        for cert in unique_certs:
            f.write(cert)

    print(f"Merged {len(unique_certs)} unique certificates into {args.output} (from: {', '.join(args.inputs)})")

if __name__ == "__main__":
    main()

