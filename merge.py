#!/usr/bin/env python3
"""
This script merges multiple PEM-encoded certificate files into a single
deduplicated bundle. It reads one or more input PEM files, removes duplicate
certificates, and writes all unique certificates into a combined output file.
"""
import os
import argparse


def load_pem_certs(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, "rb") as f:
        pem_data = f.read()
    blocks = []
    for cert in pem_data.split(b"-----END CERTIFICATE-----"):
        cert = cert.strip()
        if not cert:
            continue
        cert += b"\n-----END CERTIFICATE-----\n"
        blocks.append(cert)
    return blocks


def main():
    parser = argparse.ArgumentParser(description="Merge PEM files into a single deduplicated bundle.")
    parser.add_argument("inputs", nargs="+", help="Input PEM files to merge (provide one or more)")
    parser.add_argument("-o", "--output", required=True, help="Output filename (no default)")
    args = parser.parse_args()

    seen = set()
    merged = []

    for file in args.inputs:
        certs = load_pem_certs(file)
        for cert in certs:
            if cert not in seen:
                merged.append(cert)
                seen.add(cert)

    with open(args.output, "wb") as f:
        for cert in merged:
            f.write(cert)

    print(f"Merged {len(merged)} unique certificates into {args.output} (from: {', '.join(args.inputs)})")


if __name__ == "__main__":
    main()
