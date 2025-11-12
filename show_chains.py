#!/usr/bin/env python3
"""
Analyze and reconstruct X.509 certificate chains from two PEM files:
one containing leaf certificates and another containing possible issuer
or intermediate certificates.

It prints complete chains first and incomplete chains last.
All certificates use SKI as ID. Cycles and large bundles are handled efficiently.
"""
import argparse
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from cert_lib import load_pem_file, get_subject_key_identifier, get_common_name


def get_cn(cert):
    """Get Common Name from certificate subject."""
    return get_common_name(cert.subject, default="Unknown CN")


def get_issuer_cn(cert):
    """Get Common Name from certificate issuer."""
    return get_common_name(cert.issuer, default="Unknown CN")


def build_subject_map(certs):
    """Map subjects to certificates for O(1) lookup during chain building"""
    subject_map = {}
    for cert, _ in certs:
        subject_map[cert.subject.rfc4514_string()] = cert
    return subject_map

def main():
    parser = argparse.ArgumentParser(description="Build certificate chains from two certificate files.")
    parser.add_argument("leaf_certs", help="File containing leaf certificates (e.g., certs_web.pem)")
    parser.add_argument("chain_certs", help="File containing chain certificates (e.g., chain.pem)")
    args = parser.parse_args()

    leaf_certs = load_pem_file(args.leaf_certs, as_objects=True, include_source=True)
    chain_certs = load_pem_file(args.chain_certs, as_objects=True, include_source=True)

    # Build quick lookup maps
    subject_map = build_subject_map(chain_certs)
    ski_to_files = {}
    for file in [args.leaf_certs, args.chain_certs]:
        cert_list = load_pem_file(file, as_objects=True, include_source=True)
        for cert, _ in cert_list:
            ski = get_subject_key_identifier(cert)
            ski_to_files.setdefault(ski, set()).add(file)

    incomplete_chains = []

    for cert, _ in leaf_certs:
        leaf_ski = get_subject_key_identifier(cert)
        files_str = ", ".join(sorted(ski_to_files.get(leaf_ski, [])))
        print(f"LEAF ID={leaf_ski} | CN={get_cn(cert)} | ISSUER={get_issuer_cn(cert)} ({files_str})")

        if cert.issuer == cert.subject:
            print("  Chain length: 1\n")
            continue

        current_cert = cert
        chain = []
        found_root = False
        seen_ski = set()
        for _ in range(10):  # maximum depth
            current_ski = get_subject_key_identifier(current_cert)
            if current_ski in seen_ski:
                # Detected cycle
                break
            seen_ski.add(current_ski)

            issuer_dn = current_cert.issuer.rfc4514_string()
            issuer_cert = subject_map.get(issuer_dn)
            if not issuer_cert or issuer_cert == current_cert:
                break

            pos = "ROOT" if issuer_cert.subject == issuer_cert.issuer else "INTERMEDIATE"
            chain.append((pos, issuer_cert))
            current_cert = issuer_cert

            if pos == "ROOT":
                found_root = True
                break

        if found_root:
            for pos, c_chain in chain:
                indent = "    " if pos == "ROOT" else ""
                ski_chain = get_subject_key_identifier(c_chain)
                files_chain = ", ".join(sorted(ski_to_files.get(ski_chain, [])))
                print(f"{indent}{pos} ID={ski_chain} | CN={get_cn(c_chain)} | ISSUER={get_issuer_cn(c_chain)} ({files_chain})")
            print(f"  Chain length: {len(chain) + 1}\n")
        else:
            incomplete_chains.append((cert, chain))

    if incomplete_chains:
        print("\nINCOMPLETE CHAINS:")
        for cert, chain in incomplete_chains:
            leaf_ski = get_subject_key_identifier(cert)
            print(f"LEAF ID={leaf_ski} | CN={get_cn(cert)} | ISSUER={get_issuer_cn(cert)}")
            for pos, c_chain in chain:
                ski_chain = get_subject_key_identifier(c_chain)
                print(f"  {pos} ID={ski_chain} | CN={get_cn(c_chain)} | ISSUER={get_issuer_cn(c_chain)}")
            print("  Chain not complete\n")

if __name__ == "__main__":
    main()

