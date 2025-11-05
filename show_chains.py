#!/usr/bin/env python3
"""
This script analyzes and reconstructs X.509 certificate chains
from two PEM files: one containing leaf (end-entity) certificates
and another containing possible issuer or intermediate certificates.
It identifies each leaf certificate, attempts to locate its issuer(s)
from the provided chain file, prints the full chain hierarchy,
and reports whether each chain is complete up to a trusted root.
"""
import argparse
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def load_certs(filename):
    """Load certificates from a PEM file."""
    if not os.path.isfile(filename):
        return []
    with open(filename, "rb") as f:
        pem_data = f.read()
    certs = []
    for cert_block in pem_data.split(b"-----END CERTIFICATE-----"):
        cert_block = cert_block.strip()
        if not cert_block:
            continue
        cert_block += b"\n-----END CERTIFICATE-----\n"
        try:
            x509_cert = x509.load_pem_x509_certificate(cert_block, default_backend())
            certs.append((x509_cert, filename))
        except Exception:
            continue
    return certs


def get_cn(cert):
    """Get the Common Name (CN) of a certificate."""
    cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return cn_attr[0].value if cn_attr else "Unknown CN"


def get_issuer_cn(cert):
    """Get the issuer's Common Name (CN) of a certificate."""
    cn_attr = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return cn_attr[0].value if cn_attr else "Unknown CN"


def main():
    parser = argparse.ArgumentParser(description="Build certificate chains from two certificate files.")
    parser.add_argument("leaf_certs", help="File containing leaf certificates (e.g., certs_web.pem)")
    parser.add_argument("chain_certs", help="File containing chain certificates (e.g., chain.pem)")
    args = parser.parse_args()

    leaf_certs = load_certs(args.leaf_certs)
    chain_certs = load_certs(args.chain_certs)

    # Map fingerprints to source files
    fp_to_files = {}
    for file in [args.leaf_certs, args.chain_certs]:
        cert_list = load_certs(file)
        for cert, _ in cert_list:
            fp = cert.fingerprint(hashes.SHA1()).hex()
            fp_to_files.setdefault(fp, set()).add(file)

    # Process each leaf certificate
    for cert, _ in leaf_certs:
        fp = cert.fingerprint(hashes.SHA1()).hex()
        files_str = ", ".join(sorted(fp_to_files.get(fp, [])))
        print(f"LEAF ID={fp} | CN={get_cn(cert)} | ISSUER={get_issuer_cn(cert)} ({files_str})")

        current_cert = cert
        chain = []
        incomplete = False
        found_root = False

        # Build chain
        for _ in range(10):  # limit to prevent infinite loops
            issuer_found = None
            for candidate, _ in chain_certs:
                try:
                    if candidate.subject == current_cert.issuer and candidate != current_cert:
                        issuer_found = candidate
                        break
                except Exception:
                    continue

            if not issuer_found:
                incomplete = True
                break

            try:
                basic = issuer_found.extensions.get_extension_for_class(x509.BasicConstraints).value
                is_root = issuer_found.subject == issuer_found.issuer and getattr(basic, 'ca', False)
                pos = "ROOT" if is_root else "INTERMEDIATE"
            except Exception:
                pos = "INTERMEDIATE"
                is_root = False

            chain.append((pos, issuer_found))
            current_cert = issuer_found

            if is_root:
                found_root = True
                break

        # Output the chain
        for pos, c_chain in chain:
            indent = "    " if pos == "ROOT" else ""
            fp_chain = c_chain.fingerprint(hashes.SHA1()).hex()
            files_chain = ", ".join(sorted(fp_to_files.get(fp_chain, [])))
            print(f"{indent}{pos} ID={fp_chain} | CN={get_cn(c_chain)} | ISSUER={get_issuer_cn(c_chain)} ({files_chain})")

        if not found_root:
            print("  Chain not complete")
            print("  Chain length: NA\n")
        else:
            total_chain_len = len(chain)  # includes leaf
            print(f"  Chain length: {total_chain_len}\n")


if __name__ == "__main__":
    main()
