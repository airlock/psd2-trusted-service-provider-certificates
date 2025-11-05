#!/usr/bin/env python3

"""
This script builds complete X.509 certificate chains for website certificates
using both locally available certificate pools and Authority Information Access (AIA)
downloads. It reads two PEM files (web certificates and a pool of CA certificates),
attempts to resolve issuer certificates via AIA URLs or the local pool,
and outputs full certificate chains in PEM format.
"""

import os
import sys
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import argparse
import warnings

# Suppress InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Suppress UserWarning for invalid certificate comparisons
warnings.filterwarnings("ignore", message="Attribute's length must be >= 1 and <= 64, but it was")

def load_certs(filename):
    certs = []
    if not os.path.exists(filename):
        return certs
    with open(filename, "rb") as f:
        pem_data = f.read()
    pem_blocks = pem_data.split(b"-----END CERTIFICATE-----")
    for i, cert_pem in enumerate(pem_blocks):
        cert_pem = cert_pem.strip()
        if not cert_pem:
            continue
        cert_pem += b"\n-----END CERTIFICATE-----\n"
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            certs.append(cert)
        except Exception:
            continue
    return certs

def download_aia(url):
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        return None
    try:
        r = requests.get(url, timeout=20, verify=False)
        r.raise_for_status()
        pem_data = r.content
        try:
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        except Exception:
            try:
                cert = x509.load_der_x509_certificate(pem_data, default_backend())
            except Exception:
                return None
        return cert
    except Exception:
        return None

def find_issuer(cert, pool):
    for candidate in pool:
        try:
            # Check the length of the attributes to prevent invalid comparisons
            if len(str(cert.issuer)) <= 64 and len(str(candidate.subject)) <= 64:
                if cert.issuer == candidate.subject:
                    return candidate
        except Exception:
            continue
    return None

def build_chain(cert, pool):
    chain = [cert]
    current = cert
    aia_count = 0
    pool_count = 0
    while True:
        issuer_cert = None
        try:
            aia_ext = current.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            aia_urls = [
                access.access_location.value
                for access in aia_ext.value
                if access.access_method.dotted_string == "1.3.6.1.5.5.7.48.2"
            ]
            for url in aia_urls:
                issuer_cert = download_aia(url)
                if issuer_cert:
                    aia_count += 1
                    break
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        if issuer_cert is None:
            issuer_cert = find_issuer(current, pool)
            if issuer_cert:
                pool_count += 1

        if issuer_cert is None or issuer_cert.subject == current.subject:
            break

        chain.append(issuer_cert)
        current = issuer_cert

    return chain, aia_count, pool_count

def save_chain(chains, filename):
    with open(filename, "wb") as f:
        for chain in chains:
            for cert in chain:
                try:
                    f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
                except Exception:
                    continue

def main():
    parser = argparse.ArgumentParser(description="Build certificate chains for web certs using a pool of certificates.")
    parser.add_argument('web_certs', help="File containing web certificates")
    parser.add_argument('pool_certs', help="File containing pool certificates")
    parser.add_argument('output', help="Output file for chains")
    args = parser.parse_args()

    # Load web and pool certificates
    web_certs = load_certs(args.web_certs)
    pool_certs = load_certs(args.pool_certs)

    # Check if any web certificates were loaded
    if not web_certs:
        print(f"No web certificates found in {args.web_certs}. Please check the file.")
        return

    # Build chains and count certificates from AIA and pool
    all_chains = []
    aia_total = 0
    pool_total = 0
    for cert in web_certs:
        chain, aia_count, pool_count = build_chain(cert, pool_certs)
        all_chains.append(chain)
        aia_total += aia_count
        pool_total += pool_count

    # Save the certificate chains
    save_chain(all_chains, args.output)
    print(f"Downloaded {aia_total} certificates from AIA extensions and {pool_total} certificates from the pool. Saved chains to {args.output}.")

if __name__ == "__main__":
    main()
