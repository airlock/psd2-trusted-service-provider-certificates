#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build complete X.509 certificate chains using:
- Local certificate pool
- Authority Information Access (AIA)
- Only currently valid certificates
"""

import os
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import argparse
import warnings

from cert_lib import remove_duplicate_certs, cert_is_valid_now

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Attribute's length must be >= 1 and <= 64, but it was")


def load_certs(filename):
    certs = []
    if not os.path.exists(filename):
        return certs
    with open(filename, "rb") as f:
        pem_data = f.read()
    for cert_pem in pem_data.split(b"-----END CERTIFICATE-----"):
        cert_pem = cert_pem.strip()
        if not cert_pem:
            continue
        cert_pem += b"\n-----END CERTIFICATE-----\n"
        if not cert_is_valid_now(cert_pem):
            continue
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
        r = requests.get(url, timeout=30, verify=False)
        r.raise_for_status()
        data = r.content
        if not cert_is_valid_now(data):
            return None
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except Exception:
            return x509.load_der_x509_certificate(data, default_backend())
    except Exception:
        return None


def find_issuer(cert, pool):
    for candidate in pool:
        try:
            if cert.issuer == candidate.subject:
                return candidate
        except Exception:
            continue
    return None


def get_aia_urls(cert):
    urls = []
    try:
        aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        urls = [
            access.access_location.value
            for access in aia_ext.value
            if access.access_method.dotted_string == "1.3.6.1.5.5.7.48.2"
        ]
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    return urls


def build_chain(cert, pool, disable_aia=False):
    chain = [cert]
    to_check = [cert]
    aia_total = pool_total = 0

    while to_check:
        current = to_check.pop()
        issuer_cert = None

        # Prüfe AIA URLs (nur falls nicht deaktiviert)
        if not disable_aia:
            for url in get_aia_urls(current):
                candidate = download_aia(url)
                if candidate and candidate not in pool:
                    pool.append(candidate)
                    to_check.append(candidate)
                    aia_total += 1

        # Prüfe Pool auf passenden Issuer
        issuer_cert = find_issuer(current, pool)
        if issuer_cert and issuer_cert not in chain:
            chain.append(issuer_cert)
            to_check.append(issuer_cert)
            pool_total += 1

        # Stop if self-signed root
        if issuer_cert and issuer_cert.subject == issuer_cert.issuer:
            continue

    return chain, aia_total, pool_total


def save_chain(chains, filename):
    all_certs_pem = []
    for chain in chains:
        for cert in chain:
            try:
                pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
                if cert_is_valid_now(pem_bytes):
                    all_certs_pem.append(pem_bytes)
            except Exception:
                continue
    unique_certs = remove_duplicate_certs(all_certs_pem)
    with open(filename, "wb") as f:
        for pem in unique_certs:
            f.write(pem)


def main():
    parser = argparse.ArgumentParser(
        description="Build certificate chains with recursive AIA and local pool processing, only valid certificates."
    )
    parser.add_argument('web_certs', help="File containing web certificates")
    parser.add_argument('pool_certs', help="File containing pool certificates")
    parser.add_argument('output', help="Output file for full chains")
    parser.add_argument('--no-aia', action='store_true', help="Disable AIA certificate downloading")
    args = parser.parse_args()

    web_certs = load_certs(args.web_certs)
    pool_certs = load_certs(args.pool_certs)
    if not web_certs:
        print(f"No valid web certificates found in {args.web_certs}.")
        return

    all_chains = []
    aia_total = pool_total = 0

    for cert in web_certs:
        chain, aia_count, pool_count = build_chain(cert, pool_certs, disable_aia=args.no_aia)
        all_chains.append(chain)
        aia_total += aia_count
        pool_total += pool_count

    save_chain(all_chains, args.output)
    print(f"Downloaded {aia_total} certificates from AIA, "
          f"{pool_total} from pool. "
          f"Saved valid chains to {args.output}.")


if __name__ == "__main__":
    main()

