#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build complete X.509 certificate chains using:
- Local certificate pool
- Authority Information Access (AIA)
- crt.sh API fallback

Retries up to 3 times for crt.sh. Reports SKIs that could not be downloaded.
"""

import os
import sys
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import ExtensionOID
import argparse
import warnings
import time

from cert_lib import cert_is_valid_now, remove_duplicate_certs

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Attribute's length must be >= 1 and <= 64, but it was")

CRT_SH_API = "https://crt.sh/?ski={}&output=json"
CRT_SH_DOWNLOAD = "https://crt.sh/?d={}"

crtsh_cache = {}
failed_crtsh = {}  # ski -> reason


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


def download_from_crtsh_by_ski(cert):
    try:
        aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        key_id = aki_ext.value.key_identifier
        if not key_id:
            failed_crtsh["UNKNOWN"] = "No AKI key identifier"
            return None
        ski_hex = key_id.hex()
    except Exception:
        failed_crtsh["UNKNOWN"] = "No AKI extension"
        return None

    if ski_hex in crtsh_cache:
        return crtsh_cache[ski_hex]

    retries = 3
    for attempt in range(1, retries + 1):
        print(f"  → Querying crt.sh for ski={ski_hex} (attempt {attempt})", file=sys.stderr, flush=True)
        try:
            r = requests.get(CRT_SH_API.format(ski_hex), timeout=30)
            print(f"    crt.sh response: {r.text[:200]}...", file=sys.stderr, flush=True)

            if r.status_code != 200 or not r.text.strip():
                reason = f"HTTP {r.status_code}" if r.status_code != 200 else "Empty result"
                if attempt == retries:
                    failed_crtsh[ski_hex] = reason
                    crtsh_cache[ski_hex] = None
                    return None
                time.sleep(2)
                continue

            entries = r.json()
            if not entries:
                if attempt == retries:
                    failed_crtsh[ski_hex] = "No entries in crt.sh"
                    crtsh_cache[ski_hex] = None
                    return None
                time.sleep(2)
                continue

            # Wähle das Zertifikat mit dem neuesten not_before-Datum
            try:
                entries = [e for e in entries if "not_before" in e]
                entries.sort(key=lambda e: e["not_before"], reverse=True)
                entry = entries[0]
            except Exception:
                entry = entries[0]

            pem_url = CRT_SH_DOWNLOAD.format(entry["id"])
            r2 = requests.get(pem_url, timeout=30)
            r2.raise_for_status()
            data = r2.content
            try:
                cert_obj = x509.load_pem_x509_certificate(data, default_backend())
            except Exception:
                cert_obj = x509.load_der_x509_certificate(data, default_backend())

            crtsh_cache[ski_hex] = cert_obj
            return cert_obj

        except Exception as e:
            if attempt == retries:
                failed_crtsh[ski_hex] = str(e)
                crtsh_cache[ski_hex] = None
                return None
            time.sleep(2)

    crtsh_cache[ski_hex] = None
    return None


def build_chain(cert, pool):
    chain = [cert]
    current = cert
    aia_total = pool_total = crtsh_total = 0

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
                candidate = download_aia(url)
                if candidate:
                    aia_total += 1
                    pool_candidate = find_issuer(candidate, pool)
                    if pool_candidate:
                        issuer_cert = pool_candidate
                        pool_total += 1
                    else:
                        issuer_cert = candidate
                        pool.append(candidate)
                    break
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass

        if issuer_cert is None:
            issuer_cert = find_issuer(current, pool)
            if issuer_cert:
                pool_total += 1

        if issuer_cert is None:
            candidate = download_from_crtsh_by_ski(current)
            if candidate:
                crtsh_total += 1
                pool.append(candidate)
                current = candidate
                continue
            else:
                break

        chain.append(issuer_cert)
        if issuer_cert.subject == issuer_cert.issuer:
            break
        current = issuer_cert

    return chain, aia_total, pool_total, crtsh_total


def save_chain(chains, filename):
    all_certs_pem = []
    for chain in chains:
        for cert in chain:
            try:
                all_certs_pem.append(cert.public_bytes(serialization.Encoding.PEM))
            except Exception:
                continue
    unique_certs = remove_duplicate_certs(all_certs_pem)
    with open(filename, "wb") as f:
        for pem in unique_certs:
            f.write(pem)


def main():
    parser = argparse.ArgumentParser(description="Build certificate chains with AIA, local pool, and crt.sh fallback (cached).")
    parser.add_argument('web_certs', help="File containing web certificates")
    parser.add_argument('pool_certs', help="File containing pool certificates")
    parser.add_argument('output', help="Output file for full chains")
    parser.add_argument('--skip-crtsh', action='store_true', help="Skip crt.sh lookups")
    args = parser.parse_args()

    web_certs = load_certs(args.web_certs)
    pool_certs = load_certs(args.pool_certs)
    if not web_certs:
        print(f"No web certificates found in {args.web_certs}.")
        return

    if args.skip_crtsh:
        global download_from_crtsh_by_ski
        download_from_crtsh_by_ski = lambda cert: None

    all_chains = []
    aia_total = pool_total = crtsh_total = 0

    for cert in web_certs:
        chain, aia_count, pool_count, crtsh_count = build_chain(cert, pool_certs)
        all_chains.append(chain)
        aia_total += aia_count
        pool_total += pool_count
        crtsh_total += crtsh_count

    save_chain(all_chains, args.output)
    print(f"Downloaded {aia_total} certificates from AIA, "
          f"{pool_total} from pool, {crtsh_total} from crt.sh. "
          f"Saved chains to {args.output}.")

    if failed_crtsh:
        print("\nSKIs not downloaded from crt.sh:")
        for ski, reason in failed_crtsh.items():
            print(f"  {ski}: {reason}")


if __name__ == "__main__":
    main()

