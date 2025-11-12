#!/usr/bin/env python3
"""
Download all X.509 certificates from the EU Trusted List (LOTL) and national TSLs.
"""

import requests
import xml.etree.ElementTree as ET
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import urllib3
import os
import sys
import warnings

from cert_lib import cert_is_valid_now, remove_duplicate_certs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"


def download_xml(url):
    r = requests.get(url, verify=False, timeout=30)
    r.raise_for_status()
    return r.content


def _log_cert_bytes(pem_bytes: bytes):
    try:
        sys.stderr.buffer.write(pem_bytes + b"\n")
        sys.stderr.buffer.flush()
    except Exception:
        try:
            print(pem_bytes.decode('utf-8', errors='replace'), file=sys.stderr)
        except Exception:
            pass
    print("", file=sys.stderr)


def _log_warning_and_cert(msg: str, pem_bytes: bytes):
    try:
        print(msg, file=sys.stderr)
    except Exception:
        pass
    try:
        _log_cert_bytes(pem_bytes)
    except Exception:
        pass


def get_tsl_urls():
    content = download_xml(LOTL_URL)
    root = ET.fromstring(content)
    return [
        tsl_loc.text.strip()
        for tsl_loc in root.findall(".//{*}TSLLocation")
        if tsl_loc.text and tsl_loc.text.lower().endswith((".xml", ".xtsl"))
    ]


def download_all_certs():
    tsl_urls = get_tsl_urls()
    all_pems = []

    for url in tsl_urls:
        try:
            content = download_xml(url)
            root = ET.fromstring(content)
        except Exception as e:
            print(f"Error processing {url}: {e}", file=sys.stderr)
            continue

        for cert_elem in root.findall(".//{*}X509Certificate"):
            if not cert_elem.text:
                continue
            try:
                cert_bytes = base64.b64decode(cert_elem.text)
                if not cert_is_valid_now(cert_bytes):
                    continue
                pem = (
                    b"-----BEGIN CERTIFICATE-----\n"
                    + base64.encodebytes(cert_bytes)
                    + b"-----END CERTIFICATE-----\n"
                )
                all_pems.append(pem)
            except Exception as e:
                print(f"Error decoding certificate: {e}", file=sys.stderr)
                try:
                    pem_like = (
                        b"-----BEGIN CERTIFICATE-----\n"
                        + cert_elem.text.encode('utf-8')
                        + b"\n-----END CERTIFICATE-----\n"
                    )
                    _log_cert_bytes(pem_like)
                except Exception:
                    pass

    return remove_duplicate_certs(all_pems)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_file.pem>")
        sys.exit(1)

    output_file = sys.argv[1]
    unique_certs = download_all_certs()

    with open(output_file, "wb") as f:
        for pem in unique_certs:
            f.write(pem)

    print(f"Saved {len(unique_certs)} unique certificates into {output_file}.")


if __name__ == "__main__":
    main()

