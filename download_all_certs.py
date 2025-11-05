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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"


def download_xml(url):
    """Downloads XML content with timeout and no certificate verification."""
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
        if tsl_loc.text and tsl_loc.text.lower().endswith(".xml")
    ]


def download_all_certs(output_file):
    """Downloads certificates from all TSLs and writes them to a PEM file.

    Returns (downloaded_count, failed_certs, tsl_count)
    """
    tsl_urls = get_tsl_urls()
    tsl_count = len(tsl_urls)
    count = 0
    failed_certs = 0
    with open(output_file, "wb") as f:
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
                    pem = (
                        b"-----BEGIN CERTIFICATE-----\n"
                        + base64.encodebytes(cert_bytes)
                        + b"-----END CERTIFICATE-----\n"
                    )
                    f.write(pem)
                    count += 1
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
                    failed_certs += 1

    return count, failed_certs, tsl_count


def load_certs(filename):
    certs = []
    failed_certs = 0
    if not os.path.exists(filename):
        return certs, failed_certs

    with open(filename, "rb") as f:
        pem_data = f.read()

    blocks = pem_data.split(b"-----END CERTIFICATE-----")
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        block_with_end = b"-----END CERTIFICATE-----"
        try:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                cert = x509.load_pem_x509_certificate(block + block_with_end, default_backend())
                certs.append(cert)
                for warn in w:
                    msg = str(warn.message)
                    if "The parsed certificate contains a NULL parameter value in its signature algorithm parameters." in msg:
                        continue
                    if "NULL parameter value" in msg or "signature algorithm parameters" in msg:
                        _log_warning_and_cert(f"Warning while loading certificate: {msg}", block + b"\n" + block_with_end)
        except Exception as e:
            failed_certs += 1
            _log_warning_and_cert(f"Failed to load certificate: {str(e)}", block + b"\n" + block_with_end)
    return certs, failed_certs


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_file.pem>")
        sys.exit(1)

    output_file = sys.argv[1]
    count, failed_certs_download, tsl_count = download_all_certs(output_file)
    all_certs, failed_certs_load = load_certs(output_file)
    failed_certs = failed_certs_download + failed_certs_load
    # Single-line summary: processed TSLs, downloaded count, failed loads
    print(f"Downloaded {count} certificates into {output_file} (to construct the CA chains). Failed to load {failed_certs} certificates.")


if __name__ == "__main__":
    main()
