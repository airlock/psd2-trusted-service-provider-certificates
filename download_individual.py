#!/usr/bin/env python3
"""
Download a list of certificates from configured URLs (DER or PEM),
convert to PEM if necessary, and append them to a specified output file.
"""

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import sys
import os
import urllib3

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurable URLs
CERT_URLS = [
    "https://www.infonotary.com/en/files/qualified-root-ca.der",
    "https://www.defensa.gob.es/pki/ca/DEFENSA-EC-RAIZ.cer"
    # add more URLs here
]

def der_to_pem(der_bytes):
    cert = x509.load_der_x509_certificate(der_bytes)
    return cert.public_bytes(serialization.Encoding.PEM)

def download_and_store(url, output_file):
    r = requests.get(url, timeout=30, verify=False)  # SSL verification disabled
    r.raise_for_status()
    content = r.content

    try:
        # Check if already PEM
        text = content.decode("utf-8")
        if "BEGIN CERTIFICATE" in text:
            pem_data = content.encode("utf-8")
        else:
            raise ValueError
    except Exception:
        # Otherwise convert DER → PEM
        pem_data = der_to_pem(content)

    # Write or append to the file
    mode = "ab" if os.path.exists(output_file) else "wb"
    with open(output_file, mode) as f:
        f.write(pem_data)
        f.write(b"\n")
    print(f"Downloading: {url} → Saved to {output_file}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_file>")
        sys.exit(1)

    output_file = sys.argv[1]

    for url in CERT_URLS:
        download_and_store(url, output_file)

if __name__ == "__main__":
    main()

