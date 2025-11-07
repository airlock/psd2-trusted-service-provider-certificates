#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate Apache mod_ssl SSLRequire based on full issuer DN 
Output is suitable for use in an Apache <Location> context.
This is used to restrict access to client certificates issued only by
trusted EU-qualified CAs, avoiding acceptance of arbitrary certificate chains.
"""

import sys
import os
from OpenSSL import crypto

def load_certs(filename: str):
    """Load all PEM certificate blocks from a file."""
    if not os.path.exists(filename):
        print(f'File not found: {filename}', file=sys.stderr)
        sys.exit(1)
    with open(filename, 'rb') as f:
        data = f.read()
    blocks = []
    for part in data.split(b'-----END CERTIFICATE-----'):
        part = part.strip()
        if not part:
            continue
        blocks.append(part + b'\n-----END CERTIFICATE-----\n')
    return blocks

def get_subject_dn(cert_pem: bytes) -> str:
    """Return the subject DN in RFC2253 format using pyOpenSSL."""
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    components = []
    for name, value in cert.get_subject().get_components():
        n = name.decode()
        v = value.decode()
        # Escape characters per RFC2253
        v = v.replace("\\", "\\\\").replace(",", "\\,").replace("+", "\\+").replace("\"", "\\\"") \
             .replace("<", "\\<").replace(">", "\\>").replace(";", "\\;")
        components.append(f"{n}={v}")
    # Reverse to match OpenSSL order (most significant first)
    components.reverse()
    return ",".join(components)

def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <ca_pem_file>', file=sys.stderr)
        sys.exit(1)

    cert_blocks = load_certs(sys.argv[1])
    if not cert_blocks:
        print(f'No certificates found in {sys.argv[1]}', file=sys.stderr)
        sys.exit(1)

    print('# Restrict access to EU-qualified web clients by issuer DN')

    dn_conditions = []
    for block in cert_blocks:
        dn = get_subject_dn(block)
        if dn:
            dn_conditions.append(f"%{{SSL_CLIENT_I_DN}} eq '{dn}'")

    print('SSLRequire (\\')
    print(' || \\\n'.join(f'    {c}' for c in sorted(dn_conditions)) + ' \\')
    print(')')

if __name__ == '__main__':
    main()

