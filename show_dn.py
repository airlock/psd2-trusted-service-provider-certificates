#!/usr/bin/env python3
"""
Print all Distinguished Names (DNs) from a PEM file containing one or more
X.509 certificates. Output is normalized for easy comparison.
Additionally, prints subjects outside EU/EWR countries at the end.
Also prints certificate validity (not_before / not_after).
"""

import os
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from cert_lib import load_pem_file

OID_ORDER = [
    x509.NameOID.COUNTRY_NAME,
    x509.NameOID.STATE_OR_PROVINCE_NAME,
    x509.NameOID.LOCALITY_NAME,
    x509.NameOID.ORGANIZATION_NAME,
    x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
    x509.NameOID.COMMON_NAME,
    x509.NameOID.EMAIL_ADDRESS,
    x509.NameOID.SERIAL_NUMBER,
]

OID_LABELS = {
    x509.NameOID.COUNTRY_NAME: "C",
    x509.NameOID.STATE_OR_PROVINCE_NAME: "ST",
    x509.NameOID.LOCALITY_NAME: "L",
    x509.NameOID.ORGANIZATION_NAME: "O",
    x509.NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    x509.NameOID.COMMON_NAME: "CN",
    x509.NameOID.EMAIL_ADDRESS: "E",
    x509.NameOID.SERIAL_NUMBER: "SERIAL",
}

EU_EWR_COUNTRIES = {
    "AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR",
    "HU","IS","IE","IT","LV","LI","LT","LU","MT","NL","NO","PL",
    "PT","RO","SK","SI","ES","SE"
}


def safe_format_dn(name):
    try:
        attrs = {attr.oid: attr.value for attr in name}
        parts = []
        for oid in OID_ORDER:
            if oid in attrs:
                parts.append(f"{OID_LABELS[oid]}={attrs[oid]}")
        for attr in name:
            if attr.oid not in OID_ORDER:
                parts.append(f"{attr.oid.dotted_string}={attr.value}")
        return ", ".join(parts) if parts else "(empty DN)"
    except Exception as e:
        return f"(unparsable DN: {e})"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pem_file>")
        sys.exit(1)

    pem_file = sys.argv[1]
    if not os.path.isfile(pem_file):
        print(f"Error: file not found: {pem_file}", file=sys.stderr)
        sys.exit(1)

    certs = load_pem_file(pem_file, as_objects=True)

    if not certs:
        print("No certificates found.")
        sys.exit(0)

    outside_ewr = []

    for i, cert in enumerate(certs, 1):
        print(f"Certificate {i}:")
        try:
            subj = safe_format_dn(cert.subject)
        except Exception as e:
            subj = f"(subject parse error: {e})"

        try:
            issuer = safe_format_dn(cert.issuer)
        except Exception as e:
            issuer = f"(issuer parse error: {e})"

        print(f"  Subject: {subj}")
        print(f"  Issuer : {issuer}")
        try:
            print(f"  Valid  : {cert.not_valid_before_utc.isoformat()}  →  {cert.not_valid_after_utc.isoformat()}")
        except AttributeError:
            print(f"  Valid  : {cert.not_valid_before.isoformat()}  →  {cert.not_valid_after.isoformat()}")
        print()

        try:
            country = cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
            if country:
                c = country[0].value.upper()
                if c not in EU_EWR_COUNTRIES:
                    outside_ewr.append(subj)
        except Exception:
            pass

    if outside_ewr:
        print("Certificates with subjects outside EU/EWR countries:")
        for dn in outside_ewr:
            print(f"  {dn}")


if __name__ == "__main__":
    main()

