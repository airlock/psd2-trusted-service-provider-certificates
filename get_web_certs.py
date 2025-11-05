#!/usr/bin/env python3
"""
This script downloads all EU Trusted Service Lists (TSLs),
extracts X.509 certificates used for website authentication
(ForWebSiteAuthentication), and stores them collectively in PEM format.
Optional flags allow skipping QC filtering and certificate validity checks.
"""

import argparse
import base64
import datetime
import json
import sys
from collections import defaultdict
from pathlib import Path

import requests
import urllib3
import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
TARGET_EXT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"
TIMEOUT = 30


def download_xml(url: str) -> bytes:
    try:
        r = requests.get(url, verify=False, timeout=TIMEOUT)
        r.raise_for_status()
        return r.content
    except Exception as e:
        print(f"Failed to download {url}: {e}", file=sys.stderr)
        return b""


def get_tsl_urls() -> list[str]:
    content = download_xml(LOTL_URL)
    if not content:
        return []
    try:
        root = ET.fromstring(content)
        return [
            tsl_loc.text.strip()
            for tsl_loc in root.findall(".//{*}TSLLocation")
            if tsl_loc.text and tsl_loc.text.lower().endswith(".xml")
        ]
    except Exception as e:
        print(f"Failed to parse LOTL XML: {e}", file=sys.stderr)
        return []


def cert_is_valid_today(cert_bytes: bytes) -> bool:
    cert = x509.load_der_x509_certificate(cert_bytes, backend=default_backend())
    now = datetime.datetime.utcnow()
    return cert.not_valid_before <= now <= cert.not_valid_after


def process_tsl(
    tsl_url: str,
    output_handle,
    stats: dict,
    no_qc: bool = False,
    skip_validity_check: bool = False,
) -> int:
    try:
        content = download_xml(tsl_url)
        if not content:
            return 0
        root = ET.fromstring(content)
    except Exception as e:
        print(f"Error reading {tsl_url}: {e}", file=sys.stderr)
        return 0

    saved_count = 0

    for service in root.findall(".//{*}TSPService"):
        svc_type_elem = service.find(".//{*}ServiceTypeIdentifier")
        svc_type = svc_type_elem.text.strip() if svc_type_elem is not None and svc_type_elem.text else ""
        is_qc = "QC" in svc_type

        extensions = service.findall(".//{*}ServiceInformationExtensions/{*}Extension")
        ext_map = []
        for ext in extensions:
            uris = [u.text.strip() for u in ext.findall(".//{*}URI") if u.text]
            qc_uris = [q.get("uri") for q in ext.findall(".//{*}Qualifier") if q.get("uri")]
            ext_map.append({"uris": uris, "qc_uris": qc_uris})

        cert_elems = service.findall(".//{*}X509Certificate")
        for cert_elem in cert_elems:
            if not cert_elem.text:
                continue
            try:
                cert_bytes = base64.b64decode(cert_elem.text)
            except Exception:
                continue

            if not skip_validity_check:
                try:
                    if not cert_is_valid_today(cert_bytes):
                        continue
                except Exception:
                    continue

            cert_exts = {uri for ext in ext_map for uri in ext["uris"]}
            for uri in cert_exts:
                stats[uri]["QC" if is_qc else "Non-QC"] += 1

            save_web = any(TARGET_EXT in ext["uris"] for ext in ext_map)
            has_qc_uri = any("QC" in (uri or "") for ext in ext_map for uri in ext["qc_uris"])
            if save_web and (no_qc or is_qc or has_qc_uri):
                pem = (
                    b"-----BEGIN CERTIFICATE-----\n"
                    + base64.encodebytes(cert_bytes)
                    + b"-----END CERTIFICATE-----\n"
                )
                output_handle.write(pem)
                saved_count += 1

    return saved_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Download all EU TSL web certificates (no defaults).")
    parser.add_argument("output", help="Output PEM file (mandatory)")
    parser.add_argument("--no-qc-check", action="store_true", help="Disable QC filtering")
    parser.add_argument("--skip-validity-check", action="store_true", help="Skip certificate validity check")
    parser.add_argument("--verbose", action="store_true", help="Print per-TSL saved counts")
    args = parser.parse_args()

    tsl_urls = get_tsl_urls()
    if not tsl_urls:
        print("No TSL URLs found.", file=sys.stderr)
        sys.exit(1)

    stats = defaultdict(lambda: {"QC": 0, "Non-QC": 0})
    total_saved = 0

    output_path = Path(args.output)
    with output_path.open("wb") as f:
        for url in tsl_urls:
            saved = process_tsl(url, f, stats, no_qc=args.no_qc_check, skip_validity_check=args.skip_validity_check)
            total_saved += saved
            if args.verbose:
                print(f"{saved} certs from {url}")

    print(f"Saved {total_saved} EU web certificates into {args.output}.")


if __name__ == "__main__":
    main()
