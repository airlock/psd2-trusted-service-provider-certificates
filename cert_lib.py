"""Utility functions for working with X.509 certificates.

Provides centralized functions for loading, validating, deduplicating,
and downloading certificates. Reduces code duplication across scripts.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import re
from typing import List, Optional, Tuple, Union

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

__all__ = [
    "cert_is_valid_now",
    "remove_duplicate_certs",
    "load_certificate",
    "load_pem_file",
    "get_subject_key_identifier",
    "get_common_name",
    "download_with_retry",
]


def load_certificate(cert_bytes: bytes) -> x509.Certificate:
    """Load a certificate from PEM or DER bytes.

    Tries PEM first, then DER. Raises ValueError if neither works.

    Parameters
    ----------
    cert_bytes : bytes
        Certificate in PEM or DER format.

    Returns
    -------
    x509.Certificate
        Parsed certificate object.

    Raises
    ------
    ValueError
        If the bytes cannot be parsed as PEM or DER.
    """
    try:
        return x509.load_pem_x509_certificate(cert_bytes, backend=default_backend())
    except ValueError:
        try:
            return x509.load_der_x509_certificate(cert_bytes, backend=default_backend())
        except ValueError as e:
            raise ValueError("Failed to parse certificate as PEM or DER") from e


def cert_is_valid_now(cert_bytes: bytes) -> bool:
    """
    Checks if the certificate is currently valid (UTC).
    cert_bytes: PEM or DER encoded certificate
    """
    cert = load_certificate(cert_bytes)
    now = datetime.datetime.utcnow()
    return cert.not_valid_before <= now <= cert.not_valid_after


def load_pem_file(
    filename: str,
    *,
    only_valid: bool = False,
    as_objects: bool = False,
    include_source: bool = False,
) -> Union[List[bytes], List[x509.Certificate], List[Tuple[x509.Certificate, str]]]:
    """Load and split a PEM file into individual certificates.

    Parameters
    ----------
    filename : str
        Path to PEM file containing one or more certificates.
    only_valid : bool, optional
        If True, filter out certificates not valid at current time (default: False).
    as_objects : bool, optional
        If True, return parsed x509.Certificate objects instead of bytes (default: False).
    include_source : bool, optional
        If True and as_objects=True, return tuples of (cert, filename) (default: False).

    Returns
    -------
    list
        List of certificate bytes, Certificate objects, or (Certificate, str) tuples.
        Empty list if file doesn't exist or contains no valid certificates.
    """
    if not os.path.exists(filename):
        return []

    with open(filename, "rb") as f:
        pem_data = f.read()

    results = []
    for cert_block in pem_data.split(b"-----END CERTIFICATE-----"):
        cert_block = cert_block.strip()
        if not cert_block:
            continue
        cert_block += b"\n-----END CERTIFICATE-----\n"

        # Validity check if requested
        if only_valid and not cert_is_valid_now(cert_block):
            continue

        # Parse if objects requested
        if as_objects:
            try:
                cert_obj = x509.load_pem_x509_certificate(cert_block, backend=default_backend())
                if include_source:
                    results.append((cert_obj, filename))
                else:
                    results.append(cert_obj)
            except Exception:
                continue
        else:
            results.append(cert_block)

    return results


def get_subject_key_identifier(cert: x509.Certificate) -> str:
    """Get Subject Key Identifier in hex, or SHA1 fingerprint as fallback.

    Parameters
    ----------
    cert : x509.Certificate
        Certificate object.

    Returns
    -------
    str
        Hex-encoded SKI or SHA1 fingerprint.
    """
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        return ski.hex()
    except Exception:
        return cert.fingerprint(hashes.SHA1()).hex()


def get_common_name(name: x509.Name, default: str = "Unknown") -> str:
    """Extract Common Name from x509.Name object.

    Parameters
    ----------
    name : x509.Name
        Subject or issuer name.
    default : str, optional
        Value to return if CN not found (default: "Unknown").

    Returns
    -------
    str
        Common Name value or default.
    """
    cn_attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return cn_attrs[0].value if cn_attrs else default


def download_with_retry(
    url: str,
    *,
    timeout: int = 30,
    verify: bool = False,
    as_certificate: bool = False,
) -> Optional[Union[bytes, x509.Certificate]]:
    """Download content via HTTP with error handling.

    Parameters
    ----------
    url : str
        URL to download.
    timeout : int, optional
        Request timeout in seconds (default: 30).
    verify : bool, optional
        Enable SSL certificate verification (default: False).
    as_certificate : bool, optional
        If True, parse and return as x509.Certificate (tries PEM then DER) (default: False).

    Returns
    -------
    bytes or x509.Certificate or None
        Downloaded content, parsed certificate, or None on failure.
    """
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        return None

    try:
        r = requests.get(url, timeout=timeout, verify=verify)
        r.raise_for_status()
        content = r.content

        if as_certificate:
            try:
                return load_certificate(content)
            except ValueError:
                return None

        return content
    except Exception:
        return None


def remove_duplicate_certs(pem_certs: list[bytes]) -> list[bytes]:
    """
    Removes duplicate PEM certificates based on canonicalized Base64 content.
    """
    seen = set()
    unique = []
    for pem in pem_certs:
        text = pem.decode("ascii", errors="ignore")
        base64_part = re.search(
            r"-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----",
            text,
            re.DOTALL
        )
        if not base64_part:
            continue
        b64_clean = re.sub(r"\s+", "", base64_part.group(1)).encode("ascii")
        h = hashlib.sha1(b64_clean).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append(pem)
    return unique
