# file: cert_lib.py
import datetime
import re
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def cert_is_valid_now(cert_bytes: bytes) -> bool:
    """
    Checks if the certificate is currently valid (UTC).
    cert_bytes: DER or PEM encoded certificate
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes, backend=default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(cert_bytes, backend=default_backend())
    now = datetime.datetime.utcnow()
    return cert.not_valid_before <= now <= cert.not_valid_after

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

