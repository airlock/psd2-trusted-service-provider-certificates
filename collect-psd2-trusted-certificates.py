#!/usr/bin/python3
"""
collect-psd2-trusted-certificates.py

Description:
    Download all trusted psd2 service provider certificates

Usage:
    collect-psd2-trusted-certificates.py -o <filename> [--verbose]

Options:
    -h --help               Show this screen.
    -o --output <filename>  File path
    --verbose
"""
import base64
import json
import logging
import os
import re
import requests
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from docopt import docopt
from lxml import etree
from typing import Dict, Set


def collect() -> Set[str]:
    """
    Retrieve certificate of all trusted service providers and write it to an file.
    :return: collection of x509 certificates.
    """
    certificates = set()
    trusted_service_providers = _find_trusted_service_providers()
    for country_code, service_provider_names in trusted_service_providers.items():
        certificates_by_country = _collect_certificates(country_code, service_provider_names)
        certificates.update(certificates_by_country)
    return certificates


def write_certs_to_file(certificates: set, path: str):
    """
    Write all passed certificates to a file.
    :param certificates: list of certificates of all trusted service providers
    :param path: path to write all certificates
    """
    if os.path.exists(path):
        os.remove(path)
    with open(path, 'w') as f:
        for certificate in certificates:
            f.write("%s\n" % certificate)


def not_expired_or_invalid(pem_as_string: str) -> bool:
    """
    :param pem_as_string: x509 PEM formatted certificate
    :return: False when certificate is expired
    """
    pem_as_byte = str.encode(pem_as_string)
    try:
        cert = x509.load_pem_x509_certificate(pem_as_byte, default_backend())
    except ValueError as ve:
        logging.info(f"Unable to parse the following certificate because it contains an invalid value:\n"
                     + pem_as_string)
        return False
    current_datetime = datetime.now()
    if current_datetime > cert.not_valid_after:
        logging.info("Expired certificate with serial number '%s'.", cert.serial_number)
        return False
    else:
        return True


def _find_trusted_service_providers() -> Dict[str, list]:
    """
    Extract list of all trusted service providers
    :return: dict of trusted service providers by country code
    """
    trusted_service_providers_by_country = {}
    url = 'http://eidas.ec.europa.eu/efda/tl-browser/api/v1/search/tsp_list'
    resp = requests.get(url)
    _assert_status_code(resp.status_code, 200)
    for company in resp.json():
        for service in company['services']:
            if any("Q_CERT_ESEAL" in s for s in service['serviceLegalTypes']) \
                    or any("Q_WAC" in s for s in service['serviceLegalTypes']):
                country_code = service['countryCode']
                service_name = service['serviceName']
                if country_code not in trusted_service_providers_by_country:
                    trusted_service_providers_by_country[country_code] = [service_name]
                else:
                    trusted_service_providers_by_country[country_code].append(service_name)
    logging.info('List of trusted service providers\n')
    logging.info(
        "%s",
        json.dumps(
            trusted_service_providers_by_country,
            sort_keys=True,
            indent=4
        )
    )
    return trusted_service_providers_by_country


def _collect_certificates(country_code: str, service_names: list) -> Set[str]:
    """
    Downloads X509 certificates of trusted service providers.
    :param country_code: country code alpha-2
    :param service_names: collection of trusted service provider names
    :return: collection of x509 certificates as String
    """
    certificates = set()
    url = f"http://eidas.ec.europa.eu/efda/tl-browser/api/v1/browser/download/{country_code}"
    resp = requests.get(url)
    _assert_status_code(resp.status_code, 200)
    resp.encoding = "utf-8-sig"
    content = resp.text
    dom = _create_xml_root_node(content)
    for service_name in service_names:
        escaped_service_name = service_name.replace('"', '&quot')
        xpath = (
            f".//ServiceInformation[ServiceName[Name[text()=\"{escaped_service_name}\"]]]"
            '/ServiceDigitalIdentity/DigitalId/X509Certificate/text()'
        )
        for certificate in dom.xpath(xpath):
            certificate = _to_pem_format(certificate)
            certificates.add(certificate)
    return certificates


def _assert_status_code(actual: int, expected: int):
    """
    Asserts the HTTP status code.
    :param actual: acutal HTTP status code
    :param expected: expected HTTP status code
    """
    if not actual == expected:
        msg = f"HTTP Status Code expected {actual} to be {expected}."
        raise AssertionError(msg)


def _create_xml_root_node(content: str):
    """
    Decode and parses an XML document.
    :param content: base64 encode xml string
    :return: XML root node
    """
    # remove default xml namespace otherwise it can not be parsed
    xml_as_string = re.sub(' xmlns="[^"]+"', '', content, count=1)
    return etree.fromstring(bytes(xml_as_string, encoding='utf-8'))


def _to_pem_format(cert_as_string: str) -> str:
    """
    :param cert_as_string: certificate as string
    :return: x509 PEM formatted certificate
    """
    if "\n" not in cert_as_string:
        cert_as_string = _wrap(cert_as_string, 65)
    pem_as_string = f"-----BEGIN CERTIFICATE-----\n{cert_as_string}\n-----END CERTIFICATE-----"
    return pem_as_string


def _wrap(text: str, max_width: int) -> str:
    s = ''
    for i in range(0, len(text), max_width):
        s = s + text[i:i + max_width] + '\n'
    return s.rstrip("\n")


if __name__ == '__main__':
    arguments = docopt(__doc__)
    certificates_file_path = arguments['--output']
    verbose = arguments['--verbose']
    if verbose:
        logging.basicConfig(format='%(message)s', level=logging.INFO)
    certs = collect()
    not_expired_certs = [c for c in certs if not_expired_or_invalid(c)]
    cert_count = len(not_expired_certs)
    expired_cert_count = len(certs) - cert_count
    logging.info('Found %s valid certificates and %s expired certificates.', cert_count, expired_cert_count)
    write_certs_to_file(not_expired_certs, certificates_file_path)

