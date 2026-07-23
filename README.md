# EU PSD2 Client Certificate CAs

## Purpose
Under the European Payment Services Directive (PSD2), participants
authenticate each other with certificates issued by EU-qualified CAs. To
verify such client certificates, a server needs the certificates of the
issuing CAs. Airlock Gateway can be used for this verification; its
configuration is described below.

The European Commission publishes the List of Trusted Lists (LOTL) at
<https://ec.europa.eu/tools/lotl/eu-lotl.xml>. It points to the national
trusted list of each member state, which contains the CAs qualified in that
country. A human readable view is available in the
[EU Trust List Browser](https://eidas.ec.europa.eu/efda/tl-browser/).

The scripts in this repository download the LOTL, follow it to all national
trusted lists and extract only the CA certificates marked for website
authentication (services with the `ForWebSiteAuthentication` extension),
plus the intermediate and root certificates needed to complete their chains.
Downloading only these CAs keeps the bundle small. This matters because the
names of the configured CAs are sent to the client in the TLS handshake:
different clients impose different limits on the total size of the handshake,
and RFC 8446 limits the size of the transferred name list to 65535 bytes.

## Certificate Chain Construction
The certificate chain is built using the **Authority Information Access (AIA)**
extensions, which provide URLs to the issuer's certificate. Since not every
certificate can be found this way, the issuer is also searched among all
certificates of the national trusted lists and in `eu_chain_missing.pem`, a
manually collected set of certificates that are neither downloadable via AIA
nor contained in the trusted lists. The process continues until the root
certificate is found.

## Usage

Python 3 is required, along with the libraries listed in
`requirements.txt`.

To generate the final bundle, run:

```
./do_all.sh
```
This process may take up to ten minutes to download all certificates and construct
the full chains. It produces three files:

- `eu_selection_ca_certs.pem`: all EU-qualified web authentication CA
  certificates extracted from the national trusted lists.
- `eu_validation_ca_certs.pem`: only the additional intermediate and root CA
  certificates that this project collects (via AIA, the certificates of the
  national trusted lists and `eu_chain_missing.pem`) to complete the chains.
- `eu_full_chains.pem`: the combined bundle of the two files above, for
  systems that expect a single file.

## Airlock Gateway Configuration

Airlock Gateway configures the client certificate CAs per virtual host, in two
separate form fields. In the Configuration Center open
*Application Firewall → Reverse Proxy*, edit the virtual host that terminates
the PSD2 client TLS connections, and switch to the tab *Client Certificates*,
section *Certificate Authority* (see the
[Airlock Gateway documentation](https://docs.airlock.com/gateway/latest/index/1574686289416.html)).
Paste the PEM content of the generated files as follows:

- **CAs for client certificate selection**: paste the content of `eu_selection_ca_certs.pem`.
  The subject DNs of these CAs are announced to the client during the TLS
  handshake (`certificate_authorities` list in the CertificateRequest
  message), so the client can select a matching certificate. Only the EU-qualified web
  authentication CAs belong here.
- **CAs for chain validation and OCSP server validation**: paste the content
  of `eu_validation_ca_certs.pem`. These certificates are only used server-side to
  validate the certificate chain up to the root; they are not announced to
  the client.
- **Chain verification depth**: enter the `Max chain length` value printed by
  `./do_all.sh`.

### Accept Only Client Certificates Issued by EU CAs

The configuration above checks that the client certificate chains up to one
of the configured root CAs. Some EU CAs operate under large commercial root
CAs, and those roots also sign certificates for entirely different customers.
A client certificate from such an unrelated CA would therefore pass the chain
validation as well. This step closes that gap: it additionally requires that
the client certificate was issued directly by one of the EU web
authentication CAs. It is technically not required, but we recommend it.

Generate Apache `Require expr` directives that compare the issuer DN of the
client certificate (`SSL_CLIENT_I_DN`) against the subject DNs of all CAs in
`eu_selection_ca_certs.pem`:

```
./get_apache_restrictions.py eu_selection_ca_certs.pem
```

**Paste the printed directives into the Apache expert settings of the
corresponding mapping.** See the
[Apache documentation of Require expr](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html#reqexpr)
for details.

## Disclaimer
This software is provided as source code under an MIT license (see LICENSE).
