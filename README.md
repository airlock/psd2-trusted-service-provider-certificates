# EU Web Certificates Restrictions

## Purpose
The European Payment Services Directive relies on PKI technology for security. 
To establish trust, all participants are required to verify each other's 
certificates. To perform this verification, the CA certificate that issued the 
participant's certificate is needed. This software provides a convenient way 
for system administrators to download all CA certificates required in PSD2 
verifications.

It's important to download the entire certificate chain because many tools, 
including OpenSSL, validate the full chain by default. This collection 
specifically focuses on certificates issued by EU-qualified CAs for web 
authentication, indicated by the EU-defined `ForWebSiteAuthentication` 
extension (an attribute of the CA, not the individual certificate).

In addition, this repository includes a method to generate Apache `SSLRequire` 
directives using the issuer DNs from the downloaded EU web certificates. This 
allows configuring access in a `<Location>` context without accepting arbitrary 
certificate chains from other roots, which could otherwise introduce security 
risks by allowing any chain ending in a common root CA.

## Certificate Chain Construction
The certificate chain is built using the **Authority Information Access (AIA)** 
extensions, which provide URLs to the issuer’s certificate. If the AIA URLs are 
not available, the issuer certificate is searched in a local pool and, if 
necessary, via public sources such as `crt.sh`. The process continues until the 
root certificate is found, completing the chain from the web certificate to the 
root CA certificate.

Usage

Python 3 or higher is required, along with the libraries listed in 
`requirements.txt`.

To generate the final bundle, run:

```
./do_all.sh
```
This process may take up to ten minutes to download all certificates and construct
the full chains. It produces the file `eu_web_and_chain.pem`.

Apache SSLRequire Directives

After running `do_all.sh` and generating the merged certificate files, you can 
generate Apache SSLRequire directives based on the web certificates only:

```
./get_apache_restrictions.py eu_web.pem
```

The output prints SSLRequire directives to standard output. Redirect the output 
to a file to use it in an Apache Location block. Using issuer DNs from the 
original EU web certificates ensures that only trusted CAs are allowed and 
prevents arbitrary chains from other roots, which could introduce security 
risks. The merged file `eu_web_and_chain.pem` is not used for the SSLRequire 
directives but is needed for verification

## Disclaimer
This software is provided as source code under an MIT license (see LICENSE).

## Security
The European Trust List Browser provides limited security on the API. The API 
is offered over TLS, so it is possible to ascertain the source of the 
information. The information itself is not signed, so the authenticity and 
integrity cannot be fully validated.
